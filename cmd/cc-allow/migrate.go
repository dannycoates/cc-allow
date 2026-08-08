package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// shellConstructs are keywords that should not be migrated as commands.
var shellConstructs = map[string]bool{
	"do": true, "done": true, "for": true, "while": true,
	"if": true, "then": true, "else": true, "elif": true,
	"fi": true, "case": true, "esac": true, "break": true,
	"continue": true, "in": true,
}

// fileToolDest maps a Claude Code file-tool name to the cc-allow file section it
// migrates into. Glob/Grep route to [read.allow] because cc-allow's glob/grep
// inherit from read via respect_file_rules.
var fileToolDest = map[string]string{
	"Edit":  "edit",
	"Read":  "read",
	"Write": "write",
	"Glob":  "read",
	"Grep":  "read",
}

// fileSections is the stable output order for migrated file-tool paths.
var fileSections = []string{"edit", "read", "write"}

// validCommandStart matches the first character of a valid command name.
var validCommandStart = regexp.MustCompile(`^[a-zA-Z./_~]`)

// subcommandWord matches a token that may be treated as a subcommand segment.
// Excludes anything with a dot, slash, or '=' so it stays a valid bare TOML key
// and so paths/values/flags fall through to args instead.
var subcommandWord = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// settingsFile is used for reading the permissions.allow array from a settings file.
type settingsFile struct {
	Permissions struct {
		Allow []string `json:"allow"`
	} `json:"permissions"`
}

// bashRuleOut is a translated subcommand-scoped bash rule. Subs[0] is the command
// name; the remainder are subcommand segments (e.g. ["git","push"]). ArgsAll holds
// optional exact argument patterns that must all be present.
type bashRuleOut struct {
	Subs    []string
	ArgsAll []string
}

func (r bashRuleOut) key() string {
	return strings.Join(r.Subs, ".") + "\x00" + strings.Join(r.ArgsAll, " ")
}

// migrationResult holds everything extracted/translated during migration.
type migrationResult struct {
	Commands []string            // bare command allows (e.g. Bash(npm:*) → "npm")
	Rules    []bashRuleOut       // subcommand-scoped bash rules
	Paths    map[string][]string // file section (edit/read/write) → cc-allow path patterns
	WebFetch []string            // webfetch allow patterns (re:...)
}

func newMigrationResult() *migrationResult {
	return &migrationResult{Paths: make(map[string][]string)}
}

func (r *migrationResult) empty() bool {
	if len(r.Commands) > 0 || len(r.Rules) > 0 || len(r.WebFetch) > 0 {
		return false
	}
	for _, paths := range r.Paths {
		if len(paths) > 0 {
			return false
		}
	}
	return true
}

func (r *migrationResult) totalPaths() int {
	n := 0
	for _, paths := range r.Paths {
		n += len(paths)
	}
	return n
}

// migrateSettingsPermissions detects Bash/Edit/Read/Write/Glob/Grep/WebFetch
// entries in settings.local.json files, translates them into proper cc-allow
// rules, merges them into .config/cc-allow.local.toml, and strips the migrated
// entries from settings.local.json. Returns the newly-migrated entries (for the
// hook's additionalContext message), or nil if nothing was migrated.
func migrateSettingsPermissions(projectRoot string) *migrationResult {
	home, _ := os.UserHomeDir()

	projectSettings := filepath.Join(projectRoot, ".claude", "settings.local.json")
	globalSettings := ""
	if home != "" {
		globalSettings = filepath.Join(home, ".claude", "settings.local.json")
	}

	// Distinct existing settings files (projectSettings == globalSettings when the
	// project root is the home directory).
	var files []string
	seenFile := make(map[string]bool)
	for _, f := range []string{projectSettings, globalSettings} {
		if f == "" || seenFile[f] || !fileExists(f) {
			continue
		}
		seenFile[f] = true
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil
	}

	// Collect and translate new entries, tracking which exact strings to strip.
	incoming := newMigrationResult()
	migrated := make(map[string]bool) // settings entry string → strip it
	for _, path := range files {
		collectFromSettings(path, incoming, migrated)
	}
	incoming = mergeResults(newMigrationResult(), incoming) // de-duplicate

	// Nothing migratable found — leave files (and local.toml) untouched.
	if incoming.empty() {
		return nil
	}

	// Merge with previously-migrated rules so repeated migrations are additive.
	localTomlPath := filepath.Join(projectRoot, ".config", "cc-allow.local.toml")
	merged := mergeResults(loadExistingLocal(localTomlPath), incoming)

	// Write the merged local.toml.
	if err := os.MkdirAll(filepath.Join(projectRoot, ".config"), 0o755); err != nil {
		return nil
	}
	if err := os.WriteFile(localTomlPath, []byte(buildLocalToml(merged)), 0o644); err != nil {
		return nil
	}

	// Strip only the entries we actually migrated.
	for _, path := range files {
		if path != "" && fileExists(path) {
			stripSettingsEntries(path, migrated)
		}
	}

	return incoming
}

// collectFromSettings reads one settings file, translating each migratable allow
// entry into res and recording its exact string in migrated for later stripping.
func collectFromSettings(path string, res *migrationResult, migrated map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var sf settingsFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return
	}

	for _, entry := range sf.Permissions.Allow {
		switch {
		case strings.HasPrefix(entry, "Bash("):
			cmd, rule, ok := translateBash(inner(entry, "Bash"))
			if !ok {
				continue
			}
			if rule != nil {
				res.Rules = append(res.Rules, *rule)
			} else {
				res.Commands = append(res.Commands, cmd)
			}
			migrated[entry] = true

		case strings.HasPrefix(entry, "WebFetch(domain:"):
			pat, ok := translateWebFetch(inner(entry, "WebFetch"))
			if !ok {
				continue
			}
			res.WebFetch = append(res.WebFetch, pat)
			migrated[entry] = true

		default:
			for tool, section := range fileToolDest {
				if !strings.HasPrefix(entry, tool+"(") {
					continue
				}
				pat, ok := translatePath(inner(entry, tool))
				if !ok {
					break
				}
				res.Paths[section] = append(res.Paths[section], pat)
				migrated[entry] = true
				break
			}
		}
	}
}

// inner returns the text between "Tool(" and the trailing ")".
func inner(entry, tool string) string {
	s := strings.TrimPrefix(entry, tool+"(")
	s = strings.TrimSuffix(s, ")")
	return strings.TrimSpace(s)
}

// translateBash converts the inside of a Bash(...) entry into either a bare
// command (rule == nil) or a subcommand-scoped rule. ok is false when the entry
// should be left in settings.local.json (shell construct, env assignment, quotes).
func translateBash(spec string) (command string, rule *bashRuleOut, ok bool) {
	// A trailing ":*" is Claude Code's prefix wildcard ("this prefix, then
	// anything"). For our purposes both prefix and exact forms map to the same
	// subcommand scoping, so just strip it.
	spec = strings.TrimSuffix(spec, ":*")
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil, false
	}

	// Tokens containing quotes/backslashes can't be translated reliably.
	if strings.ContainsAny(spec, "\"'\\") {
		return "", nil, false
	}

	fields := strings.Fields(spec)
	cmd := fields[0]

	if shellConstructs[cmd] {
		return "", nil, false
	}
	if !validCommandStart.MatchString(cmd) {
		return "", nil, false
	}
	if strings.Contains(cmd, "=") {
		return "", nil, false
	}

	// Leading word-like tokens become subcommand segments; the first non-word
	// token (a flag, path, or value) and everything after become args.all.
	subs := []string{cmd}
	rest := fields[1:]
	i := 0
	for ; i < len(rest); i++ {
		if !subcommandWord.MatchString(rest[i]) {
			break
		}
		subs = append(subs, rest[i])
	}
	args := rest[i:]

	// Bare command (no subcommands, no args): honor Claude Code's intent to allow
	// the whole command via the commands list.
	if len(subs) == 1 && len(args) == 0 {
		return cmd, nil, true
	}
	return "", &bashRuleOut{Subs: subs, ArgsAll: args}, true
}

// translatePath converts a Claude Code path specifier into a cc-allow "path:"
// pattern, mapping CC's gitignore-style anchors onto cc-allow's variables:
//
//	//abs/**      → path:/abs/**               (absolute)
//	/proj/**      → path:$PROJECT_ROOT/proj/** (project root)
//	~/x/**        → path:$HOME/x/**            (home)
//	./x  or  x    → path:$PROJECT_ROOT/x       (cwd ≈ project root)
func translatePath(spec string) (string, bool) {
	if spec == "" {
		return "", false
	}
	switch {
	case strings.HasPrefix(spec, "//"):
		// Absolute filesystem path: collapse leading slashes to one.
		return "path:/" + strings.TrimLeft(spec, "/"), true
	case strings.HasPrefix(spec, "~/"):
		return "path:$HOME/" + spec[2:], true
	case spec == "~":
		return "path:$HOME", true
	case strings.HasPrefix(spec, "/"):
		// Project-root anchored.
		return "path:$PROJECT_ROOT" + spec, true
	case strings.HasPrefix(spec, "./"):
		return "path:$PROJECT_ROOT/" + spec[2:], true
	default:
		// Bare relative path: anchored at the project root (cc-allow expects the
		// cwd to be the project root).
		return "path:$PROJECT_ROOT/" + spec, true
	}
}

// translateWebFetch converts a WebFetch(domain:...) specifier into a cc-allow
// regex pattern over the URL, honoring CC's wildcard-domain dot boundaries.
func translateWebFetch(spec string) (string, bool) {
	host := strings.TrimPrefix(spec, "domain:")
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	if strings.HasPrefix(host, "*.") {
		// Subdomains of host (one or more labels), but not the bare apex.
		return "re:^https?://([^/.]+\\.)+" + regexp.QuoteMeta(host[2:]) + "(/|$)", true
	}
	return "re:^https?://" + regexp.QuoteMeta(host) + "(/|$)", true
}

// loadExistingLocal reads previously-migrated rules from an existing
// cc-allow.local.toml (parsed by cc-allow itself) so migration is additive.
func loadExistingLocal(path string) *migrationResult {
	res := newMigrationResult()
	cfg, err := loadConfig(path)
	if err != nil {
		return res
	}
	res.Commands = append(res.Commands, cfg.Bash.Allow.Commands...)
	for _, r := range cfg.getParsedRules() {
		if r.Action != ActionAllow {
			continue
		}
		res.Rules = append(res.Rules, bashRuleOut{
			Subs:    append([]string{r.Command}, r.Subcommands...),
			ArgsAll: argsAllPatterns(r),
		})
	}
	res.Paths["edit"] = append(res.Paths["edit"], cfg.Edit.Allow.Paths...)
	res.Paths["read"] = append(res.Paths["read"], cfg.Read.Allow.Paths...)
	res.Paths["write"] = append(res.Paths["write"], cfg.Write.Allow.Paths...)
	res.WebFetch = append(res.WebFetch, cfg.WebFetch.Allow.Paths...)
	return res
}

// argsAllPatterns extracts the flat args.all patterns from a migrated rule.
func argsAllPatterns(r BashRule) []string {
	if r.Args.All != nil {
		return r.Args.All.Patterns
	}
	return nil
}

// mergeResults unions two results, de-duplicating each component.
func mergeResults(a, b *migrationResult) *migrationResult {
	out := newMigrationResult()
	out.Commands = dedup(append(a.Commands, b.Commands...))
	out.WebFetch = dedup(append(a.WebFetch, b.WebFetch...))
	for _, section := range fileSections {
		out.Paths[section] = dedup(append(a.Paths[section], b.Paths[section]...))
	}
	seen := make(map[string]bool)
	for _, r := range append(append([]bashRuleOut{}, a.Rules...), b.Rules...) {
		if seen[r.key()] {
			continue
		}
		seen[r.key()] = true
		out.Rules = append(out.Rules, r)
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].key() < out.Rules[j].key() })
	return out
}

// stripSettingsEntries removes the given entries from a settings file's
// permissions.allow array, preserving all other fields.
func stripSettingsEntries(path string, remove map[string]bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}
	perms, ok := raw["permissions"].(map[string]any)
	if !ok {
		return
	}
	allowRaw, ok := perms["allow"].([]any)
	if !ok {
		return
	}
	filtered := make([]any, 0, len(allowRaw))
	for _, item := range allowRaw {
		if s, ok := item.(string); ok && remove[s] {
			continue
		}
		filtered = append(filtered, item)
	}
	perms["allow"] = filtered
	raw["permissions"] = perms

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return
	}
	out = append(out, '\n')
	os.WriteFile(path, out, 0o644)
}

// buildLocalToml renders the merged result as .config/cc-allow.local.toml.
func buildLocalToml(r *migrationResult) string {
	var b strings.Builder
	b.WriteString("version = \"2.0\"\n")
	b.WriteString("# Auto-migrated from .claude/settings.local.json\n")
	b.WriteString("# To make permanent, add to .config/cc-allow.toml or ~/.config/cc-allow.toml.\n")

	if len(r.Commands) > 0 {
		b.WriteString("\n[bash.allow]\n")
		b.WriteString(fmt.Sprintf("commands = [%s]\n", formatList(r.Commands)))
	}
	for _, rule := range r.Rules {
		b.WriteString(fmt.Sprintf("\n[[bash.allow.%s]]\n", strings.Join(rule.Subs, ".")))
		if len(rule.ArgsAll) > 0 {
			b.WriteString(fmt.Sprintf("args.all = [%s]\n", formatList(rule.ArgsAll)))
		}
	}
	for _, section := range fileSections {
		if len(r.Paths[section]) > 0 {
			b.WriteString(fmt.Sprintf("\n[%s.allow]\n", section))
			b.WriteString(fmt.Sprintf("paths = [%s]\n", formatList(r.Paths[section])))
		}
	}
	if len(r.WebFetch) > 0 {
		b.WriteString("\n[webfetch.allow]\n")
		b.WriteString(fmt.Sprintf("paths = [%s]\n", formatList(r.WebFetch)))
	}
	return b.String()
}

// formatList formats a sorted list of strings for TOML output.
func formatList(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return strings.Join(quoted, ", ")
}

// dedup removes duplicates from a string slice and returns a sorted result.
func dedup(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

// fileExists returns true if the path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
