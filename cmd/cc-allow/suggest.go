package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cc-allow/pkg/pathutil"
)

// mntDriveRoot matches a bare WSL/Windows drive-mount root like /mnt/d.
var mntDriveRoot = regexp.MustCompile(`^/mnt/[^/]+$`)

// runSuggestRule reads PostToolUse hook JSON from stdin and, for an approved
// Read/Write/Edit/WebFetch/Glob/Grep, deterministically computes a directory-
// or origin-scoped allow rule and merges it into the session's TOML config.
// It exits allow only once the merged rule causes the original input to
// evaluate to "allow"; anything else (unsupported tool, unsafe directory, a
// pattern that still doesn't match) exits ask so the caller falls through to
// today's behavior of just asking again next time.
func runSuggestRule() ExitCode {
	input, err := buildInput(true, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	section, ok := sectionForTool(input.ToolName)
	if !ok {
		return ExitAsk
	}

	if input.SessionID == "" || strings.ContainsAny(input.SessionID, "/\\") || strings.Contains(input.SessionID, "..") {
		return ExitAsk
	}

	projectRoot := findProjectRoot()
	if projectRoot == "" {
		return ExitAsk
	}

	home, _ := os.UserHomeDir()

	var candidate string
	var matchInput string

	switch input.ToolName {
	case ToolRead, ToolWrite, ToolEdit:
		path := input.ToolInput.FilePath
		if path == "" {
			return ExitAsk
		}
		dir := filepath.Dir(path)
		if tooBroadDir(dir, home) {
			return ExitAsk
		}
		candidate = patternForDir(dir, home, projectRoot)
		matchInput = path

	case ToolGlob, ToolGrep:
		dir := input.ToolInput.Path
		if dir == "" {
			dir, _ = os.Getwd()
		}
		if dir == "" || tooBroadDir(dir, home) {
			return ExitAsk
		}
		candidate = patternForDir(dir, home, projectRoot)
		matchInput = dir

	case ToolWebFetch:
		rawURL := input.ToolInput.URL
		if rawURL == "" {
			return ExitAsk
		}
		pat, err := patternForURL(rawURL)
		if err != nil {
			return ExitAsk
		}
		candidate = pat
		matchInput = rawURL

	default:
		return ExitAsk
	}

	pattern, err := ParsePattern(candidate)
	if err != nil {
		return ExitAsk
	}
	pathVars := pathutil.NewPathVars(projectRoot)
	matchCtx := &MatchContext{PathVars: pathVars}
	if !pattern.MatchWithContext(matchInput, matchCtx) {
		return ExitAsk
	}

	sessionPath := filepath.Join(projectRoot, ".config", "cc-allow", "sessions", input.SessionID+".toml")
	if err := os.MkdirAll(filepath.Dir(sessionPath), 0o755); err != nil {
		return ExitError
	}
	if _, err := mergeSessionRule(sessionPath, section, candidate); err != nil {
		return ExitError
	}

	chain, err := LoadConfigChain("", input.SessionID)
	if err != nil {
		return ExitAsk
	}
	result := NewToolDispatcher(chain).Dispatch(input)
	if result.Action == ActionAllow {
		return ExitAllow
	}
	return ExitAsk
}

// sectionForTool maps a hook tool name to the cc-allow config section its
// allow rule belongs in. Glob/Grep route to "read" because cc-allow's
// glob/grep inherit from read via respect_file_rules (see migrate.go's
// fileToolDest for the same convention). Bash and unknown tools return ok=false
// since the caller keeps using the existing LLM-authored path for those.
func sectionForTool(tool ToolName) (section string, ok bool) {
	switch tool {
	case ToolRead, ToolGlob, ToolGrep:
		return "read", true
	case ToolWrite:
		return "write", true
	case ToolEdit:
		return "edit", true
	case ToolWebFetch:
		return "webfetch", true
	default:
		return "", false
	}
}

// tooBroadDir reports whether dir is too shallow to safely generalize into a
// durable allow rule: $HOME itself, the filesystem root, one level above
// $HOME (e.g. /home or /Users -- catches sibling home directories too), or a
// bare drive-mount root like /mnt/d. This is the deterministic replacement
// for the old claude -p prompt's fuzzy "not too loose or specific" guidance.
func tooBroadDir(dir, home string) bool {
	if dir == "" || dir == "/" {
		return true
	}
	if home != "" && (dir == home || dir == filepath.Dir(home)) {
		return true
	}
	return mntDriveRoot.MatchString(dir)
}

// patternForDir builds a cc-allow "path:" pattern generalizing dir to itself
// plus everything under it, preferring cc-allow's portable $HOME/$PROJECT_ROOT
// variables over a literal path -- the same convention translatePath already
// uses in migrate.go.
func patternForDir(dir, home, projectRoot string) string {
	if rest, ok := relativeTo(dir, home); ok {
		return joinPathPattern("$HOME", rest)
	}
	if rest, ok := relativeTo(dir, projectRoot); ok {
		return joinPathPattern("$PROJECT_ROOT", rest)
	}
	return "path:" + dir + "/**"
}

// relativeTo returns the portion of dir under base (empty if dir == base),
// and ok=false if base is empty or dir is not base or a descendant of it.
func relativeTo(dir, base string) (rest string, ok bool) {
	if base == "" {
		return "", false
	}
	if dir == base {
		return "", true
	}
	prefix := base + string(filepath.Separator)
	if !strings.HasPrefix(dir, prefix) {
		return "", false
	}
	return strings.TrimPrefix(dir, prefix), true
}

// joinPathPattern builds a "path:" pattern from a portable variable and the
// path segment under it (rest == "" when dir was exactly the variable's root).
func joinPathPattern(variable, rest string) string {
	if rest == "" {
		return "path:" + variable + "/**"
	}
	return "path:" + variable + "/" + rest + "/**"
}

// patternForURL builds a cc-allow "re:" pattern generalizing a URL to its
// scheme+host, matching translateWebFetch's construction in migrate.go.
func patternForURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("suggest-rule: URL missing scheme or host: %s", rawURL)
	}
	return "re:^" + regexp.QuoteMeta(u.Scheme+"://"+u.Host) + "/", nil
}

// sectionHeaderStart returns the index right after "[<section>.allow]"'s
// closing bracket, or -1 if that header line isn't present in text.
func sectionHeaderStart(text, section string) int {
	re := regexp.MustCompile(`(?m)^\[` + regexp.QuoteMeta(section+".allow") + `\]\s*?$`)
	loc := re.FindStringIndex(text)
	if loc == nil {
		return -1
	}
	return loc[1]
}

// nextSectionHeaderOffset returns the offset (within text) of the next
// top-level "[...]" header line, or len(text) if there is none.
func nextSectionHeaderOffset(text string) int {
	re := regexp.MustCompile(`(?m)^\[`)
	if loc := re.FindStringIndex(text); loc != nil {
		return loc[0]
	}
	return len(text)
}

// pathsArrayRe matches a "paths = [" key opening within a section body.
var pathsArrayRe = regexp.MustCompile(`(?m)^\s*paths\s*=\s*\[`)

// mergeSessionRule inserts pattern into the "paths" array of "[section.allow]"
// in the session config at path, creating the file or section as needed. It
// never parses or rewrites the rest of the file -- only this narrow text
// region is touched -- so any existing LLM-authored [bash.allow] block is
// left untouched byte-for-byte. Returns changed=false if pattern is already
// present verbatim (a prior invocation got there first).
func mergeSessionRule(path, section, pattern string) (changed bool, err error) {
	quoted := fmt.Sprintf("%q", pattern)

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		data = []byte("version = \"2.0\"\n")
	}
	text := string(data)

	headerEnd := sectionHeaderStart(text, section)
	if headerEnd == -1 {
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += fmt.Sprintf("\n[%s.allow]\npaths = [%s]\n", section, quoted)
		return true, os.WriteFile(path, []byte(text), 0o644)
	}

	sectionEnd := headerEnd + nextSectionHeaderOffset(text[headerEnd:])
	body := text[headerEnd:sectionEnd]

	loc := pathsArrayRe.FindStringIndex(body)
	if loc == nil {
		newText := text[:headerEnd] + "\npaths = [" + quoted + "]\n" + text[headerEnd:]
		return true, os.WriteFile(path, []byte(newText), 0o644)
	}

	arrayOpen := headerEnd + loc[1] - 1 // index of the '[' itself
	closeRel := strings.Index(body[loc[1]:], "]")
	if closeRel == -1 {
		return false, fmt.Errorf("suggest-rule: malformed paths array in %s", path)
	}
	arrayClose := headerEnd + loc[1] + closeRel // index of the matching ']'

	arrayBody := text[arrayOpen+1 : arrayClose]
	if strings.Contains(arrayBody, quoted) {
		return false, nil
	}

	insertion := ", " + quoted
	if strings.TrimSpace(arrayBody) == "" {
		insertion = quoted
	}
	newText := text[:arrayClose] + insertion + text[arrayClose:]
	return true, os.WriteFile(path, []byte(newText), 0o644)
}
