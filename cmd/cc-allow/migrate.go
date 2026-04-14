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

// fileTools are the tool names whose path-scoped entries can be migrated.
var fileTools = map[string]string{
	"Edit":  "edit",
	"Read":  "read",
	"Write": "write",
}

// validCommandStart matches the first character of a valid command name.
var validCommandStart = regexp.MustCompile(`^[a-zA-Z./_~]`)

// settingsFile is used for reading the permissions.allow array from settings.local.json.
type settingsFile struct {
	Permissions struct {
		Allow []string `json:"allow"`
	} `json:"permissions"`
}

// migrationResult holds the commands and file paths extracted during migration.
type migrationResult struct {
	Commands []string            // bash commands migrated
	Paths    map[string][]string // tool (edit/read/write) → paths migrated
}

func (r *migrationResult) empty() bool {
	if len(r.Commands) > 0 {
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

// migrateSettingsPermissions detects Bash(...), Edit(...), Read(...), and Write(...)
// entries in settings.local.json files, extracts command names and file paths,
// writes them to .config/cc-allow.local.toml, and strips migrated entries from
// settings.local.json. Returns a migrationResult describing what was migrated.
func migrateSettingsPermissions(projectRoot string) *migrationResult {
	home, _ := os.UserHomeDir()

	projectSettings := filepath.Join(projectRoot, ".claude", "settings.local.json")
	globalSettings := ""
	if home != "" {
		globalSettings = filepath.Join(home, ".claude", "settings.local.json")
	}

	// Fast path: if neither file exists, return nil.
	projectExists := fileExists(projectSettings)
	globalExists := globalSettings != "" && fileExists(globalSettings)
	if !projectExists && !globalExists {
		return nil
	}

	// Collect commands and file paths from both files.
	result := &migrationResult{Paths: make(map[string][]string)}

	for _, path := range []string{projectSettings, globalSettings} {
		if path == "" || !fileExists(path) {
			continue
		}
		result.Commands = append(result.Commands, extractBashCommands(path)...)
		for tool, paths := range extractFileToolPaths(path) {
			result.Paths[tool] = append(result.Paths[tool], paths...)
		}
	}

	if result.empty() {
		return nil
	}

	// Deduplicate and sort.
	result.Commands = dedup(result.Commands)
	for tool, paths := range result.Paths {
		result.Paths[tool] = dedup(paths)
	}

	// Merge into .config/cc-allow.local.toml.
	localTomlPath := filepath.Join(projectRoot, ".config", "cc-allow.local.toml")
	existing := readExistingLocalToml(localTomlPath)

	mergedCommands := dedup(append(existing.commands, result.Commands...))
	mergedPaths := make(map[string][]string)
	for _, tool := range []string{"edit", "read", "write"} {
		mergedPaths[tool] = dedup(append(existing.paths[tool], result.Paths[tool]...))
	}

	// Write the local.toml file.
	if err := os.MkdirAll(filepath.Join(projectRoot, ".config"), 0755); err != nil {
		return nil
	}
	content := buildLocalToml(mergedCommands, mergedPaths)
	if err := os.WriteFile(localTomlPath, []byte(content), 0644); err != nil {
		return nil
	}

	// Strip migrated entries from both settings files.
	if projectExists {
		stripSettingsEntries(projectSettings)
	}
	if globalExists {
		stripSettingsEntries(globalSettings)
	}

	return result
}

// extractBashCommands reads a settings.local.json and returns command names from Bash(...) entries.
func extractBashCommands(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var sf settingsFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil
	}

	var commands []string
	for _, entry := range sf.Permissions.Allow {
		if !strings.HasPrefix(entry, "Bash(") {
			continue
		}

		cmd := extractCommandName(entry)
		if cmd == "" {
			continue
		}

		// Filter out shell constructs.
		if shellConstructs[cmd] {
			continue
		}

		// Filter out entries starting with invalid characters.
		if !validCommandStart.MatchString(cmd) {
			continue
		}

		// Filter out entries containing = (env var assignments).
		if strings.Contains(cmd, "=") {
			continue
		}

		// Filter out entries containing quotes or backslashes.
		if strings.ContainsAny(cmd, "\"'\\") {
			continue
		}

		commands = append(commands, cmd)
	}

	return commands
}

// extractFileToolPaths reads a settings.local.json and returns path-scoped file tool entries.
// Returns a map of lowercase tool name ("edit", "read", "write") to cc-allow path patterns.
// Bare tool names (e.g. "Edit" without parens) are skipped.
func extractFileToolPaths(path string) map[string][]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var sf settingsFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil
	}

	result := make(map[string][]string)
	for _, entry := range sf.Permissions.Allow {
		for toolName, ccTool := range fileTools {
			prefix := toolName + "("
			if !strings.HasPrefix(entry, prefix) {
				continue
			}
			// Strip prefix and closing paren.
			inner := strings.TrimPrefix(entry, prefix)
			inner = strings.TrimSuffix(inner, ")")
			inner = strings.TrimSpace(inner)
			if inner == "" {
				continue
			}
			// Prefix with "path:" for cc-allow.
			result[ccTool] = append(result[ccTool], "path:"+inner)
		}
	}

	return result
}

// extractCommandName extracts the base command name from a Bash(...) entry.
// Strips "Bash(" prefix and everything from ":" or ")" onward, then takes the first word.
func extractCommandName(entry string) string {
	// Strip "Bash(" prefix.
	s := strings.TrimPrefix(entry, "Bash(")

	// Strip from ":" or ")" onward.
	if idx := strings.IndexAny(s, ":)"); idx >= 0 {
		s = s[:idx]
	}

	// Take first space-delimited word.
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, " "); idx >= 0 {
		s = s[:idx]
	}

	return s
}

// isMigratableEntry returns true if the entry should be stripped from settings.local.json.
// This includes Bash(...), WebFetch(...), and path-scoped file tool entries (Edit/Read/Write with parens).
func isMigratableEntry(entry string) bool {
	if strings.HasPrefix(entry, "Bash(") || strings.HasPrefix(entry, "WebFetch(") {
		return true
	}
	for toolName := range fileTools {
		if strings.HasPrefix(entry, toolName+"(") {
			return true
		}
	}
	return false
}

// stripSettingsEntries removes migratable entries from a settings.local.json file,
// preserving all other fields.
func stripSettingsEntries(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	perms, ok := raw["permissions"].(map[string]interface{})
	if !ok {
		return
	}

	allowRaw, ok := perms["allow"].([]interface{})
	if !ok {
		return
	}

	filtered := make([]interface{}, 0, len(allowRaw))
	for _, item := range allowRaw {
		s, ok := item.(string)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		if isMigratableEntry(s) {
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
	// Append newline for consistency.
	out = append(out, '\n')

	os.WriteFile(path, out, 0644)
}

// existingLocalToml holds parsed data from an existing cc-allow.local.toml.
type existingLocalToml struct {
	commands []string
	paths    map[string][]string // tool → paths
}

// readExistingLocalToml reads commands and file paths from an existing cc-allow.local.toml.
func readExistingLocalToml(path string) existingLocalToml {
	result := existingLocalToml{paths: make(map[string][]string)}

	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	currentSection := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)

		// Track section headers.
		if strings.HasPrefix(trimmed, "[") {
			switch trimmed {
			case "[bash.allow]":
				currentSection = "bash"
			case "[edit.allow]":
				currentSection = "edit"
			case "[read.allow]":
				currentSection = "read"
			case "[write.allow]":
				currentSection = "write"
			default:
				currentSection = ""
			}
			continue
		}

		// Parse array lines.
		if currentSection == "bash" && strings.HasPrefix(trimmed, "commands") {
			result.commands = parseTomlArray(trimmed)
		}
		if (currentSection == "edit" || currentSection == "read" || currentSection == "write") &&
			strings.HasPrefix(trimmed, "paths") {
			result.paths[currentSection] = parseTomlArray(trimmed)
		}
	}

	return result
}

// parseTomlArray extracts string values from a TOML one-line array like: key = ["a", "b"]
func parseTomlArray(line string) []string {
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	inner := line[start+1 : end]
	var items []string
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"")
		if part != "" {
			items = append(items, part)
		}
	}
	return items
}

// buildLocalToml generates the TOML content for .config/cc-allow.local.toml.
func buildLocalToml(commands []string, paths map[string][]string) string {
	var b strings.Builder
	b.WriteString("version = \"2.0\"\n")
	b.WriteString("# Auto-migrated from .claude/settings.local.json\n")
	b.WriteString("# To make permanent, add to .config/cc-allow.toml or ~/.config/cc-allow.toml.\n")

	if len(commands) > 0 {
		b.WriteString("\n[bash.allow]\n")
		b.WriteString(fmt.Sprintf("commands = [%s]\n", formatList(commands)))
	}

	for _, tool := range []string{"edit", "read", "write"} {
		if len(paths[tool]) > 0 {
			b.WriteString(fmt.Sprintf("\n[%s.allow]\n", tool))
			b.WriteString(fmt.Sprintf("paths = [%s]\n", formatList(paths[tool])))
		}
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
