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

// validCommandStart matches the first character of a valid command name.
var validCommandStart = regexp.MustCompile(`^[a-zA-Z./_~]`)

// settingsFile is used for reading the permissions.allow array from settings.local.json.
type settingsFile struct {
	Permissions struct {
		Allow []string `json:"allow"`
	} `json:"permissions"`
}

// migrateSettingsPermissions detects Bash(...) entries in settings.local.json files,
// extracts command names, writes them to .config/cc-allow.local.toml, and strips
// the migrated entries from settings.local.json. Returns the list of migrated command names.
func migrateSettingsPermissions(projectRoot string) []string {
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

	// Collect commands from both files.
	var allCommands []string
	if projectExists {
		allCommands = append(allCommands, extractBashCommands(projectSettings)...)
	}
	if globalExists {
		allCommands = append(allCommands, extractBashCommands(globalSettings)...)
	}

	if len(allCommands) == 0 {
		return nil
	}

	// Deduplicate and sort.
	allCommands = dedup(allCommands)

	// Merge into .config/cc-allow.local.toml.
	localTomlPath := filepath.Join(projectRoot, ".config", "cc-allow.local.toml")
	existing := readExistingCommands(localTomlPath)
	merged := dedup(append(existing, allCommands...))

	// Write the local.toml file.
	if err := os.MkdirAll(filepath.Join(projectRoot, ".config"), 0755); err != nil {
		return nil
	}
	content := fmt.Sprintf("version = \"2.0\"\n# Auto-migrated from .claude/settings.local.json\n# To make permanent, add to .config/cc-allow.toml or ~/.config/cc-allow.toml.\n\n[bash.allow]\ncommands = [%s]\n", formatCommandList(merged))
	if err := os.WriteFile(localTomlPath, []byte(content), 0644); err != nil {
		return nil
	}

	// Strip Bash( and WebFetch( entries from both settings files.
	if projectExists {
		stripSettingsEntries(projectSettings)
	}
	if globalExists {
		stripSettingsEntries(globalSettings)
	}

	return allCommands
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

// stripSettingsEntries removes Bash( and WebFetch( entries from a settings.local.json file,
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
		if strings.HasPrefix(s, "Bash(") || strings.HasPrefix(s, "WebFetch(") {
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

// readExistingCommands reads commands from an existing cc-allow.local.toml file.
func readExistingCommands(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var commands []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "commands") {
			continue
		}
		// Extract content between [ and ].
		start := strings.Index(line, "[")
		end := strings.LastIndex(line, "]")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		inner := line[start+1 : end]
		for _, part := range strings.Split(inner, ",") {
			part = strings.TrimSpace(part)
			part = strings.Trim(part, "\"")
			if part != "" {
				commands = append(commands, part)
			}
		}
	}

	return commands
}

// formatCommandList formats a sorted list of commands for TOML output.
func formatCommandList(commands []string) string {
	quoted := make([]string, len(commands))
	for i, cmd := range commands {
		quoted[i] = fmt.Sprintf("%q", cmd)
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
