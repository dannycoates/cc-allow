package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// countSessionMatches evaluates a tool input against all other session configs.
// Returns the number of sessions that would allow the given tool use.
func countSessionMatches(projectRoot, currentSessionID string, input HookInput) int {
	if projectRoot == "" {
		return 0
	}

	sessionsDir := filepath.Join(projectRoot, ".config", "cc-allow", "sessions")
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return 0
	}

	currentFile := currentSessionID + ".toml"
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == ".gitignore" || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		if entry.Name() == currentFile {
			continue
		}
		cfg, err := loadConfig(filepath.Join(sessionsDir, entry.Name()))
		if err != nil {
			continue
		}
		chain := &ConfigChain{
			Configs:     []*Config{cfg},
			ProjectRoot: projectRoot,
		}
		dispatcher := NewToolDispatcher(chain)
		result := dispatcher.Dispatch(input)
		if result.Action == ActionAllow {
			count++
		}
	}
	return count
}

// buildSessionMatchContext builds additionalContext for PostToolUse when other sessions match.
func buildSessionMatchContext(matchCount int, toolName ToolName, inputDesc string) string {
	return fmt.Sprintf(
		"<system-reminder>The tool use just approved (%s %s) is also covered by rules in %d other session(s). "+
			"You MUST use AskUserQuestion to ask if they want to add a matching rule to the project level config "+
			"(.config/cc-allow.toml) so it applies to all sessions. If they agree, use /allow-rules to add it.</system-reminder>",
		toolName, inputDesc, matchCount,
	)
}

// describeToolInput returns a human-readable description of the tool input.
func describeToolInput(input HookInput) string {
	switch input.ToolName {
	case ToolBash:
		return "command: `" + input.ToolInput.Command + "`"
	case ToolRead, ToolWrite, ToolEdit:
		return "file: `" + input.ToolInput.FilePath + "`"
	case ToolWebFetch:
		return "URL: `" + input.ToolInput.URL + "`"
	case ToolGlob, ToolGrep:
		if input.ToolInput.Path != "" {
			return "pattern='" + input.ToolInput.Pattern + "' path='" + input.ToolInput.Path + "'"
		}
		return "pattern='" + input.ToolInput.Pattern + "'"
	default:
		return ""
	}
}
