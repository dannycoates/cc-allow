package main

import (
	"os"
	"path/filepath"
)

// Config discovery functions for cc-allow.
// Handles finding config files in standard locations.

// ProjectConfigResult holds discovery results including migration info.
type ProjectConfigResult struct {
	ProjectConfig string   // path to project config (empty if not found)
	LocalConfig   string   // path to local config (empty if not found)
	LegacyPaths   []string // paths found at old .claude/ location (needs migration)
}

// findGlobalConfig looks for ~/.config/cc-allow.toml
func findGlobalConfig() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".config", "cc-allow.toml")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// findProjectConfigs looks for cc-allow.toml and cc-allow.local.toml
// starting from cwd and walking up to the project root. Prefers .config/ over .claude/ (legacy).
// If found at .claude/, the path is recorded in LegacyPaths for migration hints.
// Only searches within the project boundary (up to and including project root).
// Returns empty if project root is $HOME (global config there is handled separately).
func findProjectConfigs() ProjectConfigResult {
	return findProjectConfigsWithRoot(findProjectRoot())
}

// findProjectConfigsWithRoot is like findProjectConfigs but accepts a pre-computed project root
// to avoid redundant filesystem traversals.
func findProjectConfigsWithRoot(projectRoot string) ProjectConfigResult {
	cwd, err := os.Getwd()
	if err != nil {
		return ProjectConfigResult{}
	}

	if projectRoot == "" {
		// No project root found - no project configs to find
		return ProjectConfigResult{}
	}

	// If project root is $HOME, treat as no project (global config is handled separately)
	if home, _ := os.UserHomeDir(); home != "" && projectRoot == home {
		return ProjectConfigResult{}
	}

	result := ProjectConfigResult{}
	dir := cwd
	for {
		if result.ProjectConfig == "" {
			newPath := filepath.Join(dir, ".config", "cc-allow.toml")
			oldPath := filepath.Join(dir, ".claude", "cc-allow.toml")
			if _, err := os.Stat(newPath); err == nil {
				result.ProjectConfig = newPath
			} else if _, err := os.Stat(oldPath); err == nil {
				result.ProjectConfig = oldPath
				result.LegacyPaths = append(result.LegacyPaths, oldPath)
			}
		}
		if result.LocalConfig == "" {
			newPath := filepath.Join(dir, ".config", "cc-allow.local.toml")
			oldPath := filepath.Join(dir, ".claude", "cc-allow.local.toml")
			if _, err := os.Stat(newPath); err == nil {
				result.LocalConfig = newPath
			} else if _, err := os.Stat(oldPath); err == nil {
				result.LocalConfig = oldPath
				result.LegacyPaths = append(result.LegacyPaths, oldPath)
			}
		}

		// Found both, or reached project root - done
		if (result.ProjectConfig != "" && result.LocalConfig != "") || dir == projectRoot {
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return result
}

// findAgentConfig looks for .config/cc-allow/<agent>.toml
// starting from cwd and walking up to the project root.
// Returns the path if found, or empty string if not found.
// Returns empty if project root is $HOME (global config location).
func findAgentConfig(agent string) string {
	return findAgentConfigWithRoot(agent, findProjectRoot())
}

// findAgentConfigWithRoot is like findAgentConfig but accepts a pre-computed project root
// to avoid redundant filesystem traversals.
func findAgentConfigWithRoot(agent string, projectRoot string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	if projectRoot == "" {
		return ""
	}

	// If project root is $HOME, treat as no project
	if home, _ := os.UserHomeDir(); home != "" && projectRoot == home {
		return ""
	}

	dir := cwd
	for {
		path := filepath.Join(dir, ".config", "cc-allow", agent+".toml")
		if _, err := os.Stat(path); err == nil {
			return path
		}

		// Reached project root, stop searching
		if dir == projectRoot {
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// findProjectRoot looks for the project root directory.
// It walks up from cwd looking for:
// 1. .config/cc-allow.toml file (new preferred location)
// 2. .claude/ directory (legacy)
// 3. .git (directory for normal repos, file for worktrees)
// Returns empty string if none found.
func findProjectRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		// Check for .config/cc-allow.toml (new location, check specific file to avoid false positives)
		configToml := filepath.Join(dir, ".config", "cc-allow.toml")
		if _, err := os.Stat(configToml); err == nil {
			return dir
		}

		// Check for .claude/ directory (legacy)
		claudePath := filepath.Join(dir, ".claude")
		if info, err := os.Stat(claudePath); err == nil && info.IsDir() {
			return dir
		}

		// Check for .git (directory for normal repos, file for worktrees)
		gitPath := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}

	return ""
}
