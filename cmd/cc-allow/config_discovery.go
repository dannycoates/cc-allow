package main

import (
	"os"
	"path/filepath"
	"strings"
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
	if projectRoot == "" {
		return ProjectConfigResult{}
	}

	// If project root is $HOME, treat as no project (global config is handled separately)
	if home, _ := os.UserHomeDir(); home != "" && projectRoot == home {
		return ProjectConfigResult{}
	}

	// When CC_PROJECT_DIR is set, it's authoritative - only check at the project root.
	// Otherwise walk from cwd up to the project root to support configs at intermediate
	// levels (e.g., monorepo packages).
	if os.Getenv("CC_PROJECT_DIR") != "" {
		return checkProjectConfigsAt(projectRoot)
	}

	cwd, err := os.Getwd()
	if err != nil {
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

// checkProjectConfigsAt checks for cc-allow configs at a single directory (no walking).
func checkProjectConfigsAt(dir string) ProjectConfigResult {
	result := ProjectConfigResult{}

	newPath := filepath.Join(dir, ".config", "cc-allow.toml")
	oldPath := filepath.Join(dir, ".claude", "cc-allow.toml")
	if _, err := os.Stat(newPath); err == nil {
		result.ProjectConfig = newPath
	} else if _, err := os.Stat(oldPath); err == nil {
		result.ProjectConfig = oldPath
		result.LegacyPaths = append(result.LegacyPaths, oldPath)
	}

	newLocal := filepath.Join(dir, ".config", "cc-allow.local.toml")
	oldLocal := filepath.Join(dir, ".claude", "cc-allow.local.toml")
	if _, err := os.Stat(newLocal); err == nil {
		result.LocalConfig = newLocal
	} else if _, err := os.Stat(oldLocal); err == nil {
		result.LocalConfig = oldLocal
		result.LegacyPaths = append(result.LegacyPaths, oldLocal)
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
	if projectRoot == "" {
		return ""
	}

	// If project root is $HOME, treat as no project
	if home, _ := os.UserHomeDir(); home != "" && projectRoot == home {
		return ""
	}

	// When CC_PROJECT_DIR is set, it's authoritative - only check at the project root.
	if os.Getenv("CC_PROJECT_DIR") != "" {
		path := filepath.Join(projectRoot, ".config", "cc-allow", agent+".toml")
		if _, err := os.Stat(path); err == nil {
			return path
		}
		return ""
	}

	cwd, err := os.Getwd()
	if err != nil {
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

// findSessionConfig looks for .config/cc-allow/sessions/<sessionID>.toml
// at the project root. Returns the path if found, or empty string if not found.
func findSessionConfig(sessionID string, projectRoot string) string {
	if sessionID == "" || projectRoot == "" {
		return ""
	}
	// Sanitize: reject path traversal
	if strings.Contains(sessionID, "/") || strings.Contains(sessionID, "\\") || strings.Contains(sessionID, "..") {
		return ""
	}
	path := filepath.Join(projectRoot, ".config", "cc-allow", "sessions", sessionID+".toml")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// findProjectRoot looks for the project root directory.
// If CC_PROJECT_DIR is set, it is used directly.
// Otherwise, it uses a two-pass search from cwd:
//
// Pass 1: Walk up looking for .config/cc-allow.toml (explicit cc-allow config marker).
//
//	This takes priority over .git to correctly handle subdirectories that have
//	their own .git (e.g., submodules, nested repos) within a parent project
//	that has a cc-allow config. Skips $HOME since ~/.config/cc-allow.toml is
//	the global config loaded separately by findGlobalConfig().
//
// Pass 2: Fall back to .claude/ directory (legacy) or .git (directory or file).
//
// Returns empty string if none found.
func findProjectRoot() string {
	if envDir := os.Getenv("CC_PROJECT_DIR"); envDir != "" {
		return envDir
	}

	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	home, _ := os.UserHomeDir()

	// Pass 1: Look for .config/cc-allow.toml (explicit cc-allow marker, highest priority).
	// Skip $HOME because ~/.config/cc-allow.toml is the global config, not a project marker.
	dir := cwd
	for {
		if home == "" || dir != home {
			configToml := filepath.Join(dir, ".config", "cc-allow.toml")
			if _, err := os.Stat(configToml); err == nil {
				return dir
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Pass 2: Fall back to .claude/ directory (legacy) or .git marker.
	dir = cwd
	for {
		claudePath := filepath.Join(dir, ".claude")
		if info, err := os.Stat(claudePath); err == nil && info.IsDir() {
			return dir
		}

		gitPath := filepath.Join(dir, ".git")
		if _, err := os.Stat(gitPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}
