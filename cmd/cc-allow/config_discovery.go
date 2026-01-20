package main

import (
	"os"
	"path/filepath"
)

// Config discovery functions for cc-allow.
// Handles finding config files in standard locations.

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

// findProjectConfigs looks for .claude/cc-allow.toml and .claude/cc-allow.local.toml
// starting from cwd and walking up. Returns both paths in a single traversal.
func findProjectConfigs() (projectConfig, localConfig string) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", ""
	}

	dir := cwd
	for {
		if projectConfig == "" {
			path := filepath.Join(dir, ".claude", "cc-allow.toml")
			if _, err := os.Stat(path); err == nil {
				projectConfig = path
			}
		}
		if localConfig == "" {
			path := filepath.Join(dir, ".claude", "cc-allow.local.toml")
			if _, err := os.Stat(path); err == nil {
				localConfig = path
			}
		}

		// Found both, done
		if projectConfig != "" && localConfig != "" {
			break
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}

	return projectConfig, localConfig
}

// findProjectRoot looks for the project root directory.
// It walks up from cwd looking for:
// 1. .claude/ directory (preferred)
// 2. .git/ directory (fallback)
// Returns empty string if neither found.
func findProjectRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		// Check for .claude/ directory
		claudePath := filepath.Join(dir, ".claude")
		if info, err := os.Stat(claudePath); err == nil && info.IsDir() {
			return dir
		}

		// Check for .git/ directory
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
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
