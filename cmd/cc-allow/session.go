package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// parseSessionMaxAge parses duration strings: "7d" -> 7*24h, or standard Go durations like "24h".
func parseSessionMaxAge(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		d, err := time.ParseDuration(days + "h")
		if err != nil {
			return 0, err
		}
		return d * 24, nil
	}
	return time.ParseDuration(s)
}

// cleanupSessionConfigs deletes session config files older than maxAge.
// Best-effort: errors are silently ignored.
func cleanupSessionConfigs(projectRoot string, maxAge time.Duration) {
	if projectRoot == "" {
		return
	}
	sessionsDir := filepath.Join(projectRoot, ".config", "cc-allow", "sessions")
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == ".gitignore" || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(sessionsDir, entry.Name()))
		}
	}
}
