package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseSessionMaxAge(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"168h", 168 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"", 0, true},
		{"abc", 0, true},
		{"xd", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSessionMaxAge(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSessionMaxAge(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("parseSessionMaxAge(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCleanupSessionConfigs(t *testing.T) {
	tmpDir := t.TempDir()
	sessionsDir := filepath.Join(tmpDir, ".config", "cc-allow", "sessions")
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a .gitignore (should not be deleted)
	if err := os.WriteFile(filepath.Join(sessionsDir, ".gitignore"), []byte("*\n!.gitignore\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a fresh session file
	freshFile := filepath.Join(sessionsDir, "fresh-session.toml")
	if err := os.WriteFile(freshFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create an old session file
	oldFile := filepath.Join(sessionsDir, "old-session.toml")
	if err := os.WriteFile(oldFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Set modification time to 10 days ago
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// Create a non-toml file (should not be deleted)
	txtFile := filepath.Join(sessionsDir, "notes.txt")
	if err := os.WriteFile(txtFile, []byte("notes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(txtFile, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// Cleanup with 7-day max age
	cleanupSessionConfigs(tmpDir, 7*24*time.Hour)

	// Fresh session file should still exist
	if _, err := os.Stat(freshFile); err != nil {
		t.Errorf("fresh session file should still exist: %v", err)
	}

	// Old session file should be deleted
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("old session file should be deleted")
	}

	// .gitignore should still exist
	if _, err := os.Stat(filepath.Join(sessionsDir, ".gitignore")); err != nil {
		t.Errorf(".gitignore should still exist: %v", err)
	}

	// Non-toml file should still exist
	if _, err := os.Stat(txtFile); err != nil {
		t.Errorf("non-toml file should still exist: %v", err)
	}
}

func TestCleanupSessionConfigsEmptyRoot(t *testing.T) {
	// Should not panic with empty project root
	cleanupSessionConfigs("", 7*24*time.Hour)
}

func TestCleanupSessionConfigsMissingDir(t *testing.T) {
	// Should not panic with nonexistent directory
	cleanupSessionConfigs("/nonexistent/path", 7*24*time.Hour)
}
