package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateNoSettingsFiles(t *testing.T) {
	tmpDir := t.TempDir()
	result := migrateSettingsPermissions(tmpDir)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
	// No local.toml should be created.
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	if _, err := os.Stat(localToml); !os.IsNotExist(err) {
		t.Errorf("cc-allow.local.toml should not exist")
	}
}

func TestMigrateNoBashEntries(t *testing.T) {
	tmpDir := t.TempDir()

	// Create settings file with no Bash entries.
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)

	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"MCP(server:tool)", "WebSearch"},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
	// No local.toml should be created.
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	if _, err := os.Stat(localToml); !os.IsNotExist(err) {
		t.Errorf("cc-allow.local.toml should not exist")
	}
}

func TestMigrateBashEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)

	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)",
				"Bash(npm run:*)",
				"Bash(cargo build:*)",
				"MCP(server:tool)",
			},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)
	if len(result) != 3 {
		t.Fatalf("expected 3 commands, got %d: %v", len(result), result)
	}

	// Check sorted order.
	expected := []string{"cargo", "git", "npm"}
	for i, cmd := range expected {
		if result[i] != cmd {
			t.Errorf("result[%d] = %q, want %q", i, result[i], cmd)
		}
	}

	// Check local.toml was created with the commands.
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	data, err := os.ReadFile(localToml)
	if err != nil {
		t.Fatalf("failed to read local.toml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `version = "2.0"`) {
		t.Error("local.toml missing version")
	}
	if !strings.Contains(content, `"cargo"`) {
		t.Error("local.toml missing cargo")
	}
	if !strings.Contains(content, `"git"`) {
		t.Error("local.toml missing git")
	}
	if !strings.Contains(content, `"npm"`) {
		t.Error("local.toml missing npm")
	}

	// Check settings.local.json was stripped of Bash entries but kept MCP.
	settingsData, err := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	if err != nil {
		t.Fatalf("failed to read settings.local.json: %v", err)
	}
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d: %v", len(allow), allow)
	}
	if allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected MCP entry to remain, got %v", allow[0])
	}
}

func TestMigrateMergeExistingLocalToml(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Create existing local.toml with some commands.
	configDir := filepath.Join(tmpDir, ".config")
	os.MkdirAll(configDir, 0755)
	existingContent := `version = "2.0"
[bash.allow]
commands = ["make", "git"]
`
	os.WriteFile(filepath.Join(configDir, "cc-allow.local.toml"), []byte(existingContent), 0644)

	// Create settings with new commands (git is duplicate).
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)",
				"Bash(cargo:*)",
			},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)
	if len(result) != 2 {
		t.Fatalf("expected 2 migrated commands, got %d: %v", len(result), result)
	}

	// Check that local.toml has all commands (merged, deduplicated, sorted).
	data, err := os.ReadFile(filepath.Join(configDir, "cc-allow.local.toml"))
	if err != nil {
		t.Fatalf("failed to read local.toml: %v", err)
	}
	content := string(data)
	// Should have all four: cargo, git, make (from existing + new, deduplicated).
	if !strings.Contains(content, `"cargo"`) {
		t.Error("local.toml missing cargo")
	}
	if !strings.Contains(content, `"git"`) {
		t.Error("local.toml missing git")
	}
	if !strings.Contains(content, `"make"`) {
		t.Error("local.toml missing make")
	}
}

func TestMigrateFiltersShellConstructs(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(do)",
				"Bash(done)",
				"Bash(for:*)",
				"Bash(while:*)",
				"Bash(if:*)",
				"Bash(then)",
				"Bash(else)",
				"Bash(elif)",
				"Bash(fi)",
				"Bash(case:*)",
				"Bash(esac)",
				"Bash(break)",
				"Bash(continue)",
				"Bash(in)",
				"Bash(git:*)",
			},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)
	if len(result) != 1 {
		t.Fatalf("expected 1 command (only git), got %d: %v", len(result), result)
	}
	if result[0] != "git" {
		t.Errorf("expected git, got %q", result[0])
	}
}

func TestMigrateFiltersEnvVarAssignments(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(FOO=bar cmd:*)",
				"Bash(git:*)",
			},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)
	if len(result) != 1 {
		t.Fatalf("expected 1 command (only git), got %d: %v", len(result), result)
	}
	if result[0] != "git" {
		t.Errorf("expected git, got %q", result[0])
	}
}

func TestMigratePreservesNonBashEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)",
				"MCP(server:tool)",
				"WebSearch",
				"Skills(skill:name)",
			},
		},
		"other_field": "preserved",
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	migrateSettingsPermissions(tmpDir)

	// Check settings still has non-Bash entries.
	settingsData, err := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	if err != nil {
		t.Fatalf("failed to read settings.local.json: %v", err)
	}
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)

	// other_field should be preserved.
	if parsed["other_field"] != "preserved" {
		t.Error("other_field was not preserved")
	}

	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 3 {
		t.Fatalf("expected 3 remaining entries, got %d: %v", len(allow), allow)
	}

	// MCP, WebSearch, Skills should remain.
	remaining := make([]string, len(allow))
	for i, v := range allow {
		remaining[i] = v.(string)
	}
	expectedRemaining := []string{"MCP(server:tool)", "WebSearch", "Skills(skill:name)"}
	for _, exp := range expectedRemaining {
		found := false
		for _, r := range remaining {
			if r == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to remain in settings, got %v", exp, remaining)
		}
	}
}

func TestMigrateStripsWebFetchEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)",
				"WebFetch(domain:example.com)",
				"WebFetch(domain:docs.rs)",
				"MCP(server:tool)",
			},
		},
	}
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), settings)

	result := migrateSettingsPermissions(tmpDir)

	// Only git should be in the migrated commands (WebFetch stripped but not migrated).
	if len(result) != 1 {
		t.Fatalf("expected 1 command, got %d: %v", len(result), result)
	}
	if result[0] != "git" {
		t.Errorf("expected git, got %q", result[0])
	}

	// Check settings: WebFetch and Bash entries should be removed, MCP stays.
	settingsData, err := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	if err != nil {
		t.Fatalf("failed to read settings.local.json: %v", err)
	}
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d: %v", len(allow), allow)
	}
	if allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected MCP entry to remain, got %v", allow[0])
	}

	// Check local.toml does NOT contain any WebFetch entries.
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	data, err := os.ReadFile(localToml)
	if err != nil {
		t.Fatalf("failed to read local.toml: %v", err)
	}
	if strings.Contains(string(data), "WebFetch") {
		t.Error("local.toml should not contain WebFetch entries")
	}
	if strings.Contains(string(data), "example.com") {
		t.Error("local.toml should not contain WebFetch domains")
	}
}

func TestMigrateGlobalSettings(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Create global settings at $HOME/.claude/settings.local.json
	globalSettingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(globalSettingsDir, 0755)
	settings := map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(make:*)",
				"Bash(cargo:*)",
			},
		},
	}
	writeJSON(t, filepath.Join(globalSettingsDir, "settings.local.json"), settings)

	// Use a subdirectory as the project root (no project settings file).
	projectRoot := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectRoot, 0755)

	result := migrateSettingsPermissions(projectRoot)
	if len(result) != 2 {
		t.Fatalf("expected 2 commands, got %d: %v", len(result), result)
	}

	expected := []string{"cargo", "make"}
	for i, cmd := range expected {
		if result[i] != cmd {
			t.Errorf("result[%d] = %q, want %q", i, result[i], cmd)
		}
	}

	// Global settings should be stripped.
	settingsData, err := os.ReadFile(filepath.Join(globalSettingsDir, "settings.local.json"))
	if err != nil {
		t.Fatalf("failed to read global settings.local.json: %v", err)
	}
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow, _ := perms["allow"].([]interface{})
	if len(allow) != 0 {
		t.Errorf("expected 0 remaining entries in global settings, got %d: %v", len(allow), allow)
	}
}

// writeJSON is a test helper that writes a value as JSON to the given path.
func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}
