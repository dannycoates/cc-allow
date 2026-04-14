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
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	if _, err := os.Stat(localToml); !os.IsNotExist(err) {
		t.Errorf("cc-allow.local.toml should not exist")
	}
}

func TestMigrateNoBashEntries(t *testing.T) {
	tmpDir := t.TempDir()
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)

	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"MCP(server:tool)", "WebSearch"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
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

	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)",
				"Bash(npm run:*)",
				"Bash(cargo build:*)",
				"MCP(server:tool)",
			},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Commands) != 3 {
		t.Fatalf("expected 3 commands, got %d: %v", len(result.Commands), result.Commands)
	}

	expected := []string{"cargo", "git", "npm"}
	for i, cmd := range expected {
		if result.Commands[i] != cmd {
			t.Errorf("result.Commands[%d] = %q, want %q", i, result.Commands[i], cmd)
		}
	}

	// Check local.toml was created.
	localToml := filepath.Join(tmpDir, ".config", "cc-allow.local.toml")
	data, err := os.ReadFile(localToml)
	if err != nil {
		t.Fatalf("failed to read local.toml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `"cargo"`) || !strings.Contains(content, `"git"`) || !strings.Contains(content, `"npm"`) {
		t.Errorf("local.toml missing expected commands: %s", content)
	}

	// Check settings.local.json was stripped of Bash entries but kept MCP.
	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 1 || allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected only MCP entry, got %v", allow)
	}
}

func TestMigrateMergeExistingLocalToml(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	configDir := filepath.Join(tmpDir, ".config")
	os.MkdirAll(configDir, 0755)
	os.WriteFile(filepath.Join(configDir, "cc-allow.local.toml"), []byte(`version = "2.0"
[bash.allow]
commands = ["make", "git"]
`), 0644)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(git:*)", "Bash(cargo:*)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if len(result.Commands) != 2 {
		t.Fatalf("expected 2 migrated commands, got %d: %v", len(result.Commands), result.Commands)
	}

	data, _ := os.ReadFile(filepath.Join(configDir, "cc-allow.local.toml"))
	content := string(data)
	for _, cmd := range []string{"cargo", "git", "make"} {
		if !strings.Contains(content, `"`+cmd+`"`) {
			t.Errorf("local.toml missing %s", cmd)
		}
	}
}

func TestMigrateFiltersShellConstructs(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(do)", "Bash(done)", "Bash(for:*)", "Bash(while:*)",
				"Bash(if:*)", "Bash(then)", "Bash(fi)", "Bash(git:*)",
			},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if len(result.Commands) != 1 || result.Commands[0] != "git" {
		t.Errorf("expected [git], got %v", result.Commands)
	}
}

func TestMigrateFiltersEnvVarAssignments(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(FOO=bar cmd:*)", "Bash(git:*)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if len(result.Commands) != 1 || result.Commands[0] != "git" {
		t.Errorf("expected [git], got %v", result.Commands)
	}
}

func TestMigratePreservesNonBashEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(git:*)", "MCP(server:tool)", "WebSearch", "Skills(skill:name)"},
		},
		"other_field": "preserved",
	})

	migrateSettingsPermissions(tmpDir)

	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)

	if parsed["other_field"] != "preserved" {
		t.Error("other_field was not preserved")
	}
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 3 {
		t.Fatalf("expected 3 remaining entries, got %d: %v", len(allow), allow)
	}
}

func TestMigrateStripsWebFetchEntries(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(git:*)", "WebFetch(domain:example.com)", "MCP(server:tool)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if len(result.Commands) != 1 || result.Commands[0] != "git" {
		t.Errorf("expected [git], got %v", result.Commands)
	}

	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 1 || allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected only MCP, got %v", allow)
	}

	localToml, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	if strings.Contains(string(localToml), "WebFetch") || strings.Contains(string(localToml), "example.com") {
		t.Error("local.toml should not contain WebFetch entries")
	}
}

func TestMigrateGlobalSettings(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	globalSettingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(globalSettingsDir, 0755)
	writeJSON(t, filepath.Join(globalSettingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(make:*)", "Bash(cargo:*)"},
		},
	})

	projectRoot := filepath.Join(tmpDir, "project")
	os.MkdirAll(projectRoot, 0755)

	result := migrateSettingsPermissions(projectRoot)
	if len(result.Commands) != 2 {
		t.Fatalf("expected 2 commands, got %d: %v", len(result.Commands), result.Commands)
	}

	settingsData, _ := os.ReadFile(filepath.Join(globalSettingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow, _ := perms["allow"].([]interface{})
	if len(allow) != 0 {
		t.Errorf("expected 0 remaining entries, got %d: %v", len(allow), allow)
	}
}

// --- File tool migration tests ---

func TestMigrateFileToolPaths(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Edit(.fix-tickets/fix-tickets-*.json)", "MCP(server:tool)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Commands) != 0 {
		t.Errorf("expected 0 commands, got %v", result.Commands)
	}
	editPaths := result.Paths["edit"]
	if len(editPaths) != 1 || editPaths[0] != "path:.fix-tickets/fix-tickets-*.json" {
		t.Errorf("expected edit path, got %v", editPaths)
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	if !strings.Contains(content, "[edit.allow]") {
		t.Error("local.toml missing [edit.allow] section")
	}
	if !strings.Contains(content, "path:.fix-tickets/fix-tickets-*.json") {
		t.Error("local.toml missing edit path")
	}
	if strings.Contains(content, "[bash.allow]") {
		t.Error("local.toml should not have [bash.allow] with no commands")
	}
}

func TestMigrateMultipleFileTools(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Edit(.fix-tickets/*.json)",
				"Read(//tmp/test/**)",
				"Write(/tmp/output.txt)",
				"Read(/var/log/app.log)",
			},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Paths["edit"]) != 1 {
		t.Errorf("expected 1 edit path, got %v", result.Paths["edit"])
	}
	if len(result.Paths["read"]) != 2 {
		t.Errorf("expected 2 read paths, got %v", result.Paths["read"])
	}
	if len(result.Paths["write"]) != 1 {
		t.Errorf("expected 1 write path, got %v", result.Paths["write"])
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	for _, section := range []string{"[edit.allow]", "[read.allow]", "[write.allow]"} {
		if !strings.Contains(content, section) {
			t.Errorf("local.toml missing %s", section)
		}
	}
}

func TestMigrateBareToolNamesSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Edit", "Read", "Write", "Edit(.special/*.md)", "MCP(server:tool)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Paths["edit"]) != 1 {
		t.Errorf("expected 1 edit path, got %v", result.Paths["edit"])
	}
	if len(result.Paths["read"]) != 0 {
		t.Errorf("expected 0 read paths, got %v", result.Paths["read"])
	}

	// Bare names should remain in settings.
	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	// Edit, Read, Write, MCP — 4 entries (bare names + MCP kept, path-scoped Edit stripped)
	if len(allow) != 4 {
		t.Errorf("expected 4 remaining entries, got %d: %v", len(allow), allow)
	}
}

func TestMigrateMergeExistingFilePaths(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	configDir := filepath.Join(tmpDir, ".config")
	os.MkdirAll(configDir, 0755)
	os.WriteFile(filepath.Join(configDir, "cc-allow.local.toml"), []byte(`version = "2.0"

[bash.allow]
commands = ["git"]

[edit.allow]
paths = ["path:existing/*.md"]
`), 0644)

	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Edit(new/*.json)", "Edit(existing/*.md)", "Bash(cargo:*)"},
		},
	})

	migrateSettingsPermissions(tmpDir)

	data, _ := os.ReadFile(filepath.Join(configDir, "cc-allow.local.toml"))
	content := string(data)

	if !strings.Contains(content, `"cargo"`) || !strings.Contains(content, `"git"`) {
		t.Errorf("commands not merged correctly: %s", content)
	}
	if !strings.Contains(content, "path:existing/*.md") || !strings.Contains(content, "path:new/*.json") {
		t.Errorf("edit paths not merged correctly: %s", content)
	}
	if strings.Count(content, "existing/*.md") != 1 {
		t.Error("duplicate edit path in local.toml")
	}
}

func TestMigrateCombinedBashAndFileTools(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{
				"Bash(git:*)", "Edit(.tickets/*.json)", "Read(//tmp/**)",
				"WebFetch(domain:example.com)", "MCP(server:tool)",
			},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Commands) != 1 || result.Commands[0] != "git" {
		t.Errorf("expected [git], got %v", result.Commands)
	}
	if len(result.Paths["edit"]) != 1 {
		t.Errorf("expected 1 edit path, got %v", result.Paths["edit"])
	}
	if len(result.Paths["read"]) != 1 {
		t.Errorf("expected 1 read path, got %v", result.Paths["read"])
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	if !strings.Contains(content, "[bash.allow]") {
		t.Error("local.toml missing [bash.allow]")
	}
	if !strings.Contains(content, "[edit.allow]") {
		t.Error("local.toml missing [edit.allow]")
	}
	if !strings.Contains(content, "[read.allow]") {
		t.Error("local.toml missing [read.allow]")
	}
	if strings.Contains(content, "[write.allow]") {
		t.Error("local.toml should not have [write.allow]")
	}

	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	perms := parsed["permissions"].(map[string]interface{})
	allow := perms["allow"].([]interface{})
	if len(allow) != 1 || allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected only MCP, got %v", allow)
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
