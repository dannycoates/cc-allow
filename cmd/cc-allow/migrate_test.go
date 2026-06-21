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
				"Bash(npm:*)",
				"Bash(cargo:*)",
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

	// WebFetch domains are migrated to a [webfetch.allow] regex pattern.
	if len(result.WebFetch) != 1 || result.WebFetch[0] != `re:^https?://example\.com(/|$)` {
		t.Errorf("expected translated webfetch pattern, got %v", result.WebFetch)
	}
	localToml, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	if !strings.Contains(string(localToml), "[webfetch.allow]") {
		t.Errorf("local.toml missing [webfetch.allow]: %s", localToml)
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
	if len(editPaths) != 1 || editPaths[0] != "path:$PROJECT_ROOT/.fix-tickets/fix-tickets-*.json" {
		t.Errorf("expected anchored edit path, got %v", editPaths)
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	if !strings.Contains(content, "[edit.allow]") {
		t.Error("local.toml missing [edit.allow] section")
	}
	if !strings.Contains(content, "path:$PROJECT_ROOT/.fix-tickets/fix-tickets-*.json") {
		t.Error("local.toml missing anchored edit path")
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
paths = ["path:$PROJECT_ROOT/existing/*.md"]
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
	if !strings.Contains(content, "path:$PROJECT_ROOT/existing/*.md") || !strings.Contains(content, "path:$PROJECT_ROOT/new/*.json") {
		t.Errorf("edit paths not merged correctly: %s", content)
	}
	// The pre-existing path and the newly-migrated Edit(existing/*.md) translate to
	// the same anchored pattern and must be de-duplicated.
	if strings.Count(content, "$PROJECT_ROOT/existing/*.md") != 1 {
		t.Errorf("duplicate edit path in local.toml: %s", content)
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

// --- Translation unit tests ---

func TestTranslateBash(t *testing.T) {
	cases := []struct {
		spec     string
		wantCmd  string   // non-empty when a bare command is expected
		wantSubs []string // non-nil when a subcommand rule is expected
		wantArgs []string
		wantOK   bool
	}{
		{"git:*", "git", nil, nil, true},
		{"git push:*", "", []string{"git", "push"}, nil, true},
		{"npm run build:*", "", []string{"npm", "run", "build"}, nil, true},
		{"gh pr view:*", "", []string{"gh", "pr", "view"}, nil, true},
		{"prettier --write:*", "", []string{"prettier"}, []string{"--write"}, true},
		{"npm run build", "", []string{"npm", "run", "build"}, nil, true},
		{"for:*", "", nil, nil, false},
		{"FOO=bar cmd:*", "", nil, nil, false},
		{`echo "hi":*`, "", nil, nil, false},
	}
	for _, c := range cases {
		cmd, rule, ok := translateBash(c.spec)
		if ok != c.wantOK {
			t.Errorf("translateBash(%q) ok=%v, want %v", c.spec, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if c.wantSubs == nil {
			if rule != nil {
				t.Errorf("translateBash(%q) = rule %v, want bare command %q", c.spec, rule, c.wantCmd)
			} else if cmd != c.wantCmd {
				t.Errorf("translateBash(%q) cmd=%q, want %q", c.spec, cmd, c.wantCmd)
			}
			continue
		}
		if rule == nil {
			t.Errorf("translateBash(%q) = bare command %q, want rule subs %v", c.spec, cmd, c.wantSubs)
			continue
		}
		if strings.Join(rule.Subs, ".") != strings.Join(c.wantSubs, ".") {
			t.Errorf("translateBash(%q) subs=%v, want %v", c.spec, rule.Subs, c.wantSubs)
		}
		if strings.Join(rule.ArgsAll, " ") != strings.Join(c.wantArgs, " ") {
			t.Errorf("translateBash(%q) args=%v, want %v", c.spec, rule.ArgsAll, c.wantArgs)
		}
	}
}

func TestTranslatePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"//tmp/abs/**", "path:/tmp/abs/**"},
		{"/docs/**", "path:$PROJECT_ROOT/docs/**"},
		{"~/.config/foo/**", "path:$HOME/.config/foo/**"},
		{"~", "path:$HOME"},
		{"src/**", "path:$PROJECT_ROOT/src/**"},
		{"./lib/**", "path:$PROJECT_ROOT/lib/**"},
	}
	for _, c := range cases {
		got, ok := translatePath(c.in)
		if !ok || got != c.want {
			t.Errorf("translatePath(%q) = %q (ok=%v), want %q", c.in, got, ok, c.want)
		}
	}
}

func TestTranslateWebFetch(t *testing.T) {
	cases := []struct{ in, want string }{
		{"domain:example.com", `re:^https?://example\.com(/|$)`},
		{"domain:*.example.com", `re:^https?://([^/.]+\.)+example\.com(/|$)`},
	}
	for _, c := range cases {
		got, ok := translateWebFetch(c.in)
		if !ok || got != c.want {
			t.Errorf("translateWebFetch(%q) = %q (ok=%v), want %q", c.in, got, ok, c.want)
		}
	}
}

// TestMigrateBashSubcommandSafety verifies a subcommand upsert produces a scoped
// rule rather than collapsing to a whole-command allow.
func TestMigrateBashSubcommandSafety(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Bash(git push:*)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Commands) != 0 {
		t.Errorf("expected no bare commands (would over-broaden), got %v", result.Commands)
	}
	if len(result.Rules) != 1 || strings.Join(result.Rules[0].Subs, ".") != "git.push" {
		t.Fatalf("expected git.push rule, got %v", result.Rules)
	}

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	if !strings.Contains(content, "[[bash.allow.git.push]]") {
		t.Errorf("local.toml missing subcommand rule: %s", content)
	}
	if strings.Contains(content, "[bash.allow]") {
		t.Errorf("local.toml should not allow the whole git command: %s", content)
	}
}

// TestMigrateGlobGrepRouteToRead verifies Glob/Grep upserts migrate into read.
func TestMigrateGlobGrepRouteToRead(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	writeJSON(t, filepath.Join(settingsDir, "settings.local.json"), map[string]interface{}{
		"permissions": map[string]interface{}{
			"allow": []string{"Glob(lib/**)", "Grep(/src/**)", "MCP(server:tool)"},
		},
	})

	result := migrateSettingsPermissions(tmpDir)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	want := []string{"path:$PROJECT_ROOT/lib/**", "path:$PROJECT_ROOT/src/**"}
	if strings.Join(result.Paths["read"], "|") != strings.Join(want, "|") {
		t.Errorf("glob/grep should route to read paths %v, got %v", want, result.Paths["read"])
	}

	// Both should be stripped from settings.
	settingsData, _ := os.ReadFile(filepath.Join(settingsDir, "settings.local.json"))
	var parsed map[string]interface{}
	json.Unmarshal(settingsData, &parsed)
	allow := parsed["permissions"].(map[string]interface{})["allow"].([]interface{})
	if len(allow) != 1 || allow[0].(string) != "MCP(server:tool)" {
		t.Errorf("expected only MCP remaining, got %v", allow)
	}
}

// TestMigrateIdempotentSubcommandRules verifies a second migration preserves
// subcommand rules written by the first.
func TestMigrateIdempotentSubcommandRules(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	settingsDir := filepath.Join(tmpDir, ".claude")
	os.MkdirAll(settingsDir, 0755)
	settingsPath := filepath.Join(settingsDir, "settings.local.json")

	writeJSON(t, settingsPath, map[string]interface{}{
		"permissions": map[string]interface{}{"allow": []string{"Bash(git push:*)"}},
	})
	migrateSettingsPermissions(tmpDir)

	// A new upsert arrives later.
	writeJSON(t, settingsPath, map[string]interface{}{
		"permissions": map[string]interface{}{"allow": []string{"Bash(npm run:*)"}},
	})
	migrateSettingsPermissions(tmpDir)

	data, _ := os.ReadFile(filepath.Join(tmpDir, ".config", "cc-allow.local.toml"))
	content := string(data)
	if !strings.Contains(content, "[[bash.allow.git.push]]") {
		t.Errorf("second migration dropped the first rule: %s", content)
	}
	if !strings.Contains(content, "[[bash.allow.npm.run]]") {
		t.Errorf("second migration missing the new rule: %s", content)
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
