package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"mvdan.cc/sh/v3/syntax"
)

// HarnessConfig represents the test harness configuration
type HarnessConfig struct {
	Rulesets  map[string]string  `toml:"rulesets"`
	Commands  []HarnessCommand   `toml:"command"`
	Files     []HarnessFile      `toml:"file"`
	WebFetch  []HarnessWebFetch  `toml:"webfetch"`
}

// HarnessCommand represents a single test command with expected results per ruleset
type HarnessCommand struct {
	Name string `toml:"name"`
	Bash string `toml:"bash"`
	File string `toml:"file"` // Alternative: load bash from file (relative to testdata/)
	// Expected results are stored as a map, populated dynamically from TOML fields
	Expected map[string]string `toml:"-"`
}

// UnmarshalTOML implements custom unmarshaling to capture ruleset expectations
func (h *HarnessCommand) UnmarshalTOML(data any) error {
	d, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map, got %T", data)
	}

	h.Expected = make(map[string]string)

	for key, val := range d {
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		switch key {
		case "name":
			h.Name = strVal
		case "bash":
			h.Bash = strVal
		case "file":
			h.File = strVal
		default:
			// Assume any other string field is a ruleset expectation
			h.Expected[key] = strVal
		}
	}

	return nil
}

// GetBash returns the bash content, loading from file if necessary
func (h *HarnessCommand) GetBash(testdataDir string) (string, error) {
	// If file is specified, load from file
	if h.File != "" {
		path := filepath.Join(testdataDir, h.File)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to read script file %s: %w", h.File, err)
		}
		return string(data), nil
	}
	// Otherwise use inline bash (even if empty)
	return h.Bash, nil
}

// HarnessFile represents a single file tool test with expected results per ruleset
type HarnessFile struct {
	Name string `toml:"name"`
	Tool ToolName `toml:"tool"` // Read, Write, or Edit
	Path string `toml:"path"` // file path to test
	// Expected results are stored as a map, populated dynamically from TOML fields
	Expected map[string]string `toml:"-"`
	// Expected messages per ruleset (optional), keyed as "<ruleset>_message"
	ExpectedMessage map[string]string `toml:"-"`
}

// UnmarshalTOML implements custom unmarshaling to capture ruleset expectations
func (h *HarnessFile) UnmarshalTOML(data any) error {
	d, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map, got %T", data)
	}

	h.Expected = make(map[string]string)
	h.ExpectedMessage = make(map[string]string)

	for key, val := range d {
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		switch key {
		case "name":
			h.Name = strVal
		case "tool":
			h.Tool = ToolName(strVal)
		case "path":
			h.Path = strVal
		default:
			// Check if this is a message expectation (e.g., "files_message")
			if strings.HasSuffix(key, "_message") {
				rulesetName := strings.TrimSuffix(key, "_message")
				h.ExpectedMessage[rulesetName] = strVal
			} else {
				// Assume any other string field is a ruleset expectation
				h.Expected[key] = strVal
			}
		}
	}

	return nil
}

// HarnessWebFetch represents a WebFetch URL test with expected results per ruleset
type HarnessWebFetch struct {
	Name string `toml:"name"`
	URL  string `toml:"url"`
	// Expected results are stored as a map, populated dynamically from TOML fields
	Expected map[string]string `toml:"-"`
	// Expected messages per ruleset (optional), keyed as "<ruleset>_message"
	ExpectedMessage map[string]string `toml:"-"`
}

// UnmarshalTOML implements custom unmarshaling to capture ruleset expectations
func (h *HarnessWebFetch) UnmarshalTOML(data any) error {
	d, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map, got %T", data)
	}

	h.Expected = make(map[string]string)
	h.ExpectedMessage = make(map[string]string)

	for key, val := range d {
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		switch key {
		case "name":
			h.Name = strVal
		case "url":
			h.URL = strVal
		default:
			if strings.HasSuffix(key, "_message") {
				rulesetName := strings.TrimSuffix(key, "_message")
				h.ExpectedMessage[rulesetName] = strVal
			} else {
				h.Expected[key] = strVal
			}
		}
	}

	return nil
}

func TestHarness(t *testing.T) {
	// Load harness config
	harnessPath := filepath.Join("testdata", "harness.toml")
	data, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("Failed to read harness.toml: %v", err)
	}

	var harness HarnessConfig
	if _, err := toml.Decode(string(data), &harness); err != nil {
		t.Fatalf("Failed to parse harness.toml: %v", err)
	}

	// Load all rulesets
	rulesets := make(map[string]*Config)
	for name, path := range harness.Rulesets {
		fullPath := filepath.Join("testdata", path)
		cfg, err := LoadConfigWithDefaults(fullPath)
		if err != nil {
			t.Fatalf("Failed to load ruleset %q from %s: %v", name, fullPath, err)
		}
		rulesets[name] = cfg
	}

	// Run each command against each ruleset
	for _, cmd := range harness.Commands {
		// Load bash content (inline or from file)
		bash, err := cmd.GetBash("testdata")
		if err != nil {
			t.Errorf("Command %q: %v", cmd.Name, err)
			continue
		}

		for rulesetName, expectedAction := range cmd.Expected {
			cfg, ok := rulesets[rulesetName]
			if !ok {
				t.Errorf("Command %q references unknown ruleset %q", cmd.Name, rulesetName)
				continue
			}

			testName := fmt.Sprintf("%s/%s", rulesetName, cmd.Name)
			t.Run(testName, func(t *testing.T) {
				result := evalBash(t, cfg, bash)
				if result.Action != Action(expectedAction) {
					// Truncate long bash strings in error output
					displayBash := bash
					if len(displayBash) > 100 {
						displayBash = displayBash[:100] + "..."
					}
					t.Errorf("bash=%q\nexpected %s, got %s", displayBash, expectedAction, result.Action)
					if result.Message != "" {
						t.Logf("message: %s", result.Message)
					}
				}
			})
		}
	}

	// For webfetch_sb ruleset, inject the API key from the real config chain
	if sbCfg, ok := rulesets["webfetch_sb"]; ok {
		apiKey := loadHarnessAPIKey(t)
		if apiKey != "" {
			sbCfg.WebFetch.SafeBrowsing.APIKey = apiKey
		}
	}

	// Run each file test against each ruleset
	for _, file := range harness.Files {
		for rulesetName, expectedAction := range file.Expected {
			cfg, ok := rulesets[rulesetName]
			if !ok {
				t.Errorf("File %q references unknown ruleset %q", file.Name, rulesetName)
				continue
			}

			testName := fmt.Sprintf("%s/%s", rulesetName, file.Name)
			t.Run(testName, func(t *testing.T) {
				result := evalFile(t, cfg, file.Tool, file.Path)
				if result.Action != Action(expectedAction) {
					t.Errorf("tool=%s path=%q\nexpected %s, got %s (source: %s)",
						file.Tool, file.Path, expectedAction, result.Action, result.Source)
					if result.Message != "" {
						t.Logf("message: %s", result.Message)
					}
				}
				// Check expected message if specified
				if expectedMsg, ok := file.ExpectedMessage[rulesetName]; ok {
					if result.Message != expectedMsg {
						t.Errorf("tool=%s path=%q\nexpected message %q, got %q",
							file.Tool, file.Path, expectedMsg, result.Message)
					}
				}
			})
		}
	}

	// Run each webfetch test against each ruleset
	for _, wf := range harness.WebFetch {
		for rulesetName, expectedAction := range wf.Expected {
			cfg, ok := rulesets[rulesetName]
			if !ok {
				t.Errorf("WebFetch %q references unknown ruleset %q", wf.Name, rulesetName)
				continue
			}

			// Skip webfetch_sb tests if no API key is available
			if rulesetName == "webfetch_sb" && cfg.WebFetch.SafeBrowsing.APIKey == "" {
				continue
			}

			testName := fmt.Sprintf("%s/%s", rulesetName, wf.Name)
			t.Run(testName, func(t *testing.T) {
				result := evalWebFetch(t, cfg, wf.URL)
				if result.Action != Action(expectedAction) {
					t.Errorf("url=%q\nexpected %s, got %s (source: %s)",
						wf.URL, expectedAction, result.Action, result.Source)
					if result.Message != "" {
						t.Logf("message: %s", result.Message)
					}
				}
				if expectedMsg, ok := wf.ExpectedMessage[rulesetName]; ok {
					if result.Message != expectedMsg {
						t.Errorf("url=%q\nexpected message %q, got %q",
							wf.URL, expectedMsg, result.Message)
					}
				}
			})
		}
	}
}

func evalBash(t *testing.T, cfg *Config, bash string) Result {
	t.Helper()

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(bash), "test")
	if err != nil {
		// Return the parse error result
		return Result{
			Action:  ActionDeny,
			Message: fmt.Sprintf("Parse error: %v", err),
		}
	}

	cwd, _ := os.Getwd()
	info := ExtractFromFile(f, cwd)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

func evalFile(t *testing.T, cfg *Config, tool ToolName, path string) Result {
	t.Helper()
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)
	switch tool {
	case ToolGlob, ToolGrep:
		return eval.evaluateSearchTool(tool, path)
	default:
		return eval.evaluateFileTool(tool, path)
	}
}

func evalWebFetch(t *testing.T, cfg *Config, url string) Result {
	t.Helper()
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	return NewEvaluator(chain).evaluateWebFetchTool(url)
}

// loadHarnessAPIKey walks up from the test directory to find the project config
// and extract the Safe Browsing API key.
func loadHarnessAPIKey(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		configPath := filepath.Join(dir, ".config", "cc-allow.toml")
		if _, err := os.Stat(configPath); err == nil {
			cfg, err := LoadConfigWithDefaults(configPath)
			if err != nil {
				return ""
			}
			return cfg.WebFetch.SafeBrowsing.APIKey
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// evalBashChain evaluates a bash command against a config chain (multiple configs merged).
func evalBashChain(t *testing.T, configs []*Config, bash string) Result {
	t.Helper()

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(bash), "test")
	if err != nil {
		return Result{
			Action:  ActionDeny,
			Message: fmt.Sprintf("Parse error: %v", err),
		}
	}

	cwd, _ := os.Getwd()
	info := ExtractFromFile(f, cwd)
	chain := &ConfigChain{Configs: configs, Merged: MergeConfigs(configs)}
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

// evalFileChain evaluates a file tool request against a config chain.
func evalFileChain(t *testing.T, configs []*Config, tool ToolName, path string) Result {
	t.Helper()
	chain := &ConfigChain{Configs: configs, Merged: MergeConfigs(configs)}
	eval := NewEvaluator(chain)
	switch tool {
	case ToolGlob, ToolGrep:
		return eval.evaluateSearchTool(tool, path)
	default:
		return eval.evaluateFileTool(tool, path)
	}
}

// TestSessionHarness tests session config overlay behavior.
// A session config is merged on top of a base project config.
// This verifies that session rules properly extend/override the base.
func TestSessionHarness(t *testing.T) {
	// Load base and session configs
	basePath := filepath.Join("testdata", "rulesets", "session_base.toml")
	sessionPath := filepath.Join("testdata", "rulesets", "session_overlay.toml")

	baseCfg, err := LoadConfigWithDefaults(basePath)
	if err != nil {
		t.Fatalf("Failed to load session_base.toml: %v", err)
	}
	sessionCfg, err := LoadConfigWithDefaults(sessionPath)
	if err != nil {
		t.Fatalf("Failed to load session_overlay.toml: %v", err)
	}

	// Test with base config only (no session)
	baseOnly := []*Config{baseCfg}
	// Test with base + session overlay
	withSession := []*Config{baseCfg, sessionCfg}

	// =========================================================================
	// Bash command tests
	// =========================================================================
	bashTests := []struct {
		name           string
		bash           string
		baseExpected   Action
		mergedExpected Action
	}{
		// Commands allowed by base stay allowed with session
		{
			name:           "ls stays allowed",
			bash:           "ls -la",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},
		{
			name:           "echo stays allowed",
			bash:           "echo hello",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},
		{
			name:           "git stays allowed",
			bash:           "git status",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},

		// Commands denied by base stay denied (deny always wins across configs)
		{
			name:           "sudo stays denied",
			bash:           "sudo rm -rf /",
			baseExpected:   ActionDeny,
			mergedExpected: ActionDeny,
		},
		{
			name:           "rm stays denied",
			bash:           "rm file.txt",
			baseExpected:   ActionDeny,
			mergedExpected: ActionDeny,
		},

		// Docker: ask by base (not in any list), session adds to allow commands
		{
			name:           "docker ask by base, allowed by session",
			bash:           "docker run hello-world",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAllow,
		},
		{
			name:           "docker ps ask by base, allowed by session",
			bash:           "docker ps",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAllow,
		},
		{
			name:           "docker compose ask by base, allowed by session",
			bash:           "docker compose up -d",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAllow,
		},

		// curl: ask by base, session adds to allow commands
		{
			name:           "curl ask by base, allowed by session",
			bash:           "curl https://example.com",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAllow,
		},

		// npm install: explicit ask rule in base cannot be overridden by session allow
		// (ask > allow at equal specificity - this is a security invariant)
		{
			name:           "npm install ask stays ask (explicit ask beats session allow)",
			bash:           "npm install lodash",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAsk,
		},
		{
			name:           "npm i ask stays ask (explicit ask beats session allow)",
			bash:           "npm i express",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAsk,
		},
		{
			name:           "npm ci ask stays ask (explicit ask beats session allow)",
			bash:           "npm ci",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAsk,
		},

		// npm non-install: allowed by base (base allow rule), stays allowed
		{
			name:           "npm list stays allowed",
			bash:           "npm list",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},
		{
			name:           "npm test stays allowed",
			bash:           "npm test",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},

		// Commands not in any list remain ask
		{
			name:           "unknown command stays ask",
			bash:           "unknown-command arg",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAsk,
		},

		// Dynamic commands stay denied (policy-level, session doesn't override)
		{
			name:           "dynamic command stays denied",
			bash:           "$CMD arg1",
			baseExpected:   ActionDeny,
			mergedExpected: ActionDeny,
		},
	}

	for _, tt := range bashTests {
		t.Run("base/"+tt.name, func(t *testing.T) {
			result := evalBashChain(t, baseOnly, tt.bash)
			if result.Action != tt.baseExpected {
				t.Errorf("bash=%q\nbase expected %s, got %s", tt.bash, tt.baseExpected, result.Action)
				if result.Message != "" {
					t.Logf("message: %s", result.Message)
				}
			}
		})
		t.Run("session/"+tt.name, func(t *testing.T) {
			result := evalBashChain(t, withSession, tt.bash)
			if result.Action != tt.mergedExpected {
				t.Errorf("bash=%q\nsession expected %s, got %s", tt.bash, tt.mergedExpected, result.Action)
				if result.Message != "" {
					t.Logf("message: %s", result.Message)
				}
			}
		})
	}

	// =========================================================================
	// File tool tests
	// =========================================================================
	fileTests := []struct {
		name           string
		tool           ToolName
		path           string
		baseExpected   Action
		mergedExpected Action
	}{
		// /project/** allowed by base, stays allowed
		{
			name:           "read project file stays allowed",
			tool:           ToolRead,
			path:           "/project/src/main.go",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},
		// /secrets/** denied by base, stays denied
		{
			name:           "read /secrets stays denied",
			tool:           ToolRead,
			path:           "/secrets/api-key.txt",
			baseExpected:   ActionDeny,
			mergedExpected: ActionDeny,
		},
		// /home/user/**: ask by base, session adds to allow paths
		{
			name:           "read /home/user ask by base, allowed by session",
			tool:           ToolRead,
			path:           "/home/user/docs/notes.txt",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAllow,
		},
		// Write to /etc stays denied (session doesn't touch write rules)
		{
			name:           "write /etc stays denied",
			tool:           ToolWrite,
			path:           "/etc/hosts",
			baseExpected:   ActionDeny,
			mergedExpected: ActionDeny,
		},
		// Write to /project allowed by base, stays allowed
		{
			name:           "write project stays allowed",
			tool:           ToolWrite,
			path:           "/project/output.txt",
			baseExpected:   ActionAllow,
			mergedExpected: ActionAllow,
		},
		// Write to random path stays ask (no session override for write)
		{
			name:           "write random path stays ask",
			tool:           ToolWrite,
			path:           "/var/data/output.csv",
			baseExpected:   ActionAsk,
			mergedExpected: ActionAsk,
		},
	}

	for _, tt := range fileTests {
		t.Run("base/"+tt.name, func(t *testing.T) {
			result := evalFileChain(t, baseOnly, tt.tool, tt.path)
			if result.Action != tt.baseExpected {
				t.Errorf("tool=%s path=%q\nbase expected %s, got %s (source: %s)", tt.tool, tt.path, tt.baseExpected, result.Action, result.Source)
			}
		})
		t.Run("session/"+tt.name, func(t *testing.T) {
			result := evalFileChain(t, withSession, tt.tool, tt.path)
			if result.Action != tt.mergedExpected {
				t.Errorf("tool=%s path=%q\nsession expected %s, got %s (source: %s)", tt.tool, tt.path, tt.mergedExpected, result.Action, result.Source)
			}
		})
	}

	// =========================================================================
	// Settings merge test - session overrides base value
	// =========================================================================
	t.Run("settings/session_max_age overridden by session", func(t *testing.T) {
		merged := MergeConfigs(withSession)
		if merged.Settings.SessionMaxAge != "3d" {
			t.Errorf("SessionMaxAge = %q, want %q (session should override base)", merged.Settings.SessionMaxAge, "3d")
		}
	})
	t.Run("settings/session_max_age from base only", func(t *testing.T) {
		merged := MergeConfigs(baseOnly)
		if merged.Settings.SessionMaxAge != "7d" {
			t.Errorf("SessionMaxAge = %q, want %q", merged.Settings.SessionMaxAge, "7d")
		}
	})
}

// TestHarnessRulesetLoading verifies all rulesets can be loaded
func TestHarnessRulesetLoading(t *testing.T) {
	harnessPath := filepath.Join("testdata", "harness.toml")
	data, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("Failed to read harness.toml: %v", err)
	}

	var harness HarnessConfig
	if _, err := toml.Decode(string(data), &harness); err != nil {
		t.Fatalf("Failed to parse harness.toml: %v", err)
	}

	for name, path := range harness.Rulesets {
		fullPath := filepath.Join("testdata", path)
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadConfigWithDefaults(fullPath)
			if err != nil {
				t.Fatalf("Failed to load: %v", err)
			}
			if cfg == nil {
				t.Fatal("Config is nil")
			}
		})
	}
}
