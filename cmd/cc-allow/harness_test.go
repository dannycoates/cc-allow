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
	Rulesets map[string]string `toml:"rulesets"`
	Commands []HarnessCommand  `toml:"command"`
	Files    []HarnessFile     `toml:"file"`
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
	Tool string `toml:"tool"` // Read, Write, or Edit
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
			h.Tool = strVal
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
				if result.Action != expectedAction {
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
				if result.Action != expectedAction {
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
}

func evalBash(t *testing.T, cfg *Config, bash string) Result {
	t.Helper()

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(bash), "test")
	if err != nil {
		// Return the parse error result
		return Result{
			Action:  "deny",
			Message: fmt.Sprintf("Parse error: %v", err),
		}
	}

	info := ExtractFromFile(f)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

func evalFile(t *testing.T, cfg *Config, tool, path string) Result {
	t.Helper()
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	return evaluateFileTool(chain, tool, path)
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
