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
func (h *HarnessCommand) UnmarshalTOML(data interface{}) error {
	d, ok := data.(map[string]interface{})
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
		cfg, err := LoadConfig(fullPath)
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
	eval := NewEvaluatorSingle(cfg)
	return eval.Evaluate(info)
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
			cfg, err := LoadConfig(fullPath)
			if err != nil {
				t.Fatalf("Failed to load: %v", err)
			}
			if cfg == nil {
				t.Fatal("Config is nil")
			}
		})
	}
}
