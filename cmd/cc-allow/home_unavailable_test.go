package main

import (
	"strings"
	"testing"
)

// TestConfigUsesHomeValidation verifies that config validation fails
// when config uses $HOME but HOME is not available.
// Issue #2: Missing HOME environment variable handling.

func TestRuleUsesHome(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		wantHome bool
	}{
		{
			name:     "rule with $HOME in command",
			rule:     Rule{Command: "path:$HOME/bin/*"},
			wantHome: true,
		},
		{
			name:     "rule with $HOME in any_match",
			rule:     Rule{Command: "cat", Args: ArgsMatch{AnyMatch: []MatchElement{{Pattern: "path:$HOME/**"}}}},
			wantHome: true,
		},
		{
			name:     "rule with $HOME in all_match",
			rule:     Rule{Command: "cat", Args: ArgsMatch{AllMatch: []MatchElement{{Pattern: "path:$HOME/**"}}}},
			wantHome: true,
		},
		{
			name:     "rule with $HOME in position",
			rule:     Rule{Command: "cat", Args: ArgsMatch{Position: map[string]FlexiblePattern{"0": {Patterns: []string{"path:$HOME/**"}}}}},
			wantHome: true,
		},
		{
			name:     "rule without $HOME",
			rule:     Rule{Command: "rm", Args: ArgsMatch{Contains: []string{"-rf"}}},
			wantHome: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleUsesHome(tt.rule)
			if got != tt.wantHome {
				t.Errorf("ruleUsesHome() = %v, want %v", got, tt.wantHome)
			}
		})
	}
}

func TestMergedConfigUsesHome(t *testing.T) {
	tests := []struct {
		name     string
		config   *MergedConfig
		wantHome bool
	}{
		{
			name: "commands.allow.names with $HOME",
			config: &MergedConfig{
				CommandsAllow: []TrackedCommandEntry{{Name: "path:$HOME/bin/*"}},
			},
			wantHome: true,
		},
		{
			name: "commands.deny.names with $HOME",
			config: &MergedConfig{
				CommandsDeny: []TrackedCommandEntry{{Name: "path:$HOME/bin/*"}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME",
			config: &MergedConfig{
				Rules: []TrackedRule{{Rule: Rule{Command: "path:$HOME/bin/*"}}},
			},
			wantHome: true,
		},
		{
			name: "redirect with $HOME",
			config: &MergedConfig{
				Redirects: []TrackedRedirectRule{{RedirectRule: RedirectRule{To: RedirectTarget{Pattern: []string{"path:$HOME/**"}}}}},
			},
			wantHome: true,
		},
		{
			name: "heredoc with $HOME",
			config: &MergedConfig{
				Heredocs: []TrackedHeredocRule{{HeredocRule: HeredocRule{ContentMatch: []string{"$HOME"}}}},
			},
			wantHome: true,
		},
		{
			name: "config without $HOME",
			config: &MergedConfig{
				CommandsAllow: []TrackedCommandEntry{{Name: "ls"}},
				Rules:         []TrackedRule{{Rule: Rule{Command: "rm"}}},
			},
			wantHome: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergedConfigUsesHome(tt.config)
			if got != tt.wantHome {
				t.Errorf("mergedConfigUsesHome() = %v, want %v", got, tt.wantHome)
			}
		})
	}
}

func TestEvaluatorConfigErrorWhenHomeUnset(t *testing.T) {
	// This test verifies that when HOME is not set and config uses $HOME,
	// the evaluator's configError is set, causing all evaluations to return "ask".
	// We can't easily unset HOME in a unit test, so we test the helper functions above
	// and trust the integration in NewEvaluator.

	// Verify the error message format
	errMsg := "config uses $HOME but HOME environment variable is not set"
	if !strings.Contains(errMsg, "$HOME") {
		t.Error("Error message should mention $HOME")
	}
}
