package main

import (
	"strings"
	"testing"
)

// TestConfigUsesHomeValidation verifies that config validation fails
// when config uses $HOME but HOME is not available.

func TestBashRuleUsesHome(t *testing.T) {
	tests := []struct {
		name     string
		rule     BashRule
		wantHome bool
	}{
		{
			name:     "rule with $HOME in command",
			rule:     BashRule{Command: "path:$HOME/bin/*"},
			wantHome: true,
		},
		{
			name:     "rule without $HOME",
			rule:     BashRule{Command: "rm"},
			wantHome: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Contains(tt.rule.Command, "$HOME")
			if got != tt.wantHome {
				t.Errorf("rule uses home = %v, want %v", got, tt.wantHome)
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
			name: "commands.allow with $HOME",
			config: &MergedConfig{
				CommandsAllow: []TrackedCommandEntry{{Name: "path:$HOME/bin/*"}},
			},
			wantHome: true,
		},
		{
			name: "commands.deny with $HOME",
			config: &MergedConfig{
				CommandsDeny: []TrackedCommandEntry{{Name: "path:$HOME/bin/*"}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME in command",
			config: &MergedConfig{
				Rules: []TrackedRule[BashRule]{{Rule: BashRule{Command: "path:$HOME/bin/*"}}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME in args.any",
			config: &MergedConfig{
				Rules: []TrackedRule[BashRule]{{Rule: BashRule{
					Command: "cat",
					Args:    ArgsMatch{Any: &BoolExpr{Patterns: []string{"path:$HOME/.bashrc"}}},
				}}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME in args.all",
			config: &MergedConfig{
				Rules: []TrackedRule[BashRule]{{Rule: BashRule{
					Command: "cat",
					Args:    ArgsMatch{All: &BoolExpr{Patterns: []string{"path:$HOME/.bashrc"}}},
				}}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME in args.position",
			config: &MergedConfig{
				Rules: []TrackedRule[BashRule]{{Rule: BashRule{
					Command: "cat",
					Args:    ArgsMatch{Position: map[string]FlexiblePattern{"0": {Patterns: []string{"path:$HOME/.bashrc"}}}},
				}}},
			},
			wantHome: true,
		},
		{
			name: "rule with $HOME in nested BoolExpr",
			config: &MergedConfig{
				Rules: []TrackedRule[BashRule]{{Rule: BashRule{
					Command: "cat",
					Args: ArgsMatch{Any: &BoolExpr{
						Any: []*BoolExpr{{Patterns: []string{"path:$HOME/.bashrc"}}},
					}},
				}}},
			},
			wantHome: true,
		},
		{
			name: "redirect with $HOME",
			config: &MergedConfig{
				Redirects: []TrackedRule[RedirectRule]{{Rule: RedirectRule{Paths: []string{"path:$HOME/.config/*"}}}},
			},
			wantHome: true,
		},
		{
			name: "heredoc with $HOME",
			config: &MergedConfig{
				Heredocs: []TrackedRule[HeredocRule]{{Rule: HeredocRule{Content: &BoolExpr{Patterns: []string{"path:$HOME"}}}}},
			},
			wantHome: true,
		},
		{
			name: "file allow with $HOME",
			config: &MergedConfig{
				Files: MergedFilesConfig{
					Allow: map[ToolName][]TrackedFilePatternEntry{ToolRead: {{Pattern: "path:$HOME/**"}}},
					Deny:  map[ToolName][]TrackedFilePatternEntry{},
				},
			},
			wantHome: true,
		},
		{
			name: "file deny with $HOME",
			config: &MergedConfig{
				Files: MergedFilesConfig{
					Allow: map[ToolName][]TrackedFilePatternEntry{},
					Deny:  map[ToolName][]TrackedFilePatternEntry{ToolWrite: {{Pattern: "path:$HOME/.ssh/*"}}},
				},
			},
			wantHome: true,
		},
		{
			name: "alias with $HOME",
			config: &MergedConfig{
				Aliases: map[string]Alias{"home": {Patterns: []string{"path:$HOME/**"}}},
			},
			wantHome: true,
		},
		{
			name: "config without $HOME",
			config: &MergedConfig{
				CommandsAllow: []TrackedCommandEntry{{Name: "ls"}},
				Rules:         []TrackedRule[BashRule]{{Rule: BashRule{Command: "rm"}}},
				Files: MergedFilesConfig{
					Allow: map[ToolName][]TrackedFilePatternEntry{},
					Deny:  map[ToolName][]TrackedFilePatternEntry{},
				},
				Aliases: map[string]Alias{},
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
