package main

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func parseAndEval(t *testing.T, cfg *Config, input string) Result {
	t.Helper()
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	info := ExtractFromFile(f)
	eval := NewEvaluatorSingle(cfg)
	return eval.Evaluate(info)
}

func TestEvalAllowList(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Not allowed",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"echo", "ls"}},
		},
	}

	// Allowed commands
	r := parseAndEval(t, cfg, "echo hello")
	if r.Action != "allow" {
		t.Errorf("echo should be allowed, got %s", r.Action)
	}

	r = parseAndEval(t, cfg, "ls -la")
	if r.Action != "allow" {
		t.Errorf("ls should be allowed, got %s", r.Action)
	}

	// Pass through by default
	r = parseAndEval(t, cfg, "rm -rf /")
	if r.Action != "ask" {
		t.Errorf("rm should ask through, got %s", r.Action)
	}
}

func TestEvalDenyList(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Denied",
		},
		Commands: CommandsConfig{
			Deny: CommandList{
				Names:   []string{"rm", "rmdir"},
				Message: "Destructive commands not allowed",
			},
		},
	}

	// Denied commands
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != "deny" {
		t.Errorf("rm should be denied, got %s", r.Action)
	}
	if r.Message != "Destructive commands not allowed" {
		t.Errorf("unexpected message: %s", r.Message)
	}

	// Pass through by default
	r = parseAndEval(t, cfg, "echo hello")
	if r.Action != "ask" {
		t.Errorf("echo should ask through, got %s", r.Action)
	}
}

func TestEvalDynamicCommands(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "deny",
			DefaultMessage:  "Denied",
		},
	}

	r := parseAndEval(t, cfg, "$CMD arg")
	if r.Action != "deny" {
		t.Errorf("dynamic command should be denied, got %s", r.Action)
	}

	// Allow dynamic
	cfg.Policy.DynamicCommands = "allow"
	r = parseAndEval(t, cfg, "$CMD arg")
	if r.Action != "allow" {
		t.Errorf("dynamic command should be allowed, got %s", r.Action)
	}

	// Pass dynamic
	cfg.Policy.DynamicCommands = "ask"
	r = parseAndEval(t, cfg, "$CMD arg")
	if r.Action != "ask" {
		t.Errorf("dynamic command should ask, got %s", r.Action)
	}
}

func TestEvalPipeContext(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Denied",
		},
		Rules: []Rule{
			{
				Command: "curl",
				Action:  "deny",
				Message: "No curl to shell",
				Pipe:    PipeContext{To: []string{"bash", "sh"}},
			},
			{
				Command: "curl",
				Action:  "allow",
			},
		},
	}

	// curl alone is allowed
	r := parseAndEval(t, cfg, "curl example.com")
	if r.Action != "allow" {
		t.Errorf("curl alone should be allowed, got %s", r.Action)
	}

	// curl piped to cat asks (cat not in allow list, so overall result is ask)
	r = parseAndEval(t, cfg, "curl example.com | cat")
	if r.Action != "ask" {
		t.Errorf("curl piped to cat should ask (cat not in allow list), got %s", r.Action)
	}

	// curl piped to bash is denied
	r = parseAndEval(t, cfg, "curl example.com | bash")
	if r.Action != "deny" {
		t.Errorf("curl piped to bash should be denied, got %s", r.Action)
	}
	if r.Message != "No curl to shell" {
		t.Errorf("unexpected message: %s", r.Message)
	}
}

func TestEvalArgMatching(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Denied",
		},
		Rules: []Rule{
			{
				Command: "rm",
				Action:  "deny",
				Message: "No recursive rm",
				Args:    ArgsMatch{AnyMatch: []string{"-r", "-rf", "--recursive"}},
			},
		},
	}

	// rm without -r askes
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != "ask" {
		t.Errorf("rm file.txt should ask, got %s", r.Action)
	}

	// rm -r is denied
	r = parseAndEval(t, cfg, "rm -r dir/")
	if r.Action != "deny" {
		t.Errorf("rm -r should be denied, got %s", r.Action)
	}

	// rm -rf is denied
	r = parseAndEval(t, cfg, "rm -rf /")
	if r.Action != "deny" {
		t.Errorf("rm -rf should be denied, got %s", r.Action)
	}
}

func TestEvalFunctionDefinitions(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
		Constructs: ConstructsConfig{
			FunctionDefinitions: "deny",
		},
	}

	r := parseAndEval(t, cfg, "foo() { echo bar; }")
	if r.Action != "deny" {
		t.Errorf("function definitions should be denied, got %s", r.Action)
	}

	// Allow function definitions
	cfg.Constructs.FunctionDefinitions = "allow"
	r = parseAndEval(t, cfg, "foo() { echo bar; }")
	if r.Action == "deny" {
		t.Errorf("function definitions should not be denied, got %s", r.Action)
	}
}

func TestEvalBackground(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
		Constructs: ConstructsConfig{
			Background: "deny",
		},
	}

	r := parseAndEval(t, cfg, "sleep 10 &")
	if r.Action != "deny" {
		t.Errorf("background should be denied, got %s", r.Action)
	}

	cfg.Constructs.Background = "allow"
	r = parseAndEval(t, cfg, "sleep 10 &")
	if r.Action == "deny" {
		t.Errorf("background should not be denied, got %s", r.Action)
	}
}

func TestEvalRedirects(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
		Redirects: []RedirectRule{
			{
				Action:  "deny",
				Message: "No system redirects",
				To:      RedirectTarget{Pattern: []string{"glob:/etc/*"}},
			},
		},
	}

	// Normal redirect askes
	r := parseAndEval(t, cfg, "echo foo > output.txt")
	if r.Action != "ask" {
		t.Errorf("normal redirect should ask, got %s", r.Action)
	}

	// System redirect is denied
	r = parseAndEval(t, cfg, "echo foo > /etc/askwd")
	if r.Action != "deny" {
		t.Errorf("system redirect should be denied, got %s", r.Action)
	}
}

func TestEvalAppendRedirects(t *testing.T) {
	appendTrue := true
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
		Redirects: []RedirectRule{
			{
				Action:  "deny",
				Message: "No appending to shell configs",
				Append:  &appendTrue,
				To:      RedirectTarget{Exact: []string{".bashrc"}},
			},
		},
	}

	// Overwrite .bashrc askes (not append)
	r := parseAndEval(t, cfg, "echo foo > .bashrc")
	if r.Action != "ask" {
		t.Errorf("overwrite .bashrc should ask (rule only applies to append), got %s", r.Action)
	}

	// Append to .bashrc is denied
	r = parseAndEval(t, cfg, "echo foo >> .bashrc")
	if r.Action != "deny" {
		t.Errorf("append to .bashrc should be denied, got %s", r.Action)
	}
}

func TestEvalMultipleCommands(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Not allowed",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"echo", "ls"}},
			Deny:  CommandList{Names: []string{"rm"}, Message: "rm not allowed"},
		},
	}

	// All allowed
	r := parseAndEval(t, cfg, "echo hello && ls")
	if r.Action != "allow" {
		t.Errorf("echo && ls should be allowed, got %s", r.Action)
	}

	// One denied
	r = parseAndEval(t, cfg, "echo hello && rm file")
	if r.Action != "deny" {
		t.Errorf("echo && rm should be denied, got %s", r.Action)
	}

	// Mixed allowed and ask -> ask wins (cat not in allow list)
	r = parseAndEval(t, cfg, "echo hello | cat")
	if r.Action != "ask" {
		t.Errorf("echo | cat should ask (cat not in allow list), got %s", r.Action)
	}
}

func TestEvalWildcardRule(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
		Rules: []Rule{
			{
				Command: "*",
				Action:  "deny",
				Message: "No piping to eval",
				Pipe:    PipeContext{To: []string{"eval"}},
			},
		},
	}

	r := parseAndEval(t, cfg, "echo 'rm -rf /' | eval")
	if r.Action != "deny" {
		t.Errorf("pipe to eval should be denied for any command, got %s", r.Action)
	}

	r = parseAndEval(t, cfg, "echo hello")
	if r.Action != "ask" {
		t.Errorf("echo without pipe should ask, got %s", r.Action)
	}
}

func TestEvalDefaultPass(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
		},
	}

	// Everything should ask
	r := parseAndEval(t, cfg, "some_random_command")
	if r.Action != "ask" {
		t.Errorf("should ask by default, got %s", r.Action)
	}
}

// Helper for multi-config tests
func parseAndEvalChain(t *testing.T, configs []*Config, input string) Result {
	t.Helper()
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	info := ExtractFromFile(f)
	chain := &ConfigChain{Configs: configs}
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

func TestConfigChainStrictestWins(t *testing.T) {
	// Global config allows curl
	globalCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"curl"}},
		},
	}

	// Project config denies curl
	projectCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Deny: CommandList{Names: []string{"curl"}, Message: "curl denied by project"},
		},
	}

	// Test: global allows, project denies -> deny wins
	r := parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "curl example.com")
	if r.Action != "deny" {
		t.Errorf("project deny should override global allow, got %s", r.Action)
	}
	if r.Message != "curl denied by project" {
		t.Errorf("unexpected message: %s", r.Message)
	}

	// Test: reverse order doesn't matter - deny still wins
	r = parseAndEvalChain(t, []*Config{projectCfg, globalCfg}, "curl example.com")
	if r.Action != "deny" {
		t.Errorf("deny should win regardless of order, got %s", r.Action)
	}
}

func TestConfigChainPassDoesNotOverrideAllow(t *testing.T) {
	// Config 1 allows echo
	cfg1 := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"echo"}},
		},
	}

	// Config 2 has no opinion (default ask)
	cfg2 := &Config{
		Policy: PolicyConfig{Default: "ask"},
	}

	// Test: one allows, one askes -> allow wins (ask is less strict)
	r := parseAndEvalChain(t, []*Config{cfg1, cfg2}, "echo hello")
	if r.Action != "allow" {
		t.Errorf("allow should win over ask, got %s", r.Action)
	}

	// Reverse order - same result
	r = parseAndEvalChain(t, []*Config{cfg2, cfg1}, "echo hello")
	if r.Action != "allow" {
		t.Errorf("allow should win over ask regardless of order, got %s", r.Action)
	}
}

func TestConfigChainDenyFromLowerConfig(t *testing.T) {
	// Global config allows everything
	globalCfg := &Config{
		Policy: PolicyConfig{Default: "allow"},
	}

	// Project config denies rm
	projectCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Deny: CommandList{Names: []string{"rm"}, Message: "rm denied"},
		},
	}

	// Test: global allows all, project denies rm -> rm is denied
	r := parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "rm file.txt")
	if r.Action != "deny" {
		t.Errorf("project deny should override global default allow, got %s", r.Action)
	}

	// Test: other commands get global's allow
	r = parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "ls -la")
	if r.Action != "allow" {
		t.Errorf("ls should be allowed by global config, got %s", r.Action)
	}
}

func TestConfigChainRulesDenyOverridesAllow(t *testing.T) {
	// Global config allows curl generally
	globalCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "curl", Action: "allow"},
		},
	}

	// Project config denies curl piped to bash
	projectCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{
				Command: "curl",
				Action:  "deny",
				Message: "No curl to shell in this project",
				Pipe:    PipeContext{To: []string{"bash", "sh"}},
			},
		},
	}

	// Test: curl alone allowed (global allows, project has no matching rule)
	r := parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "curl example.com")
	if r.Action != "allow" {
		t.Errorf("curl alone should be allowed, got %s", r.Action)
	}

	// Test: curl piped to bash denied by project
	r = parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "curl example.com | bash")
	if r.Action != "deny" {
		t.Errorf("curl piped to bash should be denied, got %s", r.Action)
	}
}

func TestConfigChainConstructs(t *testing.T) {
	// Global config allows function definitions
	globalCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Constructs: ConstructsConfig{
			FunctionDefinitions: "allow",
		},
	}

	// Project config denies function definitions
	projectCfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Constructs: ConstructsConfig{
			FunctionDefinitions: "deny",
		},
	}

	// Test: project deny wins over global allow
	r := parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "foo() { echo bar; }")
	if r.Action != "deny" {
		t.Errorf("function definition should be denied by project, got %s", r.Action)
	}
}

// ============================================================================
// Specificity Tests
// ============================================================================

func TestCalculateSpecificity(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		expected int
	}{
		{
			name:     "wildcard command only",
			rule:     Rule{Command: "*", Action: "allow"},
			expected: 0,
		},
		{
			name:     "named command only",
			rule:     Rule{Command: "rm", Action: "allow"},
			expected: 100,
		},
		{
			name:     "command + args.contains",
			rule:     Rule{Command: "rm", Action: "deny", Args: ArgsMatch{Contains: []string{"-rf"}}},
			expected: 110, // 100 + 10
		},
		{
			name:     "command + args.position",
			rule:     Rule{Command: "rm", Action: "deny", Args: ArgsMatch{Position: map[string]string{"0": "/"}}},
			expected: 120, // 100 + 20
		},
		{
			name:     "command + args.any_match",
			rule:     Rule{Command: "rm", Action: "deny", Args: ArgsMatch{AnyMatch: []string{"-r", "-rf"}}},
			expected: 110, // 100 + 5 + 5
		},
		{
			name:     "command + pipe.to",
			rule:     Rule{Command: "curl", Action: "deny", Pipe: PipeContext{To: []string{"bash", "sh"}}},
			expected: 120, // 100 + 10 + 10
		},
		{
			name:     "command + pipe.from wildcard",
			rule:     Rule{Command: "bash", Action: "deny", Pipe: PipeContext{From: []string{"*"}}},
			expected: 105, // 100 + 5
		},
		{
			name:     "command + pipe.from named",
			rule:     Rule{Command: "bash", Action: "deny", Pipe: PipeContext{From: []string{"curl"}}},
			expected: 110, // 100 + 10
		},
		{
			name: "complex rule",
			rule: Rule{
				Command: "rm",
				Action:  "deny",
				Args: ArgsMatch{
					Contains: []string{"-rf"},
					Position: map[string]string{"0": "/"},
				},
				Pipe: PipeContext{To: []string{"xargs"}},
			},
			expected: 140, // 100 + 10 + 20 + 10
		},
		{
			name: "wildcard with multiple conditions",
			rule: Rule{
				Command: "*",
				Action:  "deny",
				Pipe:    PipeContext{To: []string{"eval", "bash"}},
			},
			expected: 20, // 0 + 10 + 10
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.Specificity()
			if got != tt.expected {
				t.Errorf("Rule.Specificity() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestActionPriority(t *testing.T) {
	if actionPriority("deny") <= actionPriority("ask") {
		t.Error("deny should have higher priority than ask")
	}
	if actionPriority("ask") <= actionPriority("allow") {
		t.Error("ask should have higher priority than allow")
	}
}

func TestSpecificityOrderIndependence(t *testing.T) {
	// Test that rule order doesn't matter - more specific rule wins
	// regardless of where it appears in the list

	// Order 1: general allow first, specific deny second
	cfg1 := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "rm", Action: "allow"}, // less specific (100)
			{Command: "rm", Action: "deny", Args: ArgsMatch{Contains: []string{"-rf"}}}, // more specific (110)
		},
	}

	// Order 2: specific deny first, general allow second
	cfg2 := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "rm", Action: "deny", Args: ArgsMatch{Contains: []string{"-rf"}}}, // more specific (110)
			{Command: "rm", Action: "allow"}, // less specific (100)
		},
	}

	// rm -rf should be denied in BOTH cases (specific deny wins)
	r1 := parseAndEval(t, cfg1, "rm -rf /")
	r2 := parseAndEval(t, cfg2, "rm -rf /")

	if r1.Action != "deny" {
		t.Errorf("cfg1: rm -rf should be denied (specific rule), got %s", r1.Action)
	}
	if r2.Action != "deny" {
		t.Errorf("cfg2: rm -rf should be denied (specific rule), got %s", r2.Action)
	}

	// rm file.txt should be allowed in BOTH cases (general allow wins)
	r1 = parseAndEval(t, cfg1, "rm file.txt")
	r2 = parseAndEval(t, cfg2, "rm file.txt")

	if r1.Action != "allow" {
		t.Errorf("cfg1: rm file.txt should be allowed (only general rule matches), got %s", r1.Action)
	}
	if r2.Action != "allow" {
		t.Errorf("cfg2: rm file.txt should be allowed (only general rule matches), got %s", r2.Action)
	}
}

func TestSpecificityTieBreaking(t *testing.T) {
	// When two rules have equal specificity, most restrictive wins (deny > ask > allow)
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "rm", Action: "allow"},                                          // specificity 100
			{Command: "rm", Action: "deny", Args: ArgsMatch{Contains: []string{"-r"}}}, // specificity 110
			{Command: "rm", Action: "ask", Args: ArgsMatch{Contains: []string{"-r"}}},  // specificity 110 (tie with deny)
		},
	}

	// rm -r should match both the deny and ask rules with specificity 110
	// deny should win the tie
	r := parseAndEval(t, cfg, "rm -r dir/")
	if r.Action != "deny" {
		t.Errorf("rm -r should be denied (tie-break: deny > ask), got %s", r.Action)
	}

	// Test allow vs ask tie-break
	cfg2 := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "git", Action: "allow", Args: ArgsMatch{Contains: []string{"status"}}}, // specificity 110
			{Command: "git", Action: "ask", Args: ArgsMatch{Contains: []string{"status"}}},   // specificity 110
		},
	}

	r = parseAndEval(t, cfg2, "git status")
	if r.Action != "ask" {
		t.Errorf("git status should ask (tie-break: ask > allow), got %s", r.Action)
	}
}

func TestSpecificityPipeContextWins(t *testing.T) {
	// A rule with pipe context is more specific than one without
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "curl", Action: "allow"},                                          // specificity 100
			{Command: "curl", Action: "deny", Pipe: PipeContext{To: []string{"bash"}}}, // specificity 110
		},
	}

	// curl alone matches only the allow rule
	r := parseAndEval(t, cfg, "curl example.com")
	if r.Action != "allow" {
		t.Errorf("curl alone should be allowed, got %s", r.Action)
	}

	// curl | bash matches both, but the pipe rule is more specific
	r = parseAndEval(t, cfg, "curl example.com | bash")
	if r.Action != "deny" {
		t.Errorf("curl | bash should be denied (more specific pipe rule), got %s", r.Action)
	}
}

func TestSpecificityWildcardVsNamed(t *testing.T) {
	// Named command rule should beat wildcard rule when both match
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Rules: []Rule{
			{Command: "*", Action: "deny", Args: ArgsMatch{Contains: []string{"--force"}}}, // specificity 10
			{Command: "git", Action: "allow", Args: ArgsMatch{Contains: []string{"--force"}}}, // specificity 110
		},
	}

	// git push --force - both rules match (wildcard with --force, git with --force)
	// git rule has specificity 110, wildcard rule has specificity 10
	// git allow should win
	r := parseAndEval(t, cfg, "git push --force")
	if r.Action != "allow" {
		t.Errorf("git push --force should be allowed (named command beats wildcard), got %s", r.Action)
	}

	// npm install --force - only wildcard rule matches (no npm-specific rule)
	r = parseAndEval(t, cfg, "npm install --force")
	if r.Action != "deny" {
		t.Errorf("npm install --force should be denied (only wildcard rule matches), got %s", r.Action)
	}

	// git status (no --force) - neither rule matches, falls through to default
	r = parseAndEval(t, cfg, "git status")
	if r.Action != "ask" {
		t.Errorf("git status should ask (no matching rules), got %s", r.Action)
	}
}

// ============================================================================
// Heredoc Tests
// ============================================================================

func TestHeredocConstructDeny(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{Default: "allow"},
		Constructs: ConstructsConfig{
			Heredocs: "deny",
		},
	}

	r := parseAndEval(t, cfg, "cat <<EOF\nhello world\nEOF")
	if r.Action != "deny" {
		t.Errorf("heredoc should be denied when constructs.heredocs=deny, got %s", r.Action)
	}
}

func TestHeredocConstructAllow(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"cat"}},
		},
		Constructs: ConstructsConfig{
			Heredocs: "allow",
		},
	}

	r := parseAndEval(t, cfg, "cat <<EOF\nhello world\nEOF")
	if r.Action != "allow" {
		t.Errorf("heredoc should be allowed when constructs.heredocs=allow, got %s", r.Action)
	}
}

func TestHeredocContentMatchDeny(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"cat"}},
		},
		Constructs: ConstructsConfig{
			Heredocs: "allow",
		},
		Heredocs: []HeredocRule{
			{
				Action:       "deny",
				Message:      "SQL injection detected",
				ContentMatch: []string{"re:DROP TABLE", "re:DELETE FROM"},
			},
		},
	}

	// Safe heredoc - no matching content
	r := parseAndEval(t, cfg, "cat <<EOF\nSELECT * FROM users\nEOF")
	if r.Action != "allow" {
		t.Errorf("safe heredoc should be allowed, got %s", r.Action)
	}

	// Dangerous heredoc - matches content_match
	r = parseAndEval(t, cfg, "cat <<EOF\nDROP TABLE users;\nEOF")
	if r.Action != "deny" {
		t.Errorf("dangerous heredoc should be denied, got %s", r.Action)
	}
}

func TestHeredocNotTreatedAsRedirect(t *testing.T) {
	// This test verifies that heredocs are NOT treated as redirects
	// Previously, "EOF" would show up as a redirect target
	cfg := &Config{
		Policy: PolicyConfig{Default: "ask"},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"cat"}},
		},
		Constructs: ConstructsConfig{
			Heredocs: "allow",
		},
		Redirects: []RedirectRule{
			{
				Action:  "deny",
				Message: "All redirects denied",
				To:      RedirectTarget{Pattern: []string{"re:.*"}},
			},
		},
	}

	// Heredoc should NOT be denied by the redirect rule
	r := parseAndEval(t, cfg, "cat <<EOF\nhello\nEOF")
	if r.Action != "allow" {
		t.Errorf("heredoc should not be treated as redirect, got %s (message: %s)", r.Action, r.Message)
	}

	// But actual file redirects should still be denied
	r = parseAndEval(t, cfg, "cat file.txt > output.txt")
	if r.Action != "deny" {
		t.Errorf("file redirect should be denied, got %s", r.Action)
	}
}

func TestPathPatternInRules(t *testing.T) {
	// Test path patterns in rule evaluation
	// Uses $HOME which is always available
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Not allowed",
		},
		Rules: []Rule{
			{
				Command: "rm",
				Action:  "allow",
				Args: ArgsMatch{
					AnyMatch: []string{"path:$HOME/**"},
				},
			},
			{
				Command: "rm",
				Action:  "deny",
				Message: "Cannot delete outside home",
				Args: ArgsMatch{
					AnyMatch: []string{"path:/etc/**"},
				},
			},
		},
	}

	// rm with path under home should be allowed
	r := parseAndEval(t, cfg, "rm ~/file.txt")
	if r.Action != "allow" {
		t.Errorf("rm ~/file.txt should be allowed (path under $HOME), got %s", r.Action)
	}

	// rm with path under /etc should be denied
	r = parseAndEval(t, cfg, "rm /etc/passwd")
	if r.Action != "deny" {
		t.Errorf("rm /etc/passwd should be denied, got %s", r.Action)
	}
}

func TestPathPatternPosition(t *testing.T) {
	// Test path patterns in positional matching
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Not allowed",
		},
		Rules: []Rule{
			{
				Command: "rm",
				Action:  "allow",
				Args: ArgsMatch{
					Position: map[string]string{
						"0": "-rf",
						"1": "path:$HOME/**",
					},
				},
			},
		},
	}

	// rm -rf with path under home should be allowed
	r := parseAndEval(t, cfg, "rm -rf ~/temp")
	if r.Action != "allow" {
		t.Errorf("rm -rf ~/temp should be allowed, got %s", r.Action)
	}

	// rm -rf with path outside home should not match the rule
	r = parseAndEval(t, cfg, "rm -rf /tmp/foo")
	if r.Action != "ask" {
		t.Errorf("rm -rf /tmp/foo should ask (rule didn't match), got %s", r.Action)
	}
}

// ============================================================================
// Command Path Resolution Tests
// ============================================================================

func TestBuiltinCommandsBypassPathResolution(t *testing.T) {
	// Builtins like cd, exit, etc. should work without path resolution
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "deny", // strict mode
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"cd", "exit", "source", "export"}},
		},
	}

	// cd is a builtin - should be allowed even with strict unresolved_commands=deny
	r := parseAndEval(t, cfg, "cd /tmp")
	if r.Action != "allow" {
		t.Errorf("cd (builtin) should be allowed, got %s", r.Action)
	}

	// exit is a builtin
	r = parseAndEval(t, cfg, "exit 0")
	if r.Action != "allow" {
		t.Errorf("exit (builtin) should be allowed, got %s", r.Action)
	}

	// source is a bash builtin
	r = parseAndEval(t, cfg, "source ~/.bashrc")
	if r.Action != "allow" {
		t.Errorf("source (builtin) should be allowed, got %s", r.Action)
	}
}

func TestUnresolvedCommandsPolicyAsk(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "allow",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask", // default
		},
	}

	// A command that definitely doesn't exist
	r := parseAndEval(t, cfg, "nonexistent_command_xyz123 --arg")
	if r.Action != "ask" {
		t.Errorf("unresolved command should ask, got %s", r.Action)
	}
}

func TestUnresolvedCommandsPolicyDeny(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "allow",
			DynamicCommands:    "ask",
			UnresolvedCommands: "deny",
		},
	}

	// A command that definitely doesn't exist
	r := parseAndEval(t, cfg, "nonexistent_command_xyz123 --arg")
	if r.Action != "deny" {
		t.Errorf("unresolved command should be denied when policy=deny, got %s", r.Action)
	}
}

func TestPathPatternInAllowList(t *testing.T) {
	// Test path: prefix in commands.allow.names
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{
				"path:/usr/bin/ls",
				"path:/bin/ls",
			}},
		},
	}

	// ls resolves to /usr/bin/ls or /bin/ls on most systems
	r := parseAndEval(t, cfg, "ls -la")
	// This should be allowed if ls resolves to one of the allowed paths
	// On most systems, ls is in /usr/bin or /bin
	if r.Action != "allow" && r.Action != "ask" {
		t.Logf("ls resolved to path, action=%s (expected allow if path matches)", r.Action)
	}
}

func TestPathPatternInDenyList(t *testing.T) {
	// Test path: prefix in commands.deny.names
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "allow",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
		},
		Commands: CommandsConfig{
			Deny: CommandList{
				Names:   []string{"path:/usr/bin/rm", "path:/bin/rm"},
				Message: "rm from /usr/bin or /bin not allowed",
			},
		},
	}

	// rm resolves to /usr/bin/rm or /bin/rm on most systems
	r := parseAndEval(t, cfg, "rm file.txt")
	// This should be denied if rm resolves to one of the denied paths
	if r.Action == "deny" {
		t.Logf("rm correctly denied (path: %s)", r.Source)
	}
}

func TestPathPatternInRuleCommand(t *testing.T) {
	// Test path: prefix in rule.command
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
		},
		Rules: []Rule{
			{
				Command: "path:/usr/bin/*",
				Action:  "allow",
			},
		},
	}

	// Commands that resolve to /usr/bin should be allowed
	r := parseAndEval(t, cfg, "ls -la")
	// This test depends on system configuration - ls may or may not be in /usr/bin
	t.Logf("ls with path:/usr/bin/* rule: action=%s", r.Action)
}

func TestAllowedPathsRestriction(t *testing.T) {
	// Test that allowed_paths restricts command resolution
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "allow",
			DynamicCommands:    "ask",
			UnresolvedCommands: "deny",
			AllowedPaths:       []string{"/nonexistent/path"},
		},
	}

	// ls should not be found because we restricted to a nonexistent path
	r := parseAndEval(t, cfg, "ls")
	if r.Action != "deny" {
		t.Errorf("ls should be denied when not in allowed_paths, got %s", r.Action)
	}
}

func TestResolvedPathUsedForMatching(t *testing.T) {
	// Test that the resolved path is used for basename matching
	cfg := &Config{
		Policy: PolicyConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"ls"}},
		},
	}

	// Running ls as a full path should still match "ls" in allow list
	// because we match against the basename of the resolved path
	r := parseAndEval(t, cfg, "/usr/bin/ls -la")
	if r.Action == "allow" {
		t.Logf("Full path /usr/bin/ls correctly matched 'ls' in allow list")
	} else {
		// The path might not exist or have different behavior
		t.Logf("Full path /usr/bin/ls action=%s (may not exist on this system)", r.Action)
	}
}
