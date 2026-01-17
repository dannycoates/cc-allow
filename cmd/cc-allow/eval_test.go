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

	// curl piped to cat askes (cat not in pipe.to list, curl matches allow rule)
	r = parseAndEval(t, cfg, "curl example.com | cat")
	if r.Action != "allow" {
		t.Errorf("curl piped to cat should be allowed, got %s", r.Action)
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

	// Mixed allowed and ask -> allow wins
	r = parseAndEval(t, cfg, "echo hello | cat")
	if r.Action != "allow" {
		t.Errorf("echo | cat should be allowed (echo is allowed), got %s", r.Action)
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
