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
	eval := NewEvaluator(cfg)
	return eval.Evaluate(info)
}

func TestEvalAllowList(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
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
	if r.Action != "pass" {
		t.Errorf("rm should pass through, got %s", r.Action)
	}
}

func TestEvalDenyList(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
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
	if r.Action != "pass" {
		t.Errorf("echo should pass through, got %s", r.Action)
	}
}

func TestEvalDynamicCommands(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
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
	cfg.Policy.DynamicCommands = "pass"
	r = parseAndEval(t, cfg, "$CMD arg")
	if r.Action != "pass" {
		t.Errorf("dynamic command should pass, got %s", r.Action)
	}
}

func TestEvalPipeContext(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
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

	// curl piped to cat passes (cat not in pipe.to list, curl matches allow rule)
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
			Default:         "pass",
			DynamicCommands: "pass",
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

	// rm without -r passes
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != "pass" {
		t.Errorf("rm file.txt should pass, got %s", r.Action)
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
			Default:         "pass",
			DynamicCommands: "pass",
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
			Default:         "pass",
			DynamicCommands: "pass",
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
			Default:         "pass",
			DynamicCommands: "pass",
		},
		Redirects: []RedirectRule{
			{
				Action:  "deny",
				Message: "No system redirects",
				To:      RedirectTarget{Pattern: []string{"glob:/etc/*"}},
			},
		},
	}

	// Normal redirect passes
	r := parseAndEval(t, cfg, "echo foo > output.txt")
	if r.Action != "pass" {
		t.Errorf("normal redirect should pass, got %s", r.Action)
	}

	// System redirect is denied
	r = parseAndEval(t, cfg, "echo foo > /etc/passwd")
	if r.Action != "deny" {
		t.Errorf("system redirect should be denied, got %s", r.Action)
	}
}

func TestEvalAppendRedirects(t *testing.T) {
	appendTrue := true
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
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

	// Overwrite .bashrc passes (not append)
	r := parseAndEval(t, cfg, "echo foo > .bashrc")
	if r.Action != "pass" {
		t.Errorf("overwrite .bashrc should pass (rule only applies to append), got %s", r.Action)
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
			Default:         "pass",
			DynamicCommands: "pass",
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

	// Mixed allowed and pass -> allow wins
	r = parseAndEval(t, cfg, "echo hello | cat")
	if r.Action != "allow" {
		t.Errorf("echo | cat should be allowed (echo is allowed), got %s", r.Action)
	}
}

func TestEvalWildcardRule(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
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
	if r.Action != "pass" {
		t.Errorf("echo without pipe should pass, got %s", r.Action)
	}
}

func TestEvalDefaultPass(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
		},
	}

	// Everything should pass
	r := parseAndEval(t, cfg, "some_random_command")
	if r.Action != "pass" {
		t.Errorf("should pass by default, got %s", r.Action)
	}
}
