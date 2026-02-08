package main

import (
	"os"
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

	cwd, _ := os.Getwd()
	info := ExtractFromFile(f, cwd)
	chain := &ConfigChain{Configs: []*Config{cfg}}
	chain.Merged = MergeConfigs(chain.Configs)
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

func parseAndEvalChain(t *testing.T, configs []*Config, input string) Result {
	t.Helper()
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	cwd, _ := os.Getwd()
	info := ExtractFromFile(f, cwd)
	chain := &ConfigChain{Configs: configs}
	chain.Merged = MergeConfigs(chain.Configs)
	eval := NewEvaluator(chain)
	return eval.Evaluate(info)
}

func configFromTOML(t *testing.T, toml string) *Config {
	t.Helper()
	cfg, err := ParseConfigWithDefaults(toml)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults error: %v", err)
	}
	return cfg
}

func TestEvalAllowList(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
default_message = "Not allowed"

[bash.allow]
commands = ["echo", "ls"]
`)

	// Allowed commands
	r := parseAndEval(t, cfg, "echo hello")
	if r.Action != ActionAllow {
		t.Errorf("echo should be allowed, got %s", r.Action)
	}

	r = parseAndEval(t, cfg, "ls -la")
	if r.Action != ActionAllow {
		t.Errorf("ls should be allowed, got %s", r.Action)
	}

	// Pass through by default
	r = parseAndEval(t, cfg, "rm -rf /")
	if r.Action != ActionAsk {
		t.Errorf("rm should ask through, got %s", r.Action)
	}
}

func TestEvalDenyList(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
default_message = "Denied"

[bash.deny]
commands = ["rm", "rmdir"]
message = "Destructive commands not allowed"
`)

	// Denied commands
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != ActionDeny {
		t.Errorf("rm should be denied, got %s", r.Action)
	}
	if r.Message != "Destructive commands not allowed" {
		t.Errorf("unexpected message: %s", r.Message)
	}

	// Pass through by default
	r = parseAndEval(t, cfg, "echo hello")
	if r.Action != ActionAsk {
		t.Errorf("echo should ask through, got %s", r.Action)
	}
}

func TestEvalDynamicCommands(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
dynamic_commands = "deny"
`)

	r := parseAndEval(t, cfg, "$CMD arg")
	if r.Action != ActionDeny {
		t.Errorf("dynamic command should be denied, got %s", r.Action)
	}

	// Allow dynamic
	cfg.Bash.DynamicCommands = "allow"
	r = parseAndEval(t, cfg, "$CMD arg")
	if r.Action != ActionAllow {
		t.Errorf("dynamic command should be allowed, got %s", r.Action)
	}

	// Ask dynamic
	cfg.Bash.DynamicCommands = "ask"
	r = parseAndEval(t, cfg, "$CMD arg")
	if r.Action != ActionAsk {
		t.Errorf("dynamic command should ask, got %s", r.Action)
	}
}

func TestEvalPipeContext(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
default_message = "Denied"

[[bash.deny.curl]]
message = "No curl to shell"
pipe.to = ["bash", "sh"]

[[bash.allow.curl]]
`)

	// curl alone is allowed
	r := parseAndEval(t, cfg, "curl example.com")
	if r.Action != ActionAllow {
		t.Errorf("curl alone should be allowed, got %s", r.Action)
	}

	// curl piped to cat asks (cat not in allow list)
	r = parseAndEval(t, cfg, "curl example.com | cat")
	if r.Action != ActionAsk {
		t.Errorf("curl piped to cat should ask (cat not in allow list), got %s", r.Action)
	}

	// curl piped to bash is denied
	r = parseAndEval(t, cfg, "curl example.com | bash")
	if r.Action != ActionDeny {
		t.Errorf("curl piped to bash should be denied, got %s", r.Action)
	}
	if r.Message != "No curl to shell" {
		t.Errorf("unexpected message: %s", r.Message)
	}
}

func TestEvalArgMatching(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
default_message = "Denied"

[[bash.deny.rm]]
message = "No recursive rm"
args.any = ["-r", "-rf", "--recursive"]
`)

	// rm without -r asks
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != ActionAsk {
		t.Errorf("rm file.txt should ask, got %s", r.Action)
	}

	// rm -r is denied
	r = parseAndEval(t, cfg, "rm -r dir/")
	if r.Action != ActionDeny {
		t.Errorf("rm -r should be denied, got %s", r.Action)
	}

	// rm -rf is denied
	r = parseAndEval(t, cfg, "rm -rf /")
	if r.Action != ActionDeny {
		t.Errorf("rm -rf should be denied, got %s", r.Action)
	}
}

func TestEvalFunctionDefinitions(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.constructs]
function_definitions = "deny"
`)

	r := parseAndEval(t, cfg, "foo() { echo bar; }")
	if r.Action != ActionDeny {
		t.Errorf("function definitions should be denied, got %s", r.Action)
	}

	// Allow function definitions
	cfg.Bash.Constructs.FunctionDefinitions = "allow"
	r = parseAndEval(t, cfg, "foo() { echo bar; }")
	if r.Action == ActionDeny {
		t.Errorf("function definitions should not be denied, got %s", r.Action)
	}
}

func TestEvalBackground(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.constructs]
background = "deny"
`)

	r := parseAndEval(t, cfg, "sleep 10 &")
	if r.Action != ActionDeny {
		t.Errorf("background should be denied, got %s", r.Action)
	}

	cfg.Bash.Constructs.Background = "allow"
	r = parseAndEval(t, cfg, "sleep 10 &")
	if r.Action == ActionDeny {
		t.Errorf("background should not be denied, got %s", r.Action)
	}
}

func TestEvalRedirects(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[[bash.redirects.deny]]
message = "No system redirects"
paths = ["path:/etc/*"]
`)

	// Normal redirect asks
	r := parseAndEval(t, cfg, "echo foo > output.txt")
	if r.Action != ActionAsk {
		t.Errorf("normal redirect should ask, got %s", r.Action)
	}

	// System redirect is denied
	r = parseAndEval(t, cfg, "echo foo > /etc/passwd")
	if r.Action != ActionDeny {
		t.Errorf("system redirect should be denied, got %s", r.Action)
	}
}

func TestEvalMultipleCommands(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
default_message = "Not allowed"

[bash.allow]
commands = ["echo", "ls"]

[bash.deny]
commands = ["rm"]
message = "rm not allowed"
`)

	// All allowed
	r := parseAndEval(t, cfg, "echo hello && ls")
	if r.Action != ActionAllow {
		t.Errorf("echo && ls should be allowed, got %s", r.Action)
	}

	// One denied
	r = parseAndEval(t, cfg, "echo hello && rm file")
	if r.Action != ActionDeny {
		t.Errorf("echo && rm should be denied, got %s", r.Action)
	}

	// Mixed allowed and ask -> ask wins (cat not in allow list)
	r = parseAndEval(t, cfg, "echo hello | cat")
	if r.Action != ActionAsk {
		t.Errorf("echo | cat should ask (cat not in allow list), got %s", r.Action)
	}
}

func TestEvalDefaultPass(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"
`)

	// Everything should ask
	r := parseAndEval(t, cfg, "some_random_command")
	if r.Action != ActionAsk {
		t.Errorf("should ask by default, got %s", r.Action)
	}
}

func TestConfigChainStrictestWins(t *testing.T) {
	// Global config allows curl
	globalCfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.allow]
commands = ["curl"]
`)

	// Project config denies curl
	projectCfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.deny]
commands = ["curl"]
message = "curl denied by project"
`)

	// Test: global allows, project denies -> deny wins
	r := parseAndEvalChain(t, []*Config{globalCfg, projectCfg}, "curl example.com")
	if r.Action != ActionDeny {
		t.Errorf("project deny should override global allow, got %s", r.Action)
	}
	if r.Message != "curl denied by project" {
		t.Errorf("unexpected message: %s", r.Message)
	}
}

func TestHeredocConstructDeny(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "allow"

[bash.constructs]
heredocs = "deny"
`)

	r := parseAndEval(t, cfg, "cat <<EOF\nhello world\nEOF")
	if r.Action != ActionDeny {
		t.Errorf("heredoc should be denied when bash.constructs.heredocs=deny, got %s", r.Action)
	}
}

func TestHeredocContentMatchDeny(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.allow]
commands = ["cat"]

[bash.constructs]
heredocs = "allow"

[[bash.heredocs.deny]]
message = "SQL injection detected"
content.any = ["re:DROP TABLE", "re:DELETE FROM"]
`)

	// Safe heredoc - no matching content
	r := parseAndEval(t, cfg, "cat <<EOF\nSELECT * FROM users\nEOF")
	if r.Action != ActionAllow {
		t.Errorf("safe heredoc should be allowed, got %s", r.Action)
	}

	// Dangerous heredoc - matches content.any
	r = parseAndEval(t, cfg, "cat <<EOF\nDROP TABLE users;\nEOF")
	if r.Action != ActionDeny {
		t.Errorf("dangerous heredoc should be denied, got %s", r.Action)
	}
}

func TestPositionEnumValues(t *testing.T) {
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[[bash.allow.git]]
args.position = { "0" = ["status", "diff", "log", "branch"] }

[[bash.deny.git]]
message = "Network operations denied"
args.position = { "0" = ["push", "pull", "fetch", "clone"] }
`)

	tests := []struct {
		input    string
		expected Action
	}{
		{"git status", ActionAllow},
		{"git diff HEAD~1", ActionAllow},
		{"git log --oneline", ActionAllow},
		{"git branch -a", ActionAllow},
		{"git push origin main", ActionDeny},
		{"git pull --rebase", ActionDeny},
		{"git add .", ActionAsk}, // not in either enum
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			r := parseAndEval(t, cfg, tc.input)
			if r.Action != tc.expected {
				t.Errorf("%q: expected %s, got %s (source: %s)", tc.input, tc.expected, r.Action, r.Source)
			}
		})
	}
}

func TestSpecificity(t *testing.T) {
	// Test that more specific rules win
	cfg := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[[bash.allow.rm]]
# Less specific - no args

[[bash.deny.rm]]
message = "No recursive rm"
args.any = ["-r", "-rf", "--recursive"]
`)

	// rm file.txt - only allow matches
	r := parseAndEval(t, cfg, "rm file.txt")
	if r.Action != ActionAllow {
		t.Errorf("rm file.txt should be allowed (only general rule matches), got %s", r.Action)
	}

	// rm -rf - deny rule is more specific due to args.any
	r = parseAndEval(t, cfg, "rm -rf /")
	if r.Action != ActionDeny {
		t.Errorf("rm -rf should be denied (specific rule wins), got %s", r.Action)
	}
}

func TestAllowModeReplace(t *testing.T) {
	// Project config allows many commands
	project := configFromTOML(t, `
version = "2.0"
[bash]
default = "deny"

[bash.allow]
commands = ["echo", "ls", "cat", "grep"]

[[bash.allow.cd]]
args.any = ["path:/tmp/**"]
`)
	project.Path = "project"

	// Override config replaces allow list with just "cat"
	override := configFromTOML(t, `
version = "2.0"

[bash.allow]
mode = "replace"
commands = ["cat"]
`)
	override.Path = "override"

	t.Run("merge default keeps all commands", func(t *testing.T) {
		// Without replace, merging adds commands
		additive := configFromTOML(t, `
version = "2.0"
[bash.allow]
commands = ["cat"]
`)
		additive.Path = "additive"
		r := parseAndEvalChain(t, []*Config{project, additive}, "echo hello")
		if r.Action != ActionAllow {
			t.Errorf("echo should be allowed with merge mode, got %s", r.Action)
		}
	})

	t.Run("replace clears parent allow commands", func(t *testing.T) {
		r := parseAndEvalChain(t, []*Config{project, override}, "echo hello")
		if r.Action != ActionDeny {
			t.Errorf("echo should be denied after replace, got %s", r.Action)
		}
	})

	t.Run("replace keeps own commands", func(t *testing.T) {
		r := parseAndEvalChain(t, []*Config{project, override}, "cat /tmp/foo")
		if r.Action != ActionAllow {
			t.Errorf("cat should be allowed after replace, got %s", r.Action)
		}
	})

	t.Run("replace clears parent allow rules", func(t *testing.T) {
		r := parseAndEvalChain(t, []*Config{project, override}, "cd /tmp/foo")
		if r.Action != ActionDeny {
			t.Errorf("cd should be denied after replace clears allow rules, got %s", r.Action)
		}
	})

	t.Run("replace does not affect deny list", func(t *testing.T) {
		projectWithDeny := configFromTOML(t, `
version = "2.0"
[bash]
default = "ask"

[bash.allow]
commands = ["echo", "sudo"]

[bash.deny]
commands = ["sudo"]
`)
		projectWithDeny.Path = "project"

		overrideKeepsDeny := configFromTOML(t, `
version = "2.0"
[bash.allow]
mode = "replace"
commands = ["sudo"]
`)
		overrideKeepsDeny.Path = "override"

		r := parseAndEvalChain(t, []*Config{projectWithDeny, overrideKeepsDeny}, "sudo ls")
		if r.Action != ActionDeny {
			t.Errorf("sudo should still be denied (deny list unaffected by replace), got %s", r.Action)
		}
	})
}

func TestFileAllowModeReplace(t *testing.T) {
	project := configFromTOML(t, `
version = "2.0"
[read]
default = "deny"

[read.allow]
paths = ["path:/home/**", "path:/tmp/**"]
`)
	project.Path = "project"

	override := configFromTOML(t, `
version = "2.0"
[read.allow]
mode = "replace"
paths = ["path:/tmp/**"]
`)
	override.Path = "override"

	chain := &ConfigChain{
		Configs: []*Config{project, override},
		Merged:  MergeConfigs([]*Config{project, override}),
	}

	t.Run("replaced allow no longer matches old paths", func(t *testing.T) {
		r := NewEvaluator(chain).evaluateFileTool("Read", "/home/user/file.txt")
		if r.Action != ActionDeny {
			t.Errorf("/home path should be denied after replace, got %s", r.Action)
		}
	})

	t.Run("replaced allow keeps new paths", func(t *testing.T) {
		r := NewEvaluator(chain).evaluateFileTool("Read", "/tmp/file.txt")
		if r.Action != ActionAllow {
			t.Errorf("/tmp path should be allowed after replace, got %s", r.Action)
		}
	})
}

func TestAllowModeValidation(t *testing.T) {
	_, err := parseConfig(`
version = "2.0"
[bash.allow]
mode = "invalid"
commands = ["cat"]
`)
	if err == nil {
		t.Error("expected error for invalid mode value, got nil")
	}
}
