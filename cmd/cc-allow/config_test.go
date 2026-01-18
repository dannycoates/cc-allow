package main

import (
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	toml := `
[policy]
default = "deny"
dynamic_commands = "deny"
default_message = "Not allowed"

[commands.deny]
names = ["rm", "rmdir"]
message = "Destructive commands not allowed"

[commands.allow]
names = ["echo", "ls"]

[[rule]]
command = "curl"
action = "deny"
message = "No curl to shell"
[rule.pipe]
to = ["bash", "sh"]

[[rule]]
command = "curl"
action = "allow"

[constructs]
function_definitions = "deny"
`

	cfg, err := ParseConfig(toml)
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	// Check policy
	if cfg.Policy.Default != "deny" {
		t.Errorf("expected default=deny, got %s", cfg.Policy.Default)
	}
	if cfg.Policy.DynamicCommands != "deny" {
		t.Errorf("expected dynamic_commands=deny, got %s", cfg.Policy.DynamicCommands)
	}

	// Check deny list
	if len(cfg.Commands.Deny.Names) != 2 {
		t.Errorf("expected 2 deny names, got %d", len(cfg.Commands.Deny.Names))
	}
	if cfg.Commands.Deny.Message != "Destructive commands not allowed" {
		t.Errorf("unexpected deny message: %s", cfg.Commands.Deny.Message)
	}

	// Check allow list
	if len(cfg.Commands.Allow.Names) != 2 {
		t.Errorf("expected 2 allow names, got %d", len(cfg.Commands.Allow.Names))
	}

	// Check rules
	if len(cfg.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(cfg.Rules))
	}

	// Check constructs
	if cfg.Constructs.FunctionDefinitions != "deny" {
		t.Errorf("expected function_definitions=deny, got %s", cfg.Constructs.FunctionDefinitions)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Policy.Default != "ask" {
		t.Errorf("expected default=ask, got %s", cfg.Policy.Default)
	}
	if cfg.Policy.DynamicCommands != "ask" {
		t.Errorf("expected dynamic_commands=ask, got %s", cfg.Policy.DynamicCommands)
	}
	if cfg.Constructs.Subshells != "ask" {
		t.Errorf("expected subshells=ask, got %s", cfg.Constructs.Subshells)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	// Minimal config
	cfg, err := ParseConfig("")
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	if cfg.Policy.Default != "ask" {
		t.Errorf("expected default default=ask, got %s", cfg.Policy.Default)
	}
	if cfg.Policy.DefaultMessage != "Command not allowed" {
		t.Errorf("expected default message, got %s", cfg.Policy.DefaultMessage)
	}
}

func TestParseConfigInvalidPatterns(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "invalid regex in args.any_match",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
any_match = ["re:[invalid"]
`,
			wantErr: "rule[0] (command=\"test\"): invalid args.any_match pattern",
		},
		{
			name: "invalid regex in args.all_match",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
all_match = ["re:(unclosed"]
`,
			wantErr: "rule[0] (command=\"test\"): invalid args.all_match pattern",
		},
		// NOTE: args.position test skipped - TOML library doesn't support integer map keys
		// This is a known limitation. Position matching works when Rule structs are
		// constructed programmatically but not from TOML config files.
		{
			name: "invalid regex in redirect pattern",
			config: `
[[redirect]]
action = "deny"
[redirect.to]
pattern = ["re:[bad"]
`,
			wantErr: "redirect[0]: invalid to.pattern",
		},
		{
			name: "invalid regex in heredoc content_match",
			config: `
[[heredoc]]
action = "deny"
content_match = ["re:+++"]
`,
			wantErr: "heredoc[0]: invalid content_match pattern",
		},
		{
			name: "valid patterns should pass",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
any_match = ["re:^-[a-z]+$", "glob:*.txt"]
`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(tt.config)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tt.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
