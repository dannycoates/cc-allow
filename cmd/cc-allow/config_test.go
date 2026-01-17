package main

import (
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

	if cfg.Policy.Default != "pass" {
		t.Errorf("expected default=pass, got %s", cfg.Policy.Default)
	}
	if cfg.Policy.DynamicCommands != "pass" {
		t.Errorf("expected dynamic_commands=pass, got %s", cfg.Policy.DynamicCommands)
	}
	if cfg.Constructs.Subshells != "pass" {
		t.Errorf("expected subshells=pass, got %s", cfg.Constructs.Subshells)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	// Minimal config
	cfg, err := ParseConfig("")
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	if cfg.Policy.Default != "pass" {
		t.Errorf("expected default default=pass, got %s", cfg.Policy.Default)
	}
	if cfg.Policy.DefaultMessage != "Command not allowed" {
		t.Errorf("expected default message, got %s", cfg.Policy.DefaultMessage)
	}
}
