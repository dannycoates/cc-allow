package main

import (
	"errors"
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
		name           string
		config         string
		wantErr        string
		wantPatternErr bool // true if error should include ErrInvalidPattern
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
			wantErr:        "invalid configuration: rule[0]",
			wantPatternErr: true,
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
			wantErr:        "invalid configuration: rule[0]",
			wantPatternErr: true,
		},
		{
			name: "invalid regex in args.position",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
position = { "0" = "re:(unclosed" }
`,
			wantErr:        "invalid configuration: rule[0]",
			wantPatternErr: true,
		},
		{
			name: "invalid position key (non-integer)",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
position = { "abc" = "foo" }
`,
			wantErr:        "is not a valid integer",
			wantPatternErr: false, // This is a key format error, not a pattern error
		},
		{
			name: "invalid regex in redirect pattern",
			config: `
[[redirect]]
action = "deny"
[redirect.to]
pattern = ["re:[bad"]
`,
			wantErr:        "invalid configuration: redirect[0]",
			wantPatternErr: true,
		},
		{
			name: "invalid regex in heredoc content_match",
			config: `
[[heredoc]]
action = "deny"
content_match = ["re:+++"]
`,
			wantErr:        "invalid configuration: heredoc[0]",
			wantPatternErr: true,
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
		{
			name: "valid args.position should pass",
			config: `
[[rule]]
command = "chmod"
action = "allow"
[rule.args]
position = { "0" = "re:^[0-7]{3,4}$", "1" = "glob:*.txt" }
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
			// Verify sentinel error works with errors.Is()
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("expected errors.Is(err, ErrInvalidConfig) to be true")
			}
			if tt.wantPatternErr && !errors.Is(err, ErrInvalidPattern) {
				t.Errorf("expected errors.Is(err, ErrInvalidPattern) to be true")
			}
		})
	}
}

func TestParseExtendedArgumentMatching(t *testing.T) {
	// Test TOML parsing of extended argument matching features
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "position with array values (enum)",
			config: `
[[rule]]
command = "git"
action = "allow"
[rule.args]
position = { "0" = ["status", "diff", "log"] }
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Rules) != 1 {
					t.Fatal("expected 1 rule")
				}
				fp, ok := cfg.Rules[0].Args.Position["0"]
				if !ok {
					t.Fatal("expected position 0")
				}
				if len(fp.Patterns) != 3 {
					t.Errorf("expected 3 patterns in position 0, got %d", len(fp.Patterns))
				}
			},
		},
		{
			name: "any_match with sequence objects",
			config: `
[[rule]]
command = "ffmpeg"
action = "allow"
[rule.args]
any_match = [
    { "0" = "-i", "1" = "path:$HOME/**" },
    "re:^--help$"
]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Rules) != 1 {
					t.Fatal("expected 1 rule")
				}
				elems := cfg.Rules[0].Args.AnyMatch
				if len(elems) != 2 {
					t.Fatalf("expected 2 any_match elements, got %d", len(elems))
				}
				// First should be sequence
				if !elems[0].IsSequence {
					t.Error("first element should be sequence")
				}
				if len(elems[0].Sequence) != 2 {
					t.Errorf("sequence should have 2 positions, got %d", len(elems[0].Sequence))
				}
				// Second should be string
				if elems[1].IsSequence {
					t.Error("second element should be string, not sequence")
				}
				if elems[1].Pattern != "re:^--help$" {
					t.Errorf("expected pattern 're:^--help$', got %q", elems[1].Pattern)
				}
			},
		},
		{
			name: "sequence with enum values",
			config: `
[[rule]]
command = "openssl"
action = "allow"
[rule.args]
all_match = [
    { "0" = "-in", "1" = ["glob:*.pem", "glob:*.crt"] }
]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Rules) != 1 {
					t.Fatal("expected 1 rule")
				}
				elems := cfg.Rules[0].Args.AllMatch
				if len(elems) != 1 {
					t.Fatalf("expected 1 all_match element, got %d", len(elems))
				}
				if !elems[0].IsSequence {
					t.Fatal("element should be sequence")
				}
				fp, ok := elems[0].Sequence["1"]
				if !ok {
					t.Fatal("expected position 1 in sequence")
				}
				if len(fp.Patterns) != 2 {
					t.Errorf("expected 2 patterns, got %d", len(fp.Patterns))
				}
			},
		},
		{
			name: "invalid sequence position key",
			config: `
[[rule]]
command = "test"
action = "deny"
[rule.args]
any_match = [
    { "abc" = "-i" }
]
`,
			wantErr: "is not a valid integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.config)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.verify != nil {
				tt.verify(t, cfg)
			}
		})
	}
}
