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
any_match = ["re:^-[a-z]+$", "path:*.txt"]
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
position = { "0" = "re:^[0-7]{3,4}$", "1" = "path:*.txt" }
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
    { "0" = "-in", "1" = ["path:*.pem", "path:*.crt"] }
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

func TestParseNewFormatActionSections(t *testing.T) {
	// Test the new action-based sections format
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "bulk allow commands",
			config: `
[allow]
commands = ["ls", "cat", "grep"]
`,
			verify: func(t *testing.T, cfg *Config) {
				// Bulk commands are converted to rules
				found := 0
				for _, rule := range cfg.Rules {
					if rule.Action == "allow" && (rule.Command == "ls" || rule.Command == "cat" || rule.Command == "grep") {
						found++
					}
				}
				if found != 3 {
					t.Errorf("expected 3 allow rules from bulk commands, got %d", found)
				}
			},
		},
		{
			name: "bulk deny commands with message",
			config: `
[deny]
commands = ["sudo", "su"]
message = "Privilege escalation blocked"
`,
			verify: func(t *testing.T, cfg *Config) {
				found := 0
				for _, rule := range cfg.Rules {
					if rule.Action == "deny" && (rule.Command == "sudo" || rule.Command == "su") {
						found++
						if rule.Message != "Privilege escalation blocked" {
							t.Errorf("expected shared message, got %q", rule.Message)
						}
					}
				}
				if found != 2 {
					t.Errorf("expected 2 deny rules from bulk commands, got %d", found)
				}
			},
		},
		{
			name: "nested command rule [[deny.rm]]",
			config: `
[[deny.rm]]
message = "rm denied"
args.any_match = ["flags:r"]
`,
			verify: func(t *testing.T, cfg *Config) {
				found := false
				for _, rule := range cfg.Rules {
					if rule.Command == "rm" && rule.Action == "deny" {
						found = true
						if len(rule.Args.AnyMatch) != 1 {
							t.Errorf("expected 1 any_match, got %d", len(rule.Args.AnyMatch))
						}
						if rule.Args.AnyMatch[0].Pattern != "flags:r" {
							t.Errorf("expected pattern 'flags:r', got %q", rule.Args.AnyMatch[0].Pattern)
						}
					}
				}
				if !found {
					t.Error("expected [[deny.rm]] rule")
				}
			},
		},
		{
			name: "positional nesting [[deny.git.push]]",
			config: `
[[deny.git.push]]
message = "force push not allowed"
args.any_match = ["--force"]
`,
			verify: func(t *testing.T, cfg *Config) {
				found := false
				for _, rule := range cfg.Rules {
					if rule.Command == "git" && rule.Action == "deny" {
						found = true
						// Should have position.0 = "push" from nesting
						if rule.Args.Position == nil {
							t.Fatal("expected position map from nesting")
						}
						if fp, ok := rule.Args.Position["0"]; !ok || len(fp.Patterns) == 0 || fp.Patterns[0] != "push" {
							t.Errorf("expected position.0 = 'push', got %+v", rule.Args.Position)
						}
					}
				}
				if !found {
					t.Error("expected [[deny.git.push]] rule")
				}
			},
		},
		{
			name: "deep nesting [[allow.docker.compose.up]]",
			config: `
[[allow.docker.compose.up]]
`,
			verify: func(t *testing.T, cfg *Config) {
				found := false
				for _, rule := range cfg.Rules {
					if rule.Command == "docker" && rule.Action == "allow" {
						found = true
						if rule.Args.Position == nil {
							t.Fatal("expected position map from nesting")
						}
						// Should have position.0 = "compose", position.1 = "up"
						if fp, ok := rule.Args.Position["0"]; !ok || len(fp.Patterns) == 0 || fp.Patterns[0] != "compose" {
							t.Errorf("expected position.0 = 'compose', got %+v", rule.Args.Position)
						}
						if fp, ok := rule.Args.Position["1"]; !ok || len(fp.Patterns) == 0 || fp.Patterns[0] != "up" {
							t.Errorf("expected position.1 = 'up', got %+v", rule.Args.Position)
						}
					}
				}
				if !found {
					t.Error("expected [[allow.docker.compose.up]] rule")
				}
			},
		},
		{
			name: "multiple rules same command",
			config: `
[[allow.rm]]
# base allow

[[deny.rm]]
args.any_match = ["flags:r"]
`,
			verify: func(t *testing.T, cfg *Config) {
				allowCount := 0
				denyCount := 0
				for _, rule := range cfg.Rules {
					if rule.Command == "rm" {
						if rule.Action == "allow" {
							allowCount++
						} else if rule.Action == "deny" {
							denyCount++
						}
					}
				}
				if allowCount != 1 || denyCount != 1 {
					t.Errorf("expected 1 allow and 1 deny for rm, got allow=%d deny=%d", allowCount, denyCount)
				}
			},
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

func TestParsePathAliases(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "single string alias",
			config: `
[paths]
project = "path:$PROJECT_ROOT/**"

[files.read]
allow = ["alias:project"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Files.Read.Allow) != 1 {
					t.Fatalf("expected 1 allow pattern, got %d", len(cfg.Files.Read.Allow))
				}
				// Alias should be expanded
				if cfg.Files.Read.Allow[0] != "path:$PROJECT_ROOT/**" {
					t.Errorf("expected expanded alias, got %q", cfg.Files.Read.Allow[0])
				}
			},
		},
		{
			name: "array alias",
			config: `
[paths]
safe = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]

[files.write]
allow = ["alias:safe"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Files.Write.Allow) != 2 {
					t.Fatalf("expected 2 allow patterns from array alias, got %d", len(cfg.Files.Write.Allow))
				}
				if cfg.Files.Write.Allow[0] != "path:$PROJECT_ROOT/**" {
					t.Errorf("expected first pattern 'path:$PROJECT_ROOT/**', got %q", cfg.Files.Write.Allow[0])
				}
				if cfg.Files.Write.Allow[1] != "path:/tmp/**" {
					t.Errorf("expected second pattern 'path:/tmp/**', got %q", cfg.Files.Write.Allow[1])
				}
			},
		},
		{
			name: "alias in rule args",
			config: `
[paths]
project = "path:$PROJECT_ROOT/**"

[[allow.rm]]
args.any_match = ["alias:project"]
`,
			verify: func(t *testing.T, cfg *Config) {
				found := false
				for _, rule := range cfg.Rules {
					if rule.Command == "rm" && rule.Action == "allow" {
						found = true
						if len(rule.Args.AnyMatch) != 1 {
							t.Fatalf("expected 1 any_match, got %d", len(rule.Args.AnyMatch))
						}
						// Alias should be expanded
						if rule.Args.AnyMatch[0].Pattern != "path:$PROJECT_ROOT/**" {
							t.Errorf("expected expanded alias, got %q", rule.Args.AnyMatch[0].Pattern)
						}
					}
				}
				if !found {
					t.Error("expected rm allow rule")
				}
			},
		},
		{
			name: "undefined alias error",
			config: `
[files.read]
allow = ["alias:undefined"]
`,
			wantErr: "undefined alias: undefined",
		},
		{
			name: "reserved prefix in alias name",
			config: `
[paths]
"path:foo" = "bar"
`,
			wantErr: "cannot start with a reserved prefix",
		},
		{
			name: "alias in allow.commands",
			config: `
[paths]
plugin-bin = "path:$CLAUDE_PLUGIN_ROOT/**"

[allow]
commands = ["alias:plugin-bin", "ls"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Allow.Commands) != 2 {
					t.Fatalf("expected 2 commands, got %d", len(cfg.Allow.Commands))
				}
				if cfg.Allow.Commands[0] != "path:$CLAUDE_PLUGIN_ROOT/**" {
					t.Errorf("expected expanded alias, got %q", cfg.Allow.Commands[0])
				}
				if cfg.Allow.Commands[1] != "ls" {
					t.Errorf("expected 'ls', got %q", cfg.Allow.Commands[1])
				}
			},
		},
		{
			name: "alias in redirect pattern",
			config: `
[paths]
project = "path:$PROJECT_ROOT/**"

[[redirect]]
action = "allow"
[redirect.to]
pattern = ["alias:project"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Redirects) != 1 {
					t.Fatalf("expected 1 redirect, got %d", len(cfg.Redirects))
				}
				if len(cfg.Redirects[0].To.Pattern) != 1 {
					t.Fatalf("expected 1 pattern, got %d", len(cfg.Redirects[0].To.Pattern))
				}
				if cfg.Redirects[0].To.Pattern[0] != "path:$PROJECT_ROOT/**" {
					t.Errorf("expected expanded alias, got %q", cfg.Redirects[0].To.Pattern[0])
				}
			},
		},
		{
			name: "array alias in deny.commands",
			config: `
[paths]
dangerous = ["sudo", "su", "doas"]

[deny]
commands = ["alias:dangerous"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Deny.Commands) != 3 {
					t.Fatalf("expected 3 commands from array alias, got %d", len(cfg.Deny.Commands))
				}
				expected := []string{"sudo", "su", "doas"}
				for i, exp := range expected {
					if cfg.Deny.Commands[i] != exp {
						t.Errorf("commands[%d]: expected %q, got %q", i, exp, cfg.Deny.Commands[i])
					}
				}
			},
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

func TestConfigVersion(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "no version (legacy)",
			config: `
[policy]
default = "ask"
`,
			wantErr: "",
		},
		{
			name: "valid version 1.0",
			config: `
version = "1.0"

[policy]
default = "ask"
`,
			wantErr: "",
		},
		{
			name: "valid version 0.9 (older)",
			config: `
version = "0.9"

[policy]
default = "ask"
`,
			wantErr: "",
		},
		{
			name: "unsupported major version",
			config: `
version = "2.0"

[policy]
default = "ask"
`,
			wantErr: "not supported",
		},
		{
			name: "unsupported minor version",
			config: `
version = "1.5"

[policy]
default = "ask"
`,
			wantErr: "not supported",
		},
		{
			name: "invalid version format - single number",
			config: `
version = "1"

[policy]
default = "ask"
`,
			wantErr: "invalid version format",
		},
		{
			name: "invalid version format - too many parts",
			config: `
version = "1.0.0"

[policy]
default = "ask"
`,
			wantErr: "invalid version format",
		},
		{
			name: "invalid version format - non-numeric major",
			config: `
version = "a.0"

[policy]
default = "ask"
`,
			wantErr: "invalid version major",
		},
		{
			name: "invalid version format - non-numeric minor",
			config: `
version = "1.b"

[policy]
default = "ask"
`,
			wantErr: "invalid version minor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(tt.config)
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
		})
	}
}
