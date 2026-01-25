package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseConfigWithDefaults(t *testing.T) {
	toml := `
version = "2.0"

[bash]
default = "deny"
dynamic_commands = "deny"
default_message = "Not allowed"

[bash.constructs]
function_definitions = "deny"

[bash.deny]
commands = ["rm", "rmdir"]
message = "Destructive commands not allowed"

[bash.allow]
commands = ["echo", "ls"]

[[bash.deny.curl]]
message = "No curl to shell"
pipe.to = ["bash", "sh"]

[[bash.allow.curl]]
`

	cfg, err := ParseConfigWithDefaults(toml)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults error: %v", err)
	}

	// Check policy
	if cfg.Bash.Default != "deny" {
		t.Errorf("expected bash.default=deny, got %s", cfg.Bash.Default)
	}
	if cfg.Bash.DynamicCommands != "deny" {
		t.Errorf("expected bash.dynamic_commands=deny, got %s", cfg.Bash.DynamicCommands)
	}

	// Check deny list
	if len(cfg.Bash.Deny.Commands) != 2 {
		t.Errorf("expected 2 deny commands, got %d", len(cfg.Bash.Deny.Commands))
	}
	if cfg.Bash.Deny.Message != "Destructive commands not allowed" {
		t.Errorf("unexpected deny message: %s", cfg.Bash.Deny.Message)
	}

	// Check allow list
	if len(cfg.Bash.Allow.Commands) != 2 {
		t.Errorf("expected 2 allow commands, got %d", len(cfg.Bash.Allow.Commands))
	}

	// Check parsed rules
	rules := cfg.getParsedRules()
	if len(rules) != 2 {
		t.Errorf("expected 2 parsed rules, got %d", len(rules))
	}

	// Check constructs
	if cfg.Bash.Constructs.FunctionDefinitions != "deny" {
		t.Errorf("expected function_definitions=deny, got %s", cfg.Bash.Constructs.FunctionDefinitions)
	}
}

func TestParsePipeContextStringFormat(t *testing.T) {
	// Test that pipe.to and pipe.from accept both string and array formats
	tests := []struct {
		name     string
		config   string
		wantTo   []string
		wantFrom []string
	}{
		{
			name: "pipe.to as string",
			config: `
[[bash.deny.curl]]
pipe.to = "bash"
`,
			wantTo: []string{"bash"},
		},
		{
			name: "pipe.to as array",
			config: `
[[bash.deny.curl]]
pipe.to = ["bash", "sh"]
`,
			wantTo: []string{"bash", "sh"},
		},
		{
			name: "pipe.from as string",
			config: `
[[bash.deny.bash]]
pipe.from = "curl"
`,
			wantFrom: []string{"curl"},
		},
		{
			name: "both as strings",
			config: `
[[bash.deny.cat]]
pipe.to = "bash"
pipe.from = "curl"
`,
			wantTo:   []string{"bash"},
			wantFrom: []string{"curl"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigWithDefaults(tt.config)
			if err != nil {
				t.Fatalf("ParseConfigWithDefaults error: %v", err)
			}
			rules := cfg.getParsedRules()
			if len(rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(rules))
			}
			rule := rules[0]
			if !slicesEqual(rule.Pipe.To, tt.wantTo) {
				t.Errorf("pipe.to = %v, want %v", rule.Pipe.To, tt.wantTo)
			}
			if !slicesEqual(rule.Pipe.From, tt.wantFrom) {
				t.Errorf("pipe.from = %v, want %v", rule.Pipe.From, tt.wantFrom)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Bash.Default != "ask" {
		t.Errorf("expected bash.default=ask, got %s", cfg.Bash.Default)
	}
	if cfg.Bash.DynamicCommands != "ask" {
		t.Errorf("expected bash.dynamic_commands=ask, got %s", cfg.Bash.DynamicCommands)
	}
	if cfg.Bash.Constructs.Subshells != "ask" {
		t.Errorf("expected bash.constructs.subshells=ask, got %s", cfg.Bash.Constructs.Subshells)
	}
}

func TestParseConfigWithDefaultsDefaults(t *testing.T) {
	// Minimal config
	cfg, err := ParseConfigWithDefaults("")
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults error: %v", err)
	}

	if cfg.Bash.Default != "ask" {
		t.Errorf("expected default bash.default=ask, got %s", cfg.Bash.Default)
	}
	if cfg.Bash.DefaultMessage != "Command not allowed" {
		t.Errorf("expected default message, got %s", cfg.Bash.DefaultMessage)
	}
}

func TestParseConfigWithDefaultsInvalidPatterns(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		wantErr        string
		wantPatternErr bool
	}{
		{
			name: "invalid regex in args.any",
			config: `
version = "2.0"
[[bash.deny.test]]
args.any = ["re:[invalid"]
`,
			wantErr:        "invalid configuration",
			wantPatternErr: true,
		},
		{
			name: "invalid regex in args.all",
			config: `
version = "2.0"
[[bash.deny.test]]
args.all = ["re:(unclosed"]
`,
			wantErr:        "invalid configuration",
			wantPatternErr: true,
		},
		{
			name: "invalid regex in args.position",
			config: `
version = "2.0"
[[bash.deny.test]]
args.position = { "0" = "re:(unclosed" }
`,
			wantErr:        "invalid configuration",
			wantPatternErr: true,
		},
		{
			name: "invalid regex in redirect paths",
			config: `
version = "2.0"
[[bash.redirects.deny]]
paths = ["re:[bad"]
`,
			wantErr:        "invalid configuration",
			wantPatternErr: true,
		},
		{
			name: "valid patterns should pass",
			config: `
version = "2.0"
[[bash.deny.test]]
args.any = ["re:^-[a-z]+$", "path:*.txt"]
`,
			wantErr: "",
		},
		{
			name: "valid args.position should pass",
			config: `
version = "2.0"
[[bash.allow.chmod]]
args.position = { "0" = "re:^[0-7]{3,4}$", "1" = "path:*.txt" }
`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigWithDefaults(tt.config)
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
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "position with array values (enum)",
			config: `
version = "2.0"
[[bash.allow.git]]
args.position = { "0" = ["status", "diff", "log"] }
`,
			verify: func(t *testing.T, cfg *Config) {
				rules := cfg.getParsedRules()
				if len(rules) != 1 {
					t.Fatal("expected 1 rule")
				}
				fp, ok := rules[0].Args.Position["0"]
				if !ok {
					t.Fatal("expected position 0")
				}
				if len(fp.Patterns) != 3 {
					t.Errorf("expected 3 patterns in position 0, got %d", len(fp.Patterns))
				}
			},
		},
		{
			name: "args.any with sequence objects",
			config: `
version = "2.0"
[[bash.allow.ffmpeg]]
args.any = [
    { "0" = "-i", "1" = "path:$HOME/**" },
    "re:^--help$"
]
`,
			verify: func(t *testing.T, cfg *Config) {
				rules := cfg.getParsedRules()
				if len(rules) != 1 {
					t.Fatal("expected 1 rule")
				}
				if rules[0].Args.Any == nil {
					t.Fatal("expected args.any to be set")
				}
				// Check that we have both sequence and pattern
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigWithDefaults(tt.config)
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
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "bulk allow commands",
			config: `
version = "2.0"
[bash.allow]
commands = ["ls", "cat", "grep"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Bash.Allow.Commands) != 3 {
					t.Errorf("expected 3 allow commands, got %d", len(cfg.Bash.Allow.Commands))
				}
			},
		},
		{
			name: "bulk deny commands with message",
			config: `
version = "2.0"
[bash.deny]
commands = ["sudo", "su"]
message = "Privilege escalation blocked"
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Bash.Deny.Commands) != 2 {
					t.Errorf("expected 2 deny commands, got %d", len(cfg.Bash.Deny.Commands))
				}
				if cfg.Bash.Deny.Message != "Privilege escalation blocked" {
					t.Errorf("expected shared message, got %q", cfg.Bash.Deny.Message)
				}
			},
		},
		{
			name: "nested command rule [[bash.deny.rm]]",
			config: `
version = "2.0"
[[bash.deny.rm]]
message = "rm denied"
args.any = ["flags:r"]
`,
			verify: func(t *testing.T, cfg *Config) {
				rules := cfg.getParsedRules()
				found := false
				for _, rule := range rules {
					if rule.Command == "rm" && rule.Action == "deny" {
						found = true
						if rule.Args.Any == nil {
							t.Error("expected args.any to be set")
						}
					}
				}
				if !found {
					t.Error("expected [[bash.deny.rm]] rule")
				}
			},
		},
		{
			name: "positional nesting [[bash.deny.git.push]]",
			config: `
version = "2.0"
[[bash.deny.git.push]]
message = "force push not allowed"
args.any = ["--force"]
`,
			verify: func(t *testing.T, cfg *Config) {
				rules := cfg.getParsedRules()
				found := false
				for _, rule := range rules {
					if rule.Command == "git" && rule.Action == "deny" && len(rule.Subcommands) == 1 && rule.Subcommands[0] == "push" {
						found = true
					}
				}
				if !found {
					t.Error("expected [[bash.deny.git.push]] rule")
				}
			},
		},
		{
			name: "deep nesting [[bash.allow.docker.compose.up]]",
			config: `
version = "2.0"
[[bash.allow.docker.compose.up]]
`,
			verify: func(t *testing.T, cfg *Config) {
				rules := cfg.getParsedRules()
				found := false
				for _, rule := range rules {
					if rule.Command == "docker" && rule.Action == "allow" {
						if len(rule.Subcommands) == 2 && rule.Subcommands[0] == "compose" && rule.Subcommands[1] == "up" {
							found = true
						}
					}
				}
				if !found {
					t.Error("expected [[bash.allow.docker.compose.up]] rule")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigWithDefaults(tt.config)
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

func TestParseAliases(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		verify  func(t *testing.T, cfg *Config)
		wantErr string
	}{
		{
			name: "single string alias",
			config: `
version = "2.0"
[aliases]
project = "path:$PROJECT_ROOT/**"

[read.allow]
paths = ["alias:project"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Read.Allow.Paths) != 1 {
					t.Fatalf("expected 1 allow path, got %d", len(cfg.Read.Allow.Paths))
				}
				// Alias should be expanded
				if cfg.Read.Allow.Paths[0] != "path:$PROJECT_ROOT/**" {
					t.Errorf("expected expanded alias, got %q", cfg.Read.Allow.Paths[0])
				}
			},
		},
		{
			name: "array alias",
			config: `
version = "2.0"
[aliases]
safe = ["path:$PROJECT_ROOT/**", "path:/tmp/**"]

[write.allow]
paths = ["alias:safe"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Write.Allow.Paths) != 2 {
					t.Fatalf("expected 2 allow paths from array alias, got %d", len(cfg.Write.Allow.Paths))
				}
				if cfg.Write.Allow.Paths[0] != "path:$PROJECT_ROOT/**" {
					t.Errorf("expected first pattern 'path:$PROJECT_ROOT/**', got %q", cfg.Write.Allow.Paths[0])
				}
				if cfg.Write.Allow.Paths[1] != "path:/tmp/**" {
					t.Errorf("expected second pattern 'path:/tmp/**', got %q", cfg.Write.Allow.Paths[1])
				}
			},
		},
		{
			name: "undefined alias error",
			config: `
version = "2.0"
[read.allow]
paths = ["alias:undefined"]
`,
			wantErr: "undefined alias: undefined",
		},
		{
			name: "reserved prefix in alias name",
			config: `
version = "2.0"
[aliases]
"path:foo" = "bar"
`,
			wantErr: "cannot start with a reserved prefix",
		},
		{
			name: "alias referencing another alias",
			config: `
version = "2.0"
[aliases]
base = "path:$PROJECT_ROOT/**"
extended = "alias:base"
`,
			wantErr: "aliases cannot reference other aliases",
		},
		{
			name: "alias array referencing another alias",
			config: `
version = "2.0"
[aliases]
base = "path:$PROJECT_ROOT/**"
extended = ["path:/tmp/**", "alias:base"]
`,
			wantErr: "aliases cannot reference other aliases",
		},
		{
			name: "alias in bash.allow.commands",
			config: `
version = "2.0"
[aliases]
plugin-bin = "path:$CLAUDE_PLUGIN_ROOT/**"

[bash.allow]
commands = ["alias:plugin-bin", "ls"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Bash.Allow.Commands) != 2 {
					t.Fatalf("expected 2 commands, got %d", len(cfg.Bash.Allow.Commands))
				}
				if cfg.Bash.Allow.Commands[0] != "path:$CLAUDE_PLUGIN_ROOT/**" {
					t.Errorf("expected expanded alias, got %q", cfg.Bash.Allow.Commands[0])
				}
				if cfg.Bash.Allow.Commands[1] != "ls" {
					t.Errorf("expected 'ls', got %q", cfg.Bash.Allow.Commands[1])
				}
			},
		},
		{
			name: "array alias in bash.deny.commands",
			config: `
version = "2.0"
[aliases]
dangerous = ["sudo", "su", "doas"]

[bash.deny]
commands = ["alias:dangerous"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Bash.Deny.Commands) != 3 {
					t.Fatalf("expected 3 commands from array alias, got %d", len(cfg.Bash.Deny.Commands))
				}
				expected := []string{"sudo", "su", "doas"}
				for i, exp := range expected {
					if cfg.Bash.Deny.Commands[i] != exp {
						t.Errorf("commands[%d]: expected %q, got %q", i, exp, cfg.Bash.Deny.Commands[i])
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigWithDefaults(tt.config)
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
			name: "valid version 2.0",
			config: `
version = "2.0"
`,
			wantErr: "",
		},
		{
			name: "legacy format detected",
			config: `
[policy]
default = "ask"
`,
			wantErr: "legacy",
		},
		{
			name: "legacy version 1.0",
			config: `
version = "1.0"
`,
			wantErr: "legacy",
		},
		{
			name: "unsupported future major version",
			config: `
version = "3.0"
`,
			wantErr: "not supported",
		},
		{
			name: "unsupported minor version",
			config: `
version = "2.5"
`,
			wantErr: "not supported",
		},
		{
			name: "invalid version format - single number",
			config: `
version = "2"
`,
			wantErr: "invalid version format",
		},
		{
			name: "invalid version format - too many parts",
			config: `
version = "2.0.0"
`,
			wantErr: "invalid version format",
		},
		{
			name: "invalid version format - non-numeric major",
			config: `
version = "a.0"
`,
			wantErr: "invalid version major",
		},
		{
			name: "invalid version format - non-numeric minor",
			config: `
version = "2.b"
`,
			wantErr: "invalid version minor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigWithDefaults(tt.config)
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

func TestInvalidActionValues(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "invalid bash.default",
			config: `
version = "2.0"
[bash]
default = "maybe"
`,
			wantErr: "bash.default: invalid action",
		},
		{
			name: "invalid bash.dynamic_commands",
			config: `
version = "2.0"
[bash]
dynamic_commands = "sometimes"
`,
			wantErr: "bash.dynamic_commands: invalid action",
		},
		{
			name: "invalid bash.unresolved_commands",
			config: `
version = "2.0"
[bash]
unresolved_commands = "block"
`,
			wantErr: "bash.unresolved_commands: invalid action",
		},
		{
			name: "invalid bash.constructs.subshells",
			config: `
version = "2.0"
[bash.constructs]
subshells = "permitted"
`,
			wantErr: "bash.constructs.subshells: invalid action",
		},
		{
			name: "invalid bash.constructs.background",
			config: `
version = "2.0"
[bash.constructs]
background = "no"
`,
			wantErr: "bash.constructs.background: invalid action",
		},
		{
			name: "invalid bash.constructs.function_definitions",
			config: `
version = "2.0"
[bash.constructs]
function_definitions = "yes"
`,
			wantErr: "bash.constructs.function_definitions: invalid action",
		},
		{
			name: "invalid bash.constructs.heredocs",
			config: `
version = "2.0"
[bash.constructs]
heredocs = "blocked"
`,
			wantErr: "bash.constructs.heredocs: invalid action",
		},
		{
			name: "invalid read.default",
			config: `
version = "2.0"
[read]
default = "permitted"
`,
			wantErr: "read.default: invalid action",
		},
		{
			name: "invalid write.default",
			config: `
version = "2.0"
[write]
default = "reject"
`,
			wantErr: "write.default: invalid action",
		},
		{
			name: "invalid edit.default",
			config: `
version = "2.0"
[edit]
default = "true"
`,
			wantErr: "edit.default: invalid action",
		},
		{
			name: "valid actions should pass",
			config: `
version = "2.0"
[bash]
default = "deny"
dynamic_commands = "ask"
unresolved_commands = "allow"

[bash.constructs]
subshells = "deny"
background = "ask"
function_definitions = "allow"
heredocs = "allow"

[read]
default = "allow"

[write]
default = "deny"

[edit]
default = "ask"
`,
			wantErr: "",
		},
		{
			name: "empty values are valid (use defaults)",
			config: `
version = "2.0"
`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigWithDefaults(tt.config)
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
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("expected errors.Is(err, ErrInvalidConfig) to be true")
			}
		})
	}
}
