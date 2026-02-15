package main

import (
	"errors"
	"os"
	"path/filepath"
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
					if rule.Command == "rm" && rule.Action == ActionDeny {
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
					if rule.Command == "git" && rule.Action == ActionDeny && len(rule.Subcommands) == 1 && rule.Subcommands[0] == "push" {
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
					if rule.Command == "docker" && rule.Action == ActionAllow {
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
project-bin = "path:$PROJECT_ROOT/bin/**"

[bash.allow]
commands = ["alias:project-bin", "ls"]
`,
			verify: func(t *testing.T, cfg *Config) {
				if len(cfg.Bash.Allow.Commands) != 2 {
					t.Fatalf("expected 2 commands, got %d", len(cfg.Bash.Allow.Commands))
				}
				if cfg.Bash.Allow.Commands[0] != "path:$PROJECT_ROOT/bin/**" {
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

func TestFindAgentConfig(t *testing.T) {
	t.Setenv("CC_PROJECT_DIR", "")

	t.Run("finds agent config in .config/cc-allow/", func(t *testing.T) {
		tmp := t.TempDir()
		t.Chdir(tmp)

		// Create .git as project root marker
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		agentDir := filepath.Join(tmp, ".config", "cc-allow")
		if err := os.MkdirAll(agentDir, 0755); err != nil {
			t.Fatal(err)
		}
		agentFile := filepath.Join(agentDir, "playwright.toml")
		if err := os.WriteFile(agentFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findAgentConfig("playwright")
		if got != agentFile {
			t.Errorf("findAgentConfig(\"playwright\") = %q, want %q", got, agentFile)
		}
	})

	t.Run("returns empty when agent config not found", func(t *testing.T) {
		tmp := t.TempDir()
		t.Chdir(tmp)

		// Create .git as project root marker
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		got := findAgentConfig("nonexistent")
		if got != "" {
			t.Errorf("findAgentConfig(\"nonexistent\") = %q, want empty string", got)
		}
	})

	t.Run("returns empty when no project root exists", func(t *testing.T) {
		tmp := t.TempDir()
		t.Chdir(tmp)

		// No project root marker - should return empty even if config exists
		agentDir := filepath.Join(tmp, ".config", "cc-allow")
		if err := os.MkdirAll(agentDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(agentDir, "myagent.toml"), []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := findAgentConfig("myagent")
		if got != "" {
			t.Errorf("findAgentConfig(\"myagent\") = %q, want empty string (no project root)", got)
		}
	})

	t.Run("finds agent config in parent directory", func(t *testing.T) {
		tmp := t.TempDir()

		// Create .git as project root marker
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		agentDir := filepath.Join(tmp, ".config", "cc-allow")
		if err := os.MkdirAll(agentDir, 0755); err != nil {
			t.Fatal(err)
		}
		agentFile := filepath.Join(agentDir, "myagent.toml")
		if err := os.WriteFile(agentFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		subdir := filepath.Join(tmp, "src", "pkg")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(subdir)

		got := findAgentConfig("myagent")
		if got != agentFile {
			t.Errorf("findAgentConfig(\"myagent\") = %q, want %q", got, agentFile)
		}
	})
}

func TestFindProjectConfigsStopsAtProjectRoot(t *testing.T) {
	t.Setenv("CC_PROJECT_DIR", "")

	// This test verifies that findProjectConfigs() only searches within
	// the project boundary (up to project root) and doesn't walk beyond.

	t.Run("returns empty when no project root exists", func(t *testing.T) {
		// Create a temp dir with NO project markers (.git, .claude, cc-allow.toml)
		tmp := t.TempDir()

		// Create a subdir without any project markers and cd into it
		subdir := filepath.Join(tmp, "some", "random", "dir")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(subdir)

		// findProjectConfigs should return empty - no project root found
		result := findProjectConfigs()
		if result.ProjectConfig != "" {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want empty (no project root)", result.ProjectConfig)
		}
	})

	t.Run("finds config at project root with .git marker", func(t *testing.T) {
		tmp := t.TempDir()

		// Create .git directory as project root marker
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create project config
		configDir := filepath.Join(tmp, ".config")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			t.Fatal(err)
		}
		projectConfig := filepath.Join(configDir, "cc-allow.toml")
		if err := os.WriteFile(projectConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create a subdir and cd into it
		subdir := filepath.Join(tmp, "src", "pkg")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(subdir)

		// findProjectConfigs should find the config at project root
		result := findProjectConfigs()
		if result.ProjectConfig != projectConfig {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want %q", result.ProjectConfig, projectConfig)
		}
	})

	t.Run("finds config at project root with .git file (worktree)", func(t *testing.T) {
		tmp := t.TempDir()

		// Create .git as a FILE (like in a worktree) instead of directory
		gitFile := filepath.Join(tmp, ".git")
		if err := os.WriteFile(gitFile, []byte("gitdir: /some/path/.git/worktrees/name\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create project config
		configDir := filepath.Join(tmp, ".config")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			t.Fatal(err)
		}
		projectConfig := filepath.Join(configDir, "cc-allow.toml")
		if err := os.WriteFile(projectConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create a subdir and cd into it
		subdir := filepath.Join(tmp, "src", "pkg")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(subdir)

		// findProjectConfigs should find the config at project root (worktree)
		result := findProjectConfigs()
		if result.ProjectConfig != projectConfig {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want %q", result.ProjectConfig, projectConfig)
		}
	})

	t.Run("cc-allow config in parent takes priority over .git in child", func(t *testing.T) {
		tmp := t.TempDir()

		// Parent has .config/cc-allow.toml - this IS the project root for cc-allow
		parentConfigDir := filepath.Join(tmp, ".config")
		if err := os.MkdirAll(parentConfigDir, 0755); err != nil {
			t.Fatal(err)
		}
		parentConfig := filepath.Join(parentConfigDir, "cc-allow.toml")
		if err := os.WriteFile(parentConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Child has .git (e.g., submodule) but no cc-allow config
		projectDir := filepath.Join(tmp, "myproject")
		if err := os.MkdirAll(filepath.Join(projectDir, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// cd into the child project
		t.Chdir(projectDir)

		// findProjectConfigs should find the parent config because
		// .config/cc-allow.toml is a stronger project root signal than .git
		result := findProjectConfigs()
		if result.ProjectConfig != parentConfig {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want %q", result.ProjectConfig, parentConfig)
		}
	})

	t.Run("stops at .git when no cc-allow config exists above", func(t *testing.T) {
		tmp := t.TempDir()

		// Parent has .git but NO cc-allow config
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// Child also has .git
		projectDir := filepath.Join(tmp, "child")
		if err := os.MkdirAll(filepath.Join(projectDir, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// cd into the child project
		t.Chdir(projectDir)

		// findProjectConfigs should return empty - project root is child (first .git),
		// and there's no cc-allow config at child level
		result := findProjectConfigs()
		if result.ProjectConfig != "" {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want empty", result.ProjectConfig)
		}
	})

	t.Run("finds config in subdir when project root is above", func(t *testing.T) {
		tmp := t.TempDir()

		// Create .git at top level (project root)
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create config in a subdir of the project
		subConfigDir := filepath.Join(tmp, "packages", "foo", ".config")
		if err := os.MkdirAll(subConfigDir, 0755); err != nil {
			t.Fatal(err)
		}
		subConfig := filepath.Join(subConfigDir, "cc-allow.toml")
		if err := os.WriteFile(subConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// cd into that subdir
		t.Chdir(filepath.Join(tmp, "packages", "foo"))

		// findProjectConfigs should find the config in current dir
		result := findProjectConfigs()
		if result.ProjectConfig != subConfig {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want %q", result.ProjectConfig, subConfig)
		}
	})

	t.Run("finds parent config and session from submodule with own .git", func(t *testing.T) {
		// Simulates: project with .config/cc-allow.toml + .git at root,
		// and a submodule subdirectory with its own .git.
		// When running from the submodule, the parent's config and session
		// should still be found.
		tmp := t.TempDir()

		// Parent project: has .git and .config/cc-allow.toml
		if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		parentConfigDir := filepath.Join(tmp, ".config")
		if err := os.MkdirAll(parentConfigDir, 0755); err != nil {
			t.Fatal(err)
		}
		parentConfig := filepath.Join(parentConfigDir, "cc-allow.toml")
		if err := os.WriteFile(parentConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Session config at project root
		sessionDir := filepath.Join(tmp, ".config", "cc-allow", "sessions")
		if err := os.MkdirAll(sessionDir, 0755); err != nil {
			t.Fatal(err)
		}
		sessionFile := filepath.Join(sessionDir, "test-session.toml")
		if err := os.WriteFile(sessionFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Submodule: has its own .git
		submodule := filepath.Join(tmp, "submodule")
		if err := os.MkdirAll(filepath.Join(submodule, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// cd into the submodule
		t.Chdir(submodule)

		// findProjectRoot should return the parent (has .config/cc-allow.toml)
		projectRoot := findProjectRoot()
		if projectRoot != tmp {
			t.Errorf("findProjectRoot() = %q, want %q", projectRoot, tmp)
		}

		// findProjectConfigs should find the parent's config
		result := findProjectConfigs()
		if result.ProjectConfig != parentConfig {
			t.Errorf("findProjectConfigs() returned ProjectConfig = %q, want %q", result.ProjectConfig, parentConfig)
		}

		// findSessionConfig should find the session at project root
		sessionPath := findSessionConfig("test-session", projectRoot)
		if sessionPath != sessionFile {
			t.Errorf("findSessionConfig() = %q, want %q", sessionPath, sessionFile)
		}
	})
}

func TestLoadConfigChainDeduplicatesGlobalConfig(t *testing.T) {
	// This test verifies that when $HOME is a project root (e.g., has .git for dotfiles),
	// the global config at ~/.config/cc-allow.toml is not loaded twice.

	t.Run("does not load global config twice when HOME has .git", func(t *testing.T) {
		// Create a fake HOME directory
		fakeHome := t.TempDir()
		t.Setenv("HOME", fakeHome)
		t.Setenv("CC_PROJECT_DIR", "")

		// Create .git at HOME (simulating dotfiles repo)
		if err := os.MkdirAll(filepath.Join(fakeHome, ".git"), 0755); err != nil {
			t.Fatal(err)
		}

		// Create global config at ~/.config/cc-allow.toml
		configDir := filepath.Join(fakeHome, ".config")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			t.Fatal(err)
		}
		globalConfig := filepath.Join(configDir, "cc-allow.toml")
		if err := os.WriteFile(globalConfig, []byte("version = \"2.0\"\n"), 0644); err != nil {
			t.Fatal(err)
		}

		// Create a subdir and cd into it
		subdir := filepath.Join(fakeHome, "projects", "test")
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(subdir)

		// Load config chain
		chain, err := LoadConfigChain("", "")
		if err != nil {
			t.Fatalf("LoadConfigChain() error = %v", err)
		}

		// Should only have one config loaded (the global one)
		if len(chain.Configs) != 1 {
			t.Errorf("LoadConfigChain() loaded %d configs, want 1 (global config should not be duplicated)", len(chain.Configs))
			for i, cfg := range chain.Configs {
				t.Logf("  config[%d]: %s", i, cfg.Path)
			}
		}
	})
}

func TestConfigValidationError(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		wantLocation string
		wantValue    string
	}{
		{
			name: "invalid action shows location and value",
			config: `
version = "2.0"
[bash]
default = "invalid_action"
`,
			wantLocation: "bash.default",
			wantValue:    "invalid_action",
		},
		{
			name: "invalid pattern shows location and value",
			config: `
version = "2.0"
[bash.allow]
commands = ["re:[unclosed"]
`,
			wantLocation: "bash.allow.commands[0]",
			wantValue:    "re:[unclosed",
		},
		{
			name: "invalid mode shows location and value",
			config: `
version = "2.0"
[bash.allow]
mode = "invalid_mode"
`,
			wantLocation: "bash.allow.mode",
			wantValue:    "invalid_mode",
		},
		{
			name: "alias with reserved prefix shows location",
			config: `
version = "2.0"
[aliases]
"path:foo" = "bar"
`,
			wantLocation: "aliases.path:foo",
			wantValue:    "path:foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigWithDefaults(tt.config)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			// Check that error is a ConfigValidationError
			var valErr *ConfigValidationError
			if !errors.As(err, &valErr) {
				t.Fatalf("expected ConfigValidationError, got %T: %v", err, err)
			}

			// Check location
			if valErr.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", valErr.Location, tt.wantLocation)
			}

			// Check value
			if valErr.Value != tt.wantValue {
				t.Errorf("Value = %q, want %q", valErr.Value, tt.wantValue)
			}

			// Check that error message contains key info
			errStr := err.Error()
			if !strings.Contains(errStr, "invalid configuration") {
				t.Errorf("error should contain 'invalid configuration', got: %s", errStr)
			}
			if !strings.Contains(errStr, tt.wantLocation) {
				t.Errorf("error should contain location %q, got: %s", tt.wantLocation, errStr)
			}
			if !strings.Contains(errStr, tt.wantValue) {
				t.Errorf("error should contain value %q, got: %s", tt.wantValue, errStr)
			}
		})
	}
}

func TestConfigErrorWrapping(t *testing.T) {
	// Create a temp config file with invalid content
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "cc-allow.toml")
	err := os.WriteFile(configPath, []byte(`
version = "2.0"
[bash]
default = "invalid"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Load the config - should fail with wrapped error including path
	_, err = loadConfig(configPath)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Check that error is wrapped in ConfigError with path
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("expected ConfigError, got %T: %v", err, err)
	}

	if cfgErr.Path != configPath {
		t.Errorf("ConfigError.Path = %q, want %q", cfgErr.Path, configPath)
	}

	// Check that the underlying validation error is accessible
	var valErr *ConfigValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("expected to find ConfigValidationError in chain, got: %v", err)
	}

	if valErr.Location != "bash.default" {
		t.Errorf("ConfigValidationError.Location = %q, want %q", valErr.Location, "bash.default")
	}

	// Check that error message includes path
	errStr := err.Error()
	if !strings.Contains(errStr, configPath) {
		t.Errorf("error should contain config path %q, got: %s", configPath, errStr)
	}

	// Verify errors.Is still works
	if !errors.Is(err, ErrInvalidConfig) {
		t.Error("errors.Is(err, ErrInvalidConfig) should be true")
	}
}

func TestFindSessionConfig(t *testing.T) {
	tmpDir := t.TempDir()
	sessionsDir := filepath.Join(tmpDir, ".config", "cc-allow", "sessions")
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a session config
	sessionFile := filepath.Join(sessionsDir, "abc123.toml")
	if err := os.WriteFile(sessionFile, []byte("version = \"2.0\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Found
	if got := findSessionConfig("abc123", tmpDir); got != sessionFile {
		t.Errorf("findSessionConfig(abc123) = %q, want %q", got, sessionFile)
	}

	// Not found
	if got := findSessionConfig("nonexistent", tmpDir); got != "" {
		t.Errorf("findSessionConfig(nonexistent) = %q, want empty", got)
	}

	// Empty session ID
	if got := findSessionConfig("", tmpDir); got != "" {
		t.Errorf("findSessionConfig('') = %q, want empty", got)
	}

	// Empty project root
	if got := findSessionConfig("abc123", ""); got != "" {
		t.Errorf("findSessionConfig with empty root = %q, want empty", got)
	}

	// Path traversal rejected
	if got := findSessionConfig("../etc/passwd", tmpDir); got != "" {
		t.Errorf("findSessionConfig(../etc/passwd) = %q, want empty", got)
	}
	if got := findSessionConfig("foo/bar", tmpDir); got != "" {
		t.Errorf("findSessionConfig(foo/bar) = %q, want empty", got)
	}
	if got := findSessionConfig("foo\\bar", tmpDir); got != "" {
		t.Errorf("findSessionConfig(foo\\bar) = %q, want empty", got)
	}
}

func TestLoadConfigChainWithSessionConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create project config
	configDir := filepath.Join(tmpDir, ".config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	projectConfig := filepath.Join(configDir, "cc-allow.toml")
	if err := os.WriteFile(projectConfig, []byte("version = \"2.0\"\n[bash]\ndefault = \"ask\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create session config
	sessionsDir := filepath.Join(configDir, "cc-allow", "sessions")
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	sessionConfig := filepath.Join(sessionsDir, "test-session.toml")
	if err := os.WriteFile(sessionConfig, []byte("version = \"2.0\"\n[bash.allow]\ncommands = [\"docker\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set project root and cd into the project
	t.Setenv("CC_PROJECT_DIR", tmpDir)
	t.Chdir(tmpDir)

	// Load with session
	chain, err := LoadConfigChain("", "test-session")
	if err != nil {
		t.Fatalf("LoadConfigChain() error = %v", err)
	}

	if chain.SessionID != "test-session" {
		t.Errorf("SessionID = %q, want %q", chain.SessionID, "test-session")
	}

	// Should have project + session configs
	foundSession := false
	for _, cfg := range chain.Configs {
		if cfg.Path == sessionConfig {
			foundSession = true
		}
	}
	if !foundSession {
		t.Error("session config not found in chain")
		for i, cfg := range chain.Configs {
			t.Logf("  config[%d]: %s", i, cfg.Path)
		}
	}

	// Load with nonexistent session - should gracefully skip
	chain2, err := LoadConfigChain("", "nonexistent")
	if err != nil {
		t.Fatalf("LoadConfigChain() with nonexistent session error = %v", err)
	}
	for _, cfg := range chain2.Configs {
		if strings.Contains(cfg.Path, "nonexistent") {
			t.Error("nonexistent session config should not be in chain")
		}
	}
}

func TestParseSettings(t *testing.T) {
	toml := `
version = "2.0"

[settings]
session_max_age = "7d"
`
	cfg, err := ParseConfigWithDefaults(toml)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults error: %v", err)
	}
	if cfg.Settings.SessionMaxAge != "7d" {
		t.Errorf("Settings.SessionMaxAge = %q, want %q", cfg.Settings.SessionMaxAge, "7d")
	}
}

func TestParseSettingsInvalidDuration(t *testing.T) {
	toml := `
version = "2.0"

[settings]
session_max_age = "invalid"
`
	_, err := ParseConfigWithDefaults(toml)
	if err == nil {
		t.Fatal("expected error for invalid session_max_age")
	}

	var valErr *ConfigValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("expected ConfigValidationError, got %T: %v", err, err)
	}
	if valErr.Location != "settings.session_max_age" {
		t.Errorf("Location = %q, want %q", valErr.Location, "settings.session_max_age")
	}
}

func TestMergeSettings(t *testing.T) {
	cfg1 := &Config{
		Path:    "config1.toml",
		Version: "2.0",
	}
	cfg2 := &Config{
		Path:    "config2.toml",
		Version: "2.0",
		Settings: SettingsConfig{
			SessionMaxAge: "7d",
		},
	}
	cfg3 := &Config{
		Path:    "config3.toml",
		Version: "2.0",
		Settings: SettingsConfig{
			SessionMaxAge: "14d",
		},
	}

	merged := MergeConfigs([]*Config{cfg1, cfg2, cfg3})
	if merged.Settings.SessionMaxAge != "14d" {
		t.Errorf("merged SessionMaxAge = %q, want %q", merged.Settings.SessionMaxAge, "14d")
	}

	// Later empty value shouldn't overwrite
	cfg4 := &Config{
		Path:    "config4.toml",
		Version: "2.0",
	}
	merged2 := MergeConfigs([]*Config{cfg2, cfg4})
	if merged2.Settings.SessionMaxAge != "7d" {
		t.Errorf("merged SessionMaxAge = %q, want %q (empty should not overwrite)", merged2.Settings.SessionMaxAge, "7d")
	}
}

func TestExtractConfigPath(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantPath string
	}{
		{
			name:     "ConfigError with path",
			err:      &ConfigError{Path: "/path/to/config.toml", Err: ErrInvalidConfig},
			wantPath: "/path/to/config.toml",
		},
		{
			name:     "ConfigError without path",
			err:      &ConfigError{Err: ErrInvalidConfig},
			wantPath: "",
		},
		{
			name:     "plain error",
			err:      errors.New("some error"),
			wantPath: "",
		},
		{
			name:     "nil error",
			err:      nil,
			wantPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractConfigPath(tt.err)
			if got != tt.wantPath {
				t.Errorf("extractConfigPath() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}
