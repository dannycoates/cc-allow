package main

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config represents the complete configuration for cc-allow.
type Config struct {
	Policy    PolicyConfig    `toml:"policy"`
	Commands  CommandsConfig  `toml:"commands"`
	Rules     []Rule          `toml:"rule"`
	Redirects []RedirectRule  `toml:"redirect"`
	Constructs ConstructsConfig `toml:"constructs"`
}

// PolicyConfig defines the default behavior when no rules match.
type PolicyConfig struct {
	Default         string `toml:"default"`          // "allow", "deny", or "pass" (default: "pass")
	DynamicCommands string `toml:"dynamic_commands"` // how to handle $VAR or $(cmd) as command names
	DefaultMessage  string `toml:"default_message"`  // fallback message when rule has no message
}

// CommandsConfig provides quick lists for common allow/deny patterns.
type CommandsConfig struct {
	Deny  CommandList `toml:"deny"`
	Allow CommandList `toml:"allow"`
}

// CommandList is a simple list of command names with an optional shared message.
type CommandList struct {
	Names   []string `toml:"names"`
	Message string   `toml:"message"`
}

// Rule represents a detailed command rule with argument matching.
type Rule struct {
	Command string      `toml:"command"` // command name or "*" for any
	Action  string      `toml:"action"`  // "allow" or "deny"
	Message string      `toml:"message"` // custom message for denials
	Args    ArgsMatch   `toml:"args"`    // argument matching options
	Pipe    PipeContext `toml:"pipe"`    // pipe context rules
}

// ArgsMatch provides different ways to match command arguments.
type ArgsMatch struct {
	Contains []string          `toml:"contains"`   // literal substring matches
	AnyMatch []string          `toml:"any_match"`  // any arg matches pattern (glob/regex)
	AllMatch []string          `toml:"all_match"`  // all patterns must match some arg
	Position map[int]string    `toml:"position"`   // specific positional arg matching
}

// PipeContext specifies rules about what a command can pipe to.
type PipeContext struct {
	To []string `toml:"to"` // deny if piped to any of these commands
}

// RedirectRule controls output/input redirection.
type RedirectRule struct {
	Action  string         `toml:"action"`  // "allow" or "deny"
	Message string         `toml:"message"` // custom message
	To      RedirectTarget `toml:"to"`      // target matching
	Append  *bool          `toml:"append"`  // if set, only applies to >> (append mode)
}

// RedirectTarget specifies how to match redirect destinations.
type RedirectTarget struct {
	Pattern []string `toml:"pattern"` // glob/regex patterns
	Exact   []string `toml:"exact"`   // exact filename matches
}

// ConstructsConfig controls handling of shell constructs.
type ConstructsConfig struct {
	Subshells           string `toml:"subshells"`            // "allow" or "deny"
	FunctionDefinitions string `toml:"function_definitions"` // "allow" or "deny"
	Background          string `toml:"background"`           // "allow" or "deny"
}

// LoadConfig reads and parses a TOML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(data))
}

// ParseConfig parses a TOML configuration string.
func ParseConfig(data string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, err
	}
	// Set defaults
	if cfg.Policy.Default == "" {
		cfg.Policy.Default = "pass"
	}
	if cfg.Policy.DynamicCommands == "" {
		cfg.Policy.DynamicCommands = "pass"
	}
	if cfg.Policy.DefaultMessage == "" {
		cfg.Policy.DefaultMessage = "Command not allowed"
	}
	if cfg.Constructs.Subshells == "" {
		cfg.Constructs.Subshells = "pass"
	}
	if cfg.Constructs.FunctionDefinitions == "" {
		cfg.Constructs.FunctionDefinitions = "pass"
	}
	if cfg.Constructs.Background == "" {
		cfg.Constructs.Background = "pass"
	}
	return &cfg, nil
}

// DefaultConfig returns a minimal default configuration.
func DefaultConfig() *Config {
	return &Config{
		Policy: PolicyConfig{
			Default:         "pass",
			DynamicCommands: "pass",
			DefaultMessage:  "Command not allowed",
		},
		Constructs: ConstructsConfig{
			Subshells:           "pass",
			FunctionDefinitions: "pass",
			Background:          "pass",
		},
	}
}

// ConfigChain holds multiple configs ordered from highest to lowest priority.
// Lower configs can only make things stricter, not looser.
type ConfigChain struct {
	Configs []*Config // ordered: global (~/), project (.claude/), explicit (--config)
}

// LoadConfigChain loads configs from standard locations plus an optional explicit path.
// Order (highest to lowest, stricter overrides): ~/.config/cc-allow.toml, .claude/cc-allow.toml, --config
func LoadConfigChain(explicitPath string) (*ConfigChain, error) {
	chain := &ConfigChain{}

	// 1. Load global config (~/.config/cc-allow.toml)
	if globalPath := findGlobalConfig(); globalPath != "" {
		cfg, err := LoadConfig(globalPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 2. Load project config (.claude/cc-allow.toml)
	if projectPath := findProjectConfig(); projectPath != "" {
		cfg, err := LoadConfig(projectPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 3. Load explicit config (--config flag)
	if explicitPath != "" {
		cfg, err := LoadConfig(explicitPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// If no configs found, use default
	if len(chain.Configs) == 0 {
		chain.Configs = append(chain.Configs, DefaultConfig())
	}

	return chain, nil
}

// findGlobalConfig looks for ~/.config/cc-allow.toml
func findGlobalConfig() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".config", "cc-allow.toml")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

// findProjectConfig looks for .claude/cc-allow.toml starting from cwd and walking up.
func findProjectConfig() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		path := filepath.Join(dir, ".claude", "cc-allow.toml")
		if _, err := os.Stat(path); err == nil {
			return path
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root
			break
		}
		dir = parent
	}

	return ""
}
