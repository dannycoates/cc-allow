package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config represents the complete configuration for cc-allow.
type Config struct {
	Path       string           `toml:"-"` // path this config was loaded from (not in TOML)
	Policy     PolicyConfig     `toml:"policy"`
	Commands   CommandsConfig   `toml:"commands"`
	Rules      []Rule           `toml:"rule"`
	Redirects  []RedirectRule   `toml:"redirect"`
	Heredocs   []HeredocRule    `toml:"heredoc"`
	Constructs ConstructsConfig `toml:"constructs"`
	Debug      DebugConfig      `toml:"debug"`
}

// DebugConfig controls debug logging behavior.
type DebugConfig struct {
	LogFile string `toml:"log_file"` // path to debug log file (default: $TMPDIR/cc-allow.log)
}

// PolicyConfig defines the default behavior when no rules match.
type PolicyConfig struct {
	Default         string `toml:"default"`          // "allow", "deny", or "ask" (default: "ask")
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

// PipeContext specifies rules about pipe relationships.
type PipeContext struct {
	To   []string `toml:"to"`   // deny if piped to any of these commands (immediate)
	From []string `toml:"from"` // deny if receiving piped input from any of these (or "*" for any)
}

// Specificity scoring constants for CSS-like rule matching.
const (
	specificityCommand      = 100 // named command (vs "*" wildcard)
	specificityPositionArg  = 20  // each args.position entry
	specificityContainsArg  = 10  // each args.contains entry
	specificityPatternArg   = 5   // each args.any_match or args.all_match entry
	specificityPipeNamed    = 10  // each named pipe.to or pipe.from entry
	specificityPipeWildcard = 5   // pipe.from = ["*"]
	specificityExact        = 10  // each exact match entry
	specificityPattern      = 5   // each pattern entry
	specificityAppend       = 5   // append mode specified
	specificityContentMatch = 10  // each content match pattern
)

// Specificity computes a CSS-like specificity score for a command rule.
func (r Rule) Specificity() int {
	score := 0

	if r.Command != "*" {
		score += specificityCommand
	}

	score += len(r.Args.Position) * specificityPositionArg
	score += len(r.Args.Contains) * specificityContainsArg
	score += len(r.Args.AnyMatch) * specificityPatternArg
	score += len(r.Args.AllMatch) * specificityPatternArg

	score += len(r.Pipe.To) * specificityPipeNamed
	for _, from := range r.Pipe.From {
		if from == "*" {
			score += specificityPipeWildcard
		} else {
			score += specificityPipeNamed
		}
	}

	return score
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

// Specificity computes a specificity score for a redirect rule.
func (r RedirectRule) Specificity() int {
	score := 0
	score += len(r.To.Exact) * specificityExact
	score += len(r.To.Pattern) * specificityPattern
	if r.Append != nil {
		score += specificityAppend
	}
	return score
}

// HeredocRule controls heredoc (<<EOF) handling.
type HeredocRule struct {
	Action       string   `toml:"action"`        // "allow", "deny", or "ask"
	Message      string   `toml:"message"`       // custom message
	ContentMatch []string `toml:"content_match"` // patterns to match against heredoc body
}

// Specificity computes a specificity score for a heredoc rule.
func (r HeredocRule) Specificity() int {
	return len(r.ContentMatch) * specificityContentMatch
}

// ConstructsConfig controls handling of shell constructs.
type ConstructsConfig struct {
	Subshells           string `toml:"subshells"`            // "allow", "deny", or "ask"
	FunctionDefinitions string `toml:"function_definitions"` // "allow", "deny", or "ask"
	Background          string `toml:"background"`           // "allow", "deny", or "ask"
	Heredocs            string `toml:"heredocs"`             // "allow", "deny", or "ask"
}

// LoadConfig reads and parses a TOML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(string(data))
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	return cfg, nil
}

// ParseConfig parses a TOML configuration string.
func ParseConfig(data string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, err
	}
	// Set defaults
	if cfg.Policy.Default == "" {
		cfg.Policy.Default = "ask"
	}
	if cfg.Policy.DynamicCommands == "" {
		cfg.Policy.DynamicCommands = "ask"
	}
	if cfg.Policy.DefaultMessage == "" {
		cfg.Policy.DefaultMessage = "Command not allowed"
	}
	if cfg.Constructs.Subshells == "" {
		cfg.Constructs.Subshells = "ask"
	}
	if cfg.Constructs.FunctionDefinitions == "" {
		cfg.Constructs.FunctionDefinitions = "ask"
	}
	if cfg.Constructs.Background == "" {
		cfg.Constructs.Background = "ask"
	}
	if cfg.Constructs.Heredocs == "" {
		cfg.Constructs.Heredocs = "allow"
	}
	// Validate all patterns
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that all patterns in the config are valid.
// This catches invalid regex patterns at load time rather than at evaluation time.
func (cfg *Config) Validate() error {
	// Validate command rules
	for i, rule := range cfg.Rules {
		if len(rule.Args.AnyMatch) > 0 {
			if _, err := NewMatcher(rule.Args.AnyMatch); err != nil {
				return fmt.Errorf("rule[%d] (command=%q): invalid args.any_match pattern: %w", i, rule.Command, err)
			}
		}
		if len(rule.Args.AllMatch) > 0 {
			if _, err := NewMatcher(rule.Args.AllMatch); err != nil {
				return fmt.Errorf("rule[%d] (command=%q): invalid args.all_match pattern: %w", i, rule.Command, err)
			}
		}
		for pos, pattern := range rule.Args.Position {
			if _, err := ParsePattern(pattern); err != nil {
				return fmt.Errorf("rule[%d] (command=%q): invalid args.position[%d] pattern: %w", i, rule.Command, pos, err)
			}
		}
	}

	// Validate redirect rules
	for i, rule := range cfg.Redirects {
		if len(rule.To.Pattern) > 0 {
			if _, err := NewMatcher(rule.To.Pattern); err != nil {
				return fmt.Errorf("redirect[%d]: invalid to.pattern: %w", i, err)
			}
		}
	}

	// Validate heredoc rules
	for i, rule := range cfg.Heredocs {
		if len(rule.ContentMatch) > 0 {
			if _, err := NewMatcher(rule.ContentMatch); err != nil {
				return fmt.Errorf("heredoc[%d]: invalid content_match pattern: %w", i, err)
			}
		}
	}

	return nil
}

// DefaultConfig returns a minimal default configuration.
func DefaultConfig() *Config {
	return &Config{
		Path: "(default)",
		Policy: PolicyConfig{
			Default:         "ask",
			DynamicCommands: "ask",
			DefaultMessage:  "Command not allowed",
		},
		Constructs: ConstructsConfig{
			Subshells:           "ask",
			FunctionDefinitions: "ask",
			Background:          "ask",
			Heredocs:            "allow",
		},
	}
}

// ConfigChain holds multiple configs ordered from highest to lowest priority.
// Lower configs can only make things stricter, not looser.
type ConfigChain struct {
	Configs []*Config // ordered: global (~/), project (.claude/), project local (.claude/*.local.toml), explicit (--config)
}

// LoadConfigChain loads configs from standard locations plus an optional explicit path.
// Order (loosest to strictest): ~/.config/cc-allow.toml, .claude/cc-allow.toml, .claude/cc-allow.local.toml, --config
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

	// 3. Load project local config (.claude/cc-allow.local.toml) - not in source control
	if localPath := findProjectLocalConfig(); localPath != "" {
		cfg, err := LoadConfig(localPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 4. Load explicit config (--config flag)
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

// findProjectLocalConfig looks for .claude/cc-allow.local.toml starting from cwd and walking up.
// This file is meant to be kept out of source control for local overrides.
func findProjectLocalConfig() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		path := filepath.Join(dir, ".claude", "cc-allow.local.toml")
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

// findProjectRoot looks for the project root directory.
// It walks up from cwd looking for:
// 1. .claude/ directory (preferred)
// 2. .git/ directory (fallback)
// Returns empty string if neither found.
func findProjectRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		// Check for .claude/ directory
		claudePath := filepath.Join(dir, ".claude")
		if info, err := os.Stat(claudePath); err == nil && info.IsDir() {
			return dir
		}

		// Check for .git/ directory
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return dir
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
