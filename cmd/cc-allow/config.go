package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

// Config represents the complete configuration for cc-allow.
type Config struct {
	Path            string           `toml:"-"` // path this config was loaded from (not in TOML)
	Policy          PolicyConfig     `toml:"policy"`
	Commands        CommandsConfig   `toml:"commands"`
	Files           FilesConfig      `toml:"files"` // file tool permissions (Read, Edit, Write)
	Rules           []Rule           `toml:"rule"`
	RedirectsPolicy RedirectsConfig  `toml:"redirects"` // redirect policy settings
	Redirects       []RedirectRule   `toml:"redirect"`  // redirect rules
	Heredocs        []HeredocRule    `toml:"heredoc"`
	Constructs      ConstructsConfig `toml:"constructs"`
	Debug           DebugConfig      `toml:"debug"`
}

// DebugConfig controls debug logging behavior.
type DebugConfig struct {
	LogFile string `toml:"log_file"` // path to debug log file (default: $TMPDIR/cc-allow.log)
}

// PolicyConfig defines the default behavior when no rules match.
type PolicyConfig struct {
	Default            string   `toml:"default"`              // "allow", "deny", or "ask" (default: "ask")
	DynamicCommands    string   `toml:"dynamic_commands"`     // how to handle $VAR or $(cmd) as command names
	DefaultMessage     string   `toml:"default_message"`      // fallback message when rule has no message
	AllowedPaths       []string `toml:"allowed_paths"`        // directories to search for commands (defaults to $PATH)
	UnresolvedCommands string   `toml:"unresolved_commands"`  // "ask" or "deny" for commands not found
	RespectFileRules   *bool    `toml:"respect_file_rules"`   // if true, check file rules for command args (default: true)
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

// FilesConfig holds file tool permission settings for Read, Edit, and Write tools.
type FilesConfig struct {
	Default string         `toml:"default"` // "allow", "deny", or "ask" (default: "ask")
	Read    FileToolConfig `toml:"read"`
	Edit    FileToolConfig `toml:"edit"`
	Write   FileToolConfig `toml:"write"`
}

// FileToolConfig provides allow/deny lists for a specific file tool.
type FileToolConfig struct {
	Allow       []string `toml:"allow"`        // patterns to allow
	Deny        []string `toml:"deny"`         // patterns to deny
	DenyMessage string   `toml:"deny_message"` // custom message for denials
}

// Rule represents a detailed command rule with argument matching.
type Rule struct {
	Command          string      `toml:"command"`           // command name or "*" for any
	Action           string      `toml:"action"`            // "allow" or "deny"
	Message          string      `toml:"message"`           // custom message for denials
	Args             ArgsMatch   `toml:"args"`              // argument matching options
	Pipe             PipeContext `toml:"pipe"`              // pipe context rules
	RespectFileRules *bool       `toml:"respect_file_rules"` // override policy.respect_file_rules for this rule
	FileAccessType   string      `toml:"file_access_type"`   // override inferred file access type ("Read", "Write", "Edit")
}

// FlexiblePattern can be a string or []string (for enum matching).
// When used in position matching, any pattern matching succeeds (OR semantics).
type FlexiblePattern struct {
	Patterns []string
}

// UnmarshalTOML implements custom TOML unmarshaling for FlexiblePattern.
func (fp *FlexiblePattern) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		fp.Patterns = []string{v}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				fp.Patterns = append(fp.Patterns, s)
			} else {
				return fmt.Errorf("array elements must be strings")
			}
		}
	default:
		return fmt.Errorf("expected string or array, got %T", data)
	}
	return nil
}

// MatchElement can be a string pattern or an adjacent sequence object.
// When IsSequence is true, it matches consecutive args at relative positions.
type MatchElement struct {
	IsSequence bool
	Pattern    string                     // if !IsSequence: pattern to match any arg
	Sequence   map[string]FlexiblePattern // if IsSequence: "0" -> patterns, "1" -> patterns, etc.
}

// UnmarshalTOML implements custom TOML unmarshaling for MatchElement.
func (me *MatchElement) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		me.IsSequence = false
		me.Pattern = v
	case map[string]interface{}:
		me.IsSequence = true
		me.Sequence = make(map[string]FlexiblePattern)
		for k, val := range v {
			var fp FlexiblePattern
			if err := fp.UnmarshalTOML(val); err != nil {
				return fmt.Errorf("position %q: %w", k, err)
			}
			me.Sequence[k] = fp
		}
	default:
		return fmt.Errorf("expected string or object, got %T", data)
	}
	return nil
}

// ArgsMatch provides different ways to match command arguments.
type ArgsMatch struct {
	Contains []string                   `toml:"contains"`  // literal substring matches
	AnyMatch []MatchElement             `toml:"any_match"` // any element matches (strings or sequence objects)
	AllMatch []MatchElement             `toml:"all_match"` // all elements must match
	Position map[string]FlexiblePattern `toml:"position"`  // specific positional arg matching with enum support
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

// RedirectsConfig holds policy settings for redirect rules.
type RedirectsConfig struct {
	RespectFileRules *bool `toml:"respect_file_rules"` // if true, check file rules for redirect targets (default: false)
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

// TrackedValue holds a string value and the config file path that set it.
// Used for policy fields to track their source.
type TrackedValue struct {
	Value  string // the actual value ("allow", "deny", "ask", or a message)
	Source string // config file path that set this value (empty if unset/default)
}

// TrackedRule wraps a Rule with source tracking and shadowing info.
type TrackedRule struct {
	Rule
	Source             string // config file path this rule came from
	Shadowed           bool   // true if a stricter rule from a later config overrides this
	Shadowing          string // if this shadows a parent rule, the path of the shadowed config
	RespectFileRules   *bool  // resolved value from rule or policy (nil = use policy default)
	ResolvedAccessType string // resolved file access type for this command
}

// TrackedRedirectRule wraps a RedirectRule with source tracking and shadowing info.
type TrackedRedirectRule struct {
	RedirectRule
	Source    string
	Shadowed  bool
	Shadowing string
}

// TrackedHeredocRule wraps a HeredocRule with source tracking and shadowing info.
type TrackedHeredocRule struct {
	HeredocRule
	Source    string
	Shadowed  bool
	Shadowing string
}

// TrackedCommandEntry tracks a single command name in allow/deny lists.
type TrackedCommandEntry struct {
	Name    string // the command name or pattern
	Source  string // config file path
	Message string // associated message (if any)
}

// TrackedFilePatternEntry tracks a single file pattern in allow/deny lists.
type TrackedFilePatternEntry struct {
	Pattern string // the file path pattern
	Source  string // config file path
	Message string // associated message (if any)
}

// MergedFilesConfig holds merged file tool settings with source tracking.
type MergedFilesConfig struct {
	Default TrackedValue // "allow", "deny", or "ask"
	// Per-tool allow/deny lists - keys are "Read", "Edit", "Write"
	Allow map[string][]TrackedFilePatternEntry
	Deny  map[string][]TrackedFilePatternEntry
}

// MergedPolicy holds policy settings with source tracking.
type MergedPolicy struct {
	Default             TrackedValue
	DynamicCommands     TrackedValue
	DefaultMessage      TrackedValue
	UnresolvedCommands  TrackedValue
	RespectFileRules    TrackedValue // "true" or "false" as string, default "true"
	AllowedPaths        []string     // union of all allowed paths
	AllowedPathsSources []string     // sources for each path
}

// MergedRedirectsConfig holds merged redirect policy settings.
type MergedRedirectsConfig struct {
	RespectFileRules TrackedValue // "true" or "false" as string, default "false"
}

// MergedConstructs holds constructs settings with source tracking.
type MergedConstructs struct {
	Subshells           TrackedValue
	FunctionDefinitions TrackedValue
	Background          TrackedValue
	Heredocs            TrackedValue
}

// MergedConfig represents the result of merging all configs in the chain.
// Each policy field tracks its source, rules accumulate with shadowing detection.
type MergedConfig struct {
	Sources         []string // all config file paths that contributed, in order
	Policy          MergedPolicy
	Constructs      MergedConstructs
	Files           MergedFilesConfig     // file tool permissions
	RedirectsPolicy MergedRedirectsConfig // redirect policy settings
	CommandsDeny    []TrackedCommandEntry // union of all deny lists
	CommandsAllow   []TrackedCommandEntry // union of all allow lists
	Rules           []TrackedRule
	Redirects       []TrackedRedirectRule
	Heredocs        []TrackedHeredocRule
	Debug           DebugConfig // just use the last one (or first non-empty)
}

// LoadConfig reads and parses a TOML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := ParseConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// ParseConfig parses a TOML configuration string.
func ParseConfig(data string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}
	// Set defaults
	if cfg.Policy.Default == "" {
		cfg.Policy.Default = "ask"
	}
	if cfg.Policy.DynamicCommands == "" {
		cfg.Policy.DynamicCommands = "ask"
	}
	if cfg.Policy.UnresolvedCommands == "" {
		cfg.Policy.UnresolvedCommands = "ask"
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

// parseConfigRaw parses a TOML configuration string WITHOUT applying defaults.
// Empty strings mean "unset" - the caller is responsible for applying defaults
// after merging multiple configs.
func parseConfigRaw(data string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}
	// NO defaults applied - empty strings mean "unset"
	// Still validate patterns
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// loadConfigRaw reads and parses a TOML configuration file WITHOUT applying defaults.
// Used by LoadConfigChain for proper inheritance.
func loadConfigRaw(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := parseConfigRaw(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// Validate checks that all patterns in the config are valid.
// This catches invalid regex patterns at load time rather than at evaluation time.
func (cfg *Config) Validate() error {
	// Validate commands.allow.names patterns
	for i, name := range cfg.Commands.Allow.Names {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: commands.allow.names[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate commands.deny.names patterns
	for i, name := range cfg.Commands.Deny.Names {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: commands.deny.names[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate command rules
	for i, rule := range cfg.Rules {
		// Validate rule.command pattern (if it has a pattern prefix)
		if rule.Command != "*" && rule.Command != "" {
			if _, err := ParsePattern(rule.Command); err != nil {
				return fmt.Errorf("%w: rule[%d]: command: %w", ErrInvalidConfig, i, err)
			}
		}
		// Validate args.any_match (can be strings or sequence objects)
		for j, elem := range rule.Args.AnyMatch {
			if err := validateMatchElement(elem, fmt.Sprintf("rule[%d] (command=%q): args.any_match[%d]", i, rule.Command, j)); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
			}
		}
		// Validate args.all_match (can be strings or sequence objects)
		for j, elem := range rule.Args.AllMatch {
			if err := validateMatchElement(elem, fmt.Sprintf("rule[%d] (command=%q): args.all_match[%d]", i, rule.Command, j)); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
			}
		}
		// Validate args.position (values can be strings or arrays of strings)
		for posStr, fp := range rule.Args.Position {
			pos, err := strconv.Atoi(posStr)
			if err != nil {
				return fmt.Errorf("%w: rule[%d] (command=%q): args.position key %q is not a valid integer", ErrInvalidConfig, i, rule.Command, posStr)
			}
			for k, pattern := range fp.Patterns {
				if _, err := ParsePattern(pattern); err != nil {
					return fmt.Errorf("%w: rule[%d] (command=%q): args.position[%d][%d]: %w", ErrInvalidConfig, i, rule.Command, pos, k, err)
				}
			}
		}
	}

	// Validate redirect rules
	for i, rule := range cfg.Redirects {
		if len(rule.To.Pattern) > 0 {
			if _, err := NewMatcher(rule.To.Pattern); err != nil {
				return fmt.Errorf("%w: redirect[%d]: to.pattern: %w", ErrInvalidConfig, i, err)
			}
		}
	}

	// Validate heredoc rules
	for i, rule := range cfg.Heredocs {
		if len(rule.ContentMatch) > 0 {
			if _, err := NewMatcher(rule.ContentMatch); err != nil {
				return fmt.Errorf("%w: heredoc[%d]: content_match: %w", ErrInvalidConfig, i, err)
			}
		}
	}

	// Validate file tool patterns
	fileTools := []struct {
		name   string
		config FileToolConfig
	}{
		{"read", cfg.Files.Read},
		{"edit", cfg.Files.Edit},
		{"write", cfg.Files.Write},
	}
	for _, tool := range fileTools {
		for i, pattern := range tool.config.Allow {
			if _, err := ParsePattern(pattern); err != nil {
				return fmt.Errorf("%w: files.%s.allow[%d]: %w", ErrInvalidConfig, tool.name, i, err)
			}
		}
		for i, pattern := range tool.config.Deny {
			if _, err := ParsePattern(pattern); err != nil {
				return fmt.Errorf("%w: files.%s.deny[%d]: %w", ErrInvalidConfig, tool.name, i, err)
			}
		}
	}

	return nil
}

// validateMatchElement validates a MatchElement (string pattern or sequence object).
func validateMatchElement(elem MatchElement, context string) error {
	if elem.IsSequence {
		// Validate each position in the sequence
		for posStr, fp := range elem.Sequence {
			pos, err := strconv.Atoi(posStr)
			if err != nil {
				return fmt.Errorf("%s: position key %q is not a valid integer", context, posStr)
			}
			for k, pattern := range fp.Patterns {
				if _, err := ParsePattern(pattern); err != nil {
					return fmt.Errorf("%s: position[%d][%d]: %w", context, pos, k, err)
				}
			}
		}
	} else {
		// Validate the single pattern
		if _, err := ParsePattern(elem.Pattern); err != nil {
			return fmt.Errorf("%s: %w", context, err)
		}
	}
	return nil
}

// DefaultConfig returns a minimal default configuration.
func DefaultConfig() *Config {
	return &Config{
		Path: "(default)",
		Policy: PolicyConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
			DefaultMessage:     "Command not allowed",
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
	Configs []*Config     // ordered: global (~/), project (.claude/), project local (.claude/*.local.toml), explicit (--config)
	Merged  *MergedConfig // the merged result of all configs
}

// LoadConfigChain loads configs from standard locations plus an optional explicit path.
// Configs are loaded WITHOUT applying defaults, then merged with stricter-wins semantics.
// Order (loosest to strictest): ~/.config/cc-allow.toml, .claude/cc-allow.toml, .claude/cc-allow.local.toml, --config
func LoadConfigChain(explicitPath string) (*ConfigChain, error) {
	chain := &ConfigChain{}

	// 1. Load global config (~/.config/cc-allow.toml)
	if globalPath := findGlobalConfig(); globalPath != "" {
		cfg, err := loadConfigRaw(globalPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 2. Load project configs (.claude/cc-allow.toml and .claude/cc-allow.local.toml)
	projectPath, localPath := findProjectConfigs()
	if projectPath != "" {
		cfg, err := loadConfigRaw(projectPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}
	if localPath != "" {
		cfg, err := loadConfigRaw(localPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 4. Load explicit config (--config flag)
	if explicitPath != "" {
		cfg, err := loadConfigRaw(explicitPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// If no configs found, use default
	if len(chain.Configs) == 0 {
		chain.Configs = append(chain.Configs, DefaultConfig())
	}

	// Merge all configs into a single merged config
	// This applies stricter-wins semantics and system defaults
	chain.Merged = MergeConfigs(chain.Configs)

	return chain, nil
}
