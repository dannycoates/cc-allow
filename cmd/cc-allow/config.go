package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

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
	Default            string   `toml:"default"`             // "allow", "deny", or "ask" (default: "ask")
	DynamicCommands    string   `toml:"dynamic_commands"`    // how to handle $VAR or $(cmd) as command names
	DefaultMessage     string   `toml:"default_message"`     // fallback message when rule has no message
	AllowedPaths       []string `toml:"allowed_paths"`       // directories to search for commands (defaults to $PATH)
	UnresolvedCommands string   `toml:"unresolved_commands"` // "ask" or "deny" for commands not found
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
	Position map[string]string `toml:"position"`   // specific positional arg matching (keys are string indices: "0", "1", etc.)
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

// TrackedValue holds a string value and the config file path that set it.
// Used for policy fields to track their source.
type TrackedValue struct {
	Value  string // the actual value ("allow", "deny", "ask", or a message)
	Source string // config file path that set this value (empty if unset/default)
}

// TrackedRule wraps a Rule with source tracking and shadowing info.
type TrackedRule struct {
	Rule
	Source    string // config file path this rule came from
	Shadowed  bool   // true if a stricter rule from a later config overrides this
	Shadowing string // if this shadows a parent rule, the path of the shadowed config
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

// MergedPolicy holds policy settings with source tracking.
type MergedPolicy struct {
	Default            TrackedValue
	DynamicCommands    TrackedValue
	DefaultMessage     TrackedValue
	UnresolvedCommands TrackedValue
	AllowedPaths       []string // union of all allowed paths
	AllowedPathsSources []string // sources for each path
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
	Sources    []string              // all config file paths that contributed, in order
	Policy     MergedPolicy
	Constructs MergedConstructs
	CommandsDeny  []TrackedCommandEntry // union of all deny lists
	CommandsAllow []TrackedCommandEntry // union of all allow lists
	Rules      []TrackedRule
	Redirects  []TrackedRedirectRule
	Heredocs   []TrackedHeredocRule
	Debug      DebugConfig           // just use the last one (or first non-empty)
}

// LoadConfig reads and parses a TOML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := ParseConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// ParseConfig parses a TOML configuration string.
func ParseConfig(data string) (*Config, error) {
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
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
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
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
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := parseConfigRaw(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// Validate checks that all patterns in the config are valid.
// This catches invalid regex patterns at load time rather than at evaluation time.
func (cfg *Config) Validate() error {
	// Validate command rules
	for i, rule := range cfg.Rules {
		if len(rule.Args.AnyMatch) > 0 {
			if _, err := NewMatcher(rule.Args.AnyMatch); err != nil {
				return fmt.Errorf("%w: rule[%d] (command=%q): args.any_match: %w", ErrInvalidConfig, i, rule.Command, err)
			}
		}
		if len(rule.Args.AllMatch) > 0 {
			if _, err := NewMatcher(rule.Args.AllMatch); err != nil {
				return fmt.Errorf("%w: rule[%d] (command=%q): args.all_match: %w", ErrInvalidConfig, i, rule.Command, err)
			}
		}
		for posStr, pattern := range rule.Args.Position {
			pos, err := strconv.Atoi(posStr)
			if err != nil {
				return fmt.Errorf("%w: rule[%d] (command=%q): args.position key %q is not a valid integer", ErrInvalidConfig, i, rule.Command, posStr)
			}
			if _, err := ParsePattern(pattern); err != nil {
				return fmt.Errorf("%w: rule[%d] (command=%q): args.position[%d]: %w", ErrInvalidConfig, i, rule.Command, pos, err)
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

// actionStrictness returns the strictness level of an action.
// Higher values are stricter: deny(2) > ask(1) > allow(0).
// Empty string (unset) returns -1.
func actionStrictness(action string) int {
	switch action {
	case "deny":
		return 2
	case "ask":
		return 1
	case "allow":
		return 0
	default:
		return -1 // unset or invalid
	}
}

// isStricter returns true if newVal is stricter than currentVal.
func isStricter(newVal, currentVal string) bool {
	return actionStrictness(newVal) > actionStrictness(currentVal)
}

// mergeTrackedValue merges a policy field, keeping the stricter value.
// If current is unset (empty), any new value is accepted.
// If new is unset, current is kept.
// Otherwise, new only wins if it's stricter.
func mergeTrackedValue(current TrackedValue, newVal, newSource string) TrackedValue {
	// If new is unset, keep current
	if newVal == "" {
		return current
	}
	// If current is unset, accept new
	if current.Value == "" {
		return TrackedValue{Value: newVal, Source: newSource}
	}
	// Both set - new wins only if stricter
	if isStricter(newVal, current.Value) {
		return TrackedValue{Value: newVal, Source: newSource}
	}
	return current
}

// mergeTrackedMessage merges a message field.
// Unlike policy fields, messages don't have strictness - later non-empty values win.
func mergeTrackedMessage(current TrackedValue, newVal, newSource string) TrackedValue {
	if newVal == "" {
		return current
	}
	// Non-empty new value overwrites
	return TrackedValue{Value: newVal, Source: newSource}
}

// newEmptyMergedConfig creates a MergedConfig with all fields unset.
func newEmptyMergedConfig() *MergedConfig {
	return &MergedConfig{
		Sources:       []string{},
		CommandsDeny:  []TrackedCommandEntry{},
		CommandsAllow: []TrackedCommandEntry{},
		Rules:         []TrackedRule{},
		Redirects:     []TrackedRedirectRule{},
		Heredocs:      []TrackedHeredocRule{},
	}
}

// mergeConfigInto merges a raw config into an existing MergedConfig.
// The raw config can only make things stricter, not looser.
func mergeConfigInto(merged *MergedConfig, cfg *Config) {
	source := cfg.Path
	merged.Sources = append(merged.Sources, source)

	// Merge policy fields (stricter wins)
	merged.Policy.Default = mergeTrackedValue(merged.Policy.Default, cfg.Policy.Default, source)
	merged.Policy.DynamicCommands = mergeTrackedValue(merged.Policy.DynamicCommands, cfg.Policy.DynamicCommands, source)
	merged.Policy.UnresolvedCommands = mergeTrackedValue(merged.Policy.UnresolvedCommands, cfg.Policy.UnresolvedCommands, source)
	merged.Policy.DefaultMessage = mergeTrackedMessage(merged.Policy.DefaultMessage, cfg.Policy.DefaultMessage, source)

	// Merge allowed_paths (union)
	for _, p := range cfg.Policy.AllowedPaths {
		merged.Policy.AllowedPaths = append(merged.Policy.AllowedPaths, p)
		merged.Policy.AllowedPathsSources = append(merged.Policy.AllowedPathsSources, source)
	}

	// Merge constructs (stricter wins)
	merged.Constructs.Subshells = mergeTrackedValue(merged.Constructs.Subshells, cfg.Constructs.Subshells, source)
	merged.Constructs.FunctionDefinitions = mergeTrackedValue(merged.Constructs.FunctionDefinitions, cfg.Constructs.FunctionDefinitions, source)
	merged.Constructs.Background = mergeTrackedValue(merged.Constructs.Background, cfg.Constructs.Background, source)
	merged.Constructs.Heredocs = mergeTrackedValue(merged.Constructs.Heredocs, cfg.Constructs.Heredocs, source)

	// Merge commands.deny list (union - anything denied anywhere stays denied)
	for _, name := range cfg.Commands.Deny.Names {
		merged.CommandsDeny = append(merged.CommandsDeny, TrackedCommandEntry{
			Name:    name,
			Source:  source,
			Message: cfg.Commands.Deny.Message,
		})
	}

	// Merge commands.allow list (union)
	for _, name := range cfg.Commands.Allow.Names {
		merged.CommandsAllow = append(merged.CommandsAllow, TrackedCommandEntry{
			Name:    name,
			Source:  source,
			Message: cfg.Commands.Allow.Message,
		})
	}

	// Merge rules with shadowing detection
	merged.Rules = mergeRules(merged.Rules, cfg.Rules, source)

	// Merge redirects with shadowing detection
	merged.Redirects = mergeRedirectRules(merged.Redirects, cfg.Redirects, source)

	// Merge heredocs with shadowing detection
	merged.Heredocs = mergeHeredocRules(merged.Heredocs, cfg.Heredocs, source)

	// Debug config - take non-empty values
	if cfg.Debug.LogFile != "" {
		merged.Debug.LogFile = cfg.Debug.LogFile
	}
}

// applyMergedDefaults fills in system defaults for any unset fields in MergedConfig.
func applyMergedDefaults(merged *MergedConfig) {
	if merged.Policy.Default.Value == "" {
		merged.Policy.Default = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.DynamicCommands.Value == "" {
		merged.Policy.DynamicCommands = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.UnresolvedCommands.Value == "" {
		merged.Policy.UnresolvedCommands = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.DefaultMessage.Value == "" {
		merged.Policy.DefaultMessage = TrackedValue{Value: "Command not allowed", Source: "(default)"}
	}
	if merged.Constructs.Subshells.Value == "" {
		merged.Constructs.Subshells = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.FunctionDefinitions.Value == "" {
		merged.Constructs.FunctionDefinitions = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.Background.Value == "" {
		merged.Constructs.Background = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.Heredocs.Value == "" {
		merged.Constructs.Heredocs = TrackedValue{Value: "allow", Source: "(default)"}
	}
}

// MergeConfigs merges multiple raw configs into a single MergedConfig.
// Configs are processed in order; each can only make things stricter.
func MergeConfigs(configs []*Config) *MergedConfig {
	merged := newEmptyMergedConfig()
	for _, cfg := range configs {
		mergeConfigInto(merged, cfg)
	}
	applyMergedDefaults(merged)
	return merged
}

// slicesEqual compares two string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mapsEqual compares two string maps for equality.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// rulesExactMatch returns true if two rules have identical command and args patterns.
// Used for shadowing detection - only exact matches are considered overlapping.
func rulesExactMatch(a, b Rule) bool {
	return a.Command == b.Command &&
		slicesEqual(a.Args.Contains, b.Args.Contains) &&
		slicesEqual(a.Args.AnyMatch, b.Args.AnyMatch) &&
		slicesEqual(a.Args.AllMatch, b.Args.AllMatch) &&
		mapsEqual(a.Args.Position, b.Args.Position) &&
		slicesEqual(a.Pipe.To, b.Pipe.To) &&
		slicesEqual(a.Pipe.From, b.Pipe.From)
}

// mergeRules merges new rules into existing rules with shadowing detection.
// If a new rule exactly matches an existing rule:
// - If new is stricter, new shadows existing (existing.Shadowed = true)
// - If new is same or looser, new gets shadowed (new.Shadowed = true)
func mergeRules(merged []TrackedRule, newRules []Rule, newSource string) []TrackedRule {
	for _, newRule := range newRules {
		tr := TrackedRule{Rule: newRule, Source: newSource}

		// Check if this shadows an existing rule (exact same pattern)
		for i, existing := range merged {
			if existing.Shadowed {
				continue // already shadowed, skip
			}
			if rulesExactMatch(existing.Rule, newRule) {
				if isStricter(newRule.Action, existing.Rule.Action) {
					// New rule is stricter, it shadows the existing
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					// New rule is same or looser, it gets shadowed
					tr.Shadowed = true
				}
				break // only shadow one matching rule
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// redirectRulesExactMatch returns true if two redirect rules have identical patterns.
func redirectRulesExactMatch(a, b RedirectRule) bool {
	// Check append mode
	aAppend := a.Append != nil && *a.Append
	bAppend := b.Append != nil && *b.Append
	if aAppend != bAppend {
		return false
	}
	return slicesEqual(a.To.Pattern, b.To.Pattern) &&
		slicesEqual(a.To.Exact, b.To.Exact)
}

// mergeRedirectRules merges redirect rules with shadowing detection.
func mergeRedirectRules(merged []TrackedRedirectRule, newRules []RedirectRule, newSource string) []TrackedRedirectRule {
	for _, newRule := range newRules {
		tr := TrackedRedirectRule{RedirectRule: newRule, Source: newSource}

		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if redirectRulesExactMatch(existing.RedirectRule, newRule) {
				if isStricter(newRule.Action, existing.RedirectRule.Action) {
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					tr.Shadowed = true
				}
				break
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// heredocRulesExactMatch returns true if two heredoc rules have identical patterns.
func heredocRulesExactMatch(a, b HeredocRule) bool {
	return slicesEqual(a.ContentMatch, b.ContentMatch)
}

// mergeHeredocRules merges heredoc rules with shadowing detection.
func mergeHeredocRules(merged []TrackedHeredocRule, newRules []HeredocRule, newSource string) []TrackedHeredocRule {
	for _, newRule := range newRules {
		tr := TrackedHeredocRule{HeredocRule: newRule, Source: newSource}

		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if heredocRulesExactMatch(existing.HeredocRule, newRule) {
				if isStricter(newRule.Action, existing.HeredocRule.Action) {
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					tr.Shadowed = true
				}
				break
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// ConfigChain holds multiple configs ordered from highest to lowest priority.
// Lower configs can only make things stricter, not looser.
type ConfigChain struct {
	Configs []*Config      // ordered: global (~/), project (.claude/), project local (.claude/*.local.toml), explicit (--config)
	Merged  *MergedConfig  // the merged result of all configs
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

	// 2. Load project config (.claude/cc-allow.toml)
	if projectPath := findProjectConfig(); projectPath != "" {
		cfg, err := loadConfigRaw(projectPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 3. Load project local config (.claude/cc-allow.local.toml) - not in source control
	if localPath := findProjectLocalConfig(); localPath != "" {
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
