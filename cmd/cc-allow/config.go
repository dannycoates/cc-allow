package main

import (
	"fmt"
	"strings"
)

// Current config version - v2.x uses the new tool-centric format
const (
	ConfigVersionMajor = 2
	ConfigVersionMinor = 2
)

// Config represents the complete v2 configuration for cc-allow.
// The v2 format is tool-centric with top-level sections for each tool type.
type Config struct {
	Version string           `toml:"version"` // config format version (e.g., "2.0")
	Path    string           `toml:"-"`       // path this config was loaded from (not in TOML)
	Aliases map[string]Alias `toml:"aliases"` // named pattern aliases for reuse
	Bash    BashConfig       `toml:"bash"`    // bash tool configuration
	Read    FileToolConfig   `toml:"read"`    // read tool configuration
	Write   FileToolConfig   `toml:"write"`   // write tool configuration
	Edit     FileToolConfig   `toml:"edit"`     // edit tool configuration
	WebFetch WebFetchConfig   `toml:"webfetch"` // webfetch tool configuration
	Debug    DebugConfig      `toml:"debug"`    // debug settings

	// Parsed rules (populated during parsing, not from TOML)
	parsedRules     []BashRule     `toml:"-"`
	parsedRedirects []RedirectRule `toml:"-"`
	parsedHeredocs  []HeredocRule  `toml:"-"`
}

// getParsedRules returns the parsed bash rules.
func (cfg *Config) getParsedRules() []BashRule {
	return cfg.parsedRules
}

// getParsedRedirects returns the parsed redirect rules.
func (cfg *Config) getParsedRedirects() []RedirectRule {
	return cfg.parsedRedirects
}

// getParsedHeredocs returns the parsed heredoc rules.
func (cfg *Config) getParsedHeredocs() []HeredocRule {
	return cfg.parsedHeredocs
}

// Alias holds one or more patterns that can be referenced with alias:name.
// Can be parsed from either a string or array of strings in TOML.
type Alias struct {
	Patterns []string
}

// UnmarshalTOML implements custom TOML unmarshaling for Alias.
func (a *Alias) UnmarshalTOML(data any) error {
	switch v := data.(type) {
	case string:
		a.Patterns = []string{v}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				a.Patterns = append(a.Patterns, s)
			} else {
				return fmt.Errorf("array elements must be strings")
			}
		}
	default:
		return fmt.Errorf("expected string or array, got %T", data)
	}
	return nil
}

// BashConfig holds all bash tool configuration.
type BashConfig struct {
	Default            string           `toml:"default"`             // default action: "allow", "deny", or "ask"
	DynamicCommands    string           `toml:"dynamic_commands"`    // how to handle $VAR or $(cmd) as command names
	UnresolvedCommands string           `toml:"unresolved_commands"` // "ask" or "deny" for commands not found
	DefaultMessage     string           `toml:"default_message"`     // fallback message when rule has no message
	RespectFileRules   *bool            `toml:"respect_file_rules"`  // check file rules for command args
	Constructs         ConstructsConfig `toml:"constructs"`          // shell construct handling
	Allow              BashAllowDeny    `toml:"allow"`               // allow rules
	Deny               BashAllowDeny    `toml:"deny"`                // deny rules
	Redirects          RedirectsConfig  `toml:"redirects"`           // redirect configuration
	Heredocs           HeredocsConfig   `toml:"heredocs"`            // heredoc configuration
}

// ConstructsConfig controls handling of shell constructs.
type ConstructsConfig struct {
	Subshells           string `toml:"subshells"`            // "allow", "deny", or "ask"
	Background          string `toml:"background"`           // "allow", "deny", or "ask"
	FunctionDefinitions string `toml:"function_definitions"` // "allow", "deny", or "ask"
	Heredocs            string `toml:"heredocs"`             // "allow", "deny", or "ask"
}

// BashAllowDeny holds command lists and rules for allow/deny sections.
type BashAllowDeny struct {
	Commands []string `toml:"commands"` // bulk list of command names
	Message  string   `toml:"message"`  // shared message for these commands
	Mode     string   `toml:"mode"`     // "merge" (default) or "replace" (only for allow)
	// Command rules are parsed separately via raw TOML access into BashRules
}

// BashRule represents a complex command rule with argument matching.
type BashRule struct {
	Command          string      // command name (from TOML key)
	Subcommands      []string    // subcommand path (e.g., ["status"] for [[bash.allow.git.status]])
	Action           string      // "allow", "deny", or "ask"
	Message          string      `toml:"message"`            // custom message
	Args             ArgsMatch   `toml:"args"`               // argument matching
	Pipe             PipeContext `toml:"pipe"`               // pipe context rules
	RespectFileRules *bool       `toml:"respect_file_rules"` // override bash.respect_file_rules
	FileAccessType   string      `toml:"file_access_type"`   // override inferred file access type
}

// ArgsMatch provides argument matching using boolean expressions.
type ArgsMatch struct {
	Any      *BoolExpr                  `toml:"any"`      // matches if ANY pattern matches (OR)
	All      *BoolExpr                  `toml:"all"`      // matches if ALL patterns match (AND)
	Not      *BoolExpr                  `toml:"not"`      // negates the result
	Xor      *BoolExpr                  `toml:"xor"`      // exactly one must match
	Position map[string]FlexiblePattern `toml:"position"` // absolute positional matching
}

// BoolExpr represents a boolean expression for argument matching.
// It can be a simple string pattern, an array of patterns/expressions,
// or a nested expression with operators.
type BoolExpr struct {
	// Simple patterns (string or string array)
	Patterns []string

	// Nested expressions
	Any []*BoolExpr `toml:"any"` // OR: any child must match
	All []*BoolExpr `toml:"all"` // AND: all children must match
	Not *BoolExpr   `toml:"not"` // NOT: negate the child
	Xor []*BoolExpr `toml:"xor"` // XOR: exactly one must match

	// Relative position sequence (for objects like {"0": "-i", "1": "path:..."})
	IsSequence bool
	Sequence   map[string]FlexiblePattern
}

// UnmarshalTOML implements custom TOML unmarshaling for BoolExpr.
func (b *BoolExpr) UnmarshalTOML(data any) error {
	return b.unmarshalWithSemantics(data, false)
}

// unmarshalWithSemantics parses BoolExpr data with semantics context.
// If useAll is true, nested array items go into .All instead of .Any.
func (b *BoolExpr) unmarshalWithSemantics(data any, useAll bool) error {
	switch v := data.(type) {
	case string:
		// Simple string pattern
		b.Patterns = []string{v}
	case []any:
		// Array - could be patterns or nested expressions
		for _, item := range v {
			child, err := parseBoolExprItemWithSemantics(item, useAll)
			if err != nil {
				return err
			}
			// If child is just a pattern, append to patterns
			if len(child.Patterns) > 0 && !child.hasOperators() && !child.IsSequence {
				b.Patterns = append(b.Patterns, child.Patterns...)
			} else {
				// Store as nested - use the semantics context
				if useAll {
					b.All = append(b.All, child)
				} else {
					b.Any = append(b.Any, child)
				}
			}
		}
	case map[string]any:
		// Could be operators (any/all/not/xor) or a sequence object
		return b.parseMapWithSemantics(v, useAll)
	default:
		return fmt.Errorf("expected string, array, or object, got %T", data)
	}
	return nil
}

// hasOperators returns true if this expression has any nested operators.
func (b *BoolExpr) hasOperators() bool {
	return len(b.Any) > 0 || len(b.All) > 0 || b.Not != nil || len(b.Xor) > 0
}

// parseMap parses a map as either operators or a sequence object.
func (b *BoolExpr) parseMap(m map[string]any) error {
	return b.parseMapWithSemantics(m, false)
}

// parseMapWithSemantics parses a map with semantics context.
func (b *BoolExpr) parseMapWithSemantics(m map[string]any, useAll bool) error {
	// Check for boolean operators - these define their own semantics
	if anyVal, ok := m["any"]; ok {
		exprs, err := parseBoolExprArrayWithSemantics(anyVal, false) // any uses OR
		if err != nil {
			return fmt.Errorf("any: %w", err)
		}
		b.Any = exprs
	}
	if allVal, ok := m["all"]; ok {
		exprs, err := parseBoolExprArrayWithSemantics(allVal, true) // all uses AND
		if err != nil {
			return fmt.Errorf("all: %w", err)
		}
		b.All = exprs
	}
	if notVal, ok := m["not"]; ok {
		child, err := parseBoolExprItemWithSemantics(notVal, useAll)
		if err != nil {
			return fmt.Errorf("not: %w", err)
		}
		b.Not = child
	}
	if xorVal, ok := m["xor"]; ok {
		exprs, err := parseBoolExprArrayWithSemantics(xorVal, false) // xor children use OR within each
		if err != nil {
			return fmt.Errorf("xor: %w", err)
		}
		b.Xor = exprs
	}

	// If we found operators, we're done
	if b.hasOperators() {
		return nil
	}

	// Otherwise, check if this is a sequence object (numeric keys like "0", "1")
	isSeq := true
	for key := range m {
		if key != "any" && key != "all" && key != "not" && key != "xor" {
			// Check if key looks like a number
			if !isNumericKey(key) {
				isSeq = false
				break
			}
		}
	}

	if isSeq && len(m) > 0 {
		b.IsSequence = true
		b.Sequence = make(map[string]FlexiblePattern)
		for key, val := range m {
			fp, err := parseFlexiblePatternRaw(val)
			if err != nil {
				return fmt.Errorf("position %s: %w", key, err)
			}
			b.Sequence[key] = fp
		}
	}

	return nil
}

// isNumericKey checks if a string is a valid numeric position key.
func isNumericKey(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseBoolExprItem parses a single item into a BoolExpr.
func parseBoolExprItem(data any) (*BoolExpr, error) {
	return parseBoolExprItemWithSemantics(data, false)
}

// parseBoolExprItemWithSemantics parses a BoolExpr item with semantics context.
// If useAll is true, nested array items go into .All instead of .Any.
func parseBoolExprItemWithSemantics(data any, useAll bool) (*BoolExpr, error) {
	b := &BoolExpr{}
	if err := b.unmarshalWithSemantics(data, useAll); err != nil {
		return nil, err
	}
	return b, nil
}

// parseBoolExprArray parses an array of items into BoolExpr slice.
func parseBoolExprArray(data any) ([]*BoolExpr, error) {
	return parseBoolExprArrayWithSemantics(data, false)
}

// parseBoolExprArrayWithSemantics parses an array with semantics context.
func parseBoolExprArrayWithSemantics(data any, useAll bool) ([]*BoolExpr, error) {
	arr, ok := data.([]any)
	if !ok {
		// Single item, wrap in array
		child, err := parseBoolExprItemWithSemantics(data, useAll)
		if err != nil {
			return nil, err
		}
		return []*BoolExpr{child}, nil
	}
	var result []*BoolExpr
	for i, item := range arr {
		child, err := parseBoolExprItemWithSemantics(item, useAll)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		result = append(result, child)
	}
	return result, nil
}

// FlexiblePattern can be a string or []string (for enum matching).
// When used in position matching, any pattern matching succeeds (OR semantics).
type FlexiblePattern struct {
	Patterns []string
}

// UnmarshalTOML implements custom TOML unmarshaling for FlexiblePattern.
func (fp *FlexiblePattern) UnmarshalTOML(data any) error {
	switch v := data.(type) {
	case string:
		fp.Patterns = []string{v}
	case []any:
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

// parseFlexiblePatternRaw parses a FlexiblePattern from raw TOML (string or array).
func parseFlexiblePatternRaw(raw any) (FlexiblePattern, error) {
	var fp FlexiblePattern
	if err := fp.UnmarshalTOML(raw); err != nil {
		return fp, err
	}
	return fp, nil
}

// PipeContext specifies rules about pipe relationships.
type PipeContext struct {
	To   []string `toml:"to"`   // deny if piped to any of these commands (immediate)
	From []string `toml:"from"` // deny if receiving piped input from any of these
}

// RedirectsConfig holds redirect policy and rules.
type RedirectsConfig struct {
	RespectFileRules *bool          `toml:"respect_file_rules"` // check write rules for redirect targets
	Allow            []RedirectRule `toml:"allow"`              // allow rules parsed separately
	Deny             []RedirectRule `toml:"deny"`               // deny rules parsed separately
}

// RedirectRule controls output/input redirection.
type RedirectRule struct {
	Action  string   `toml:"-"`       // "allow" or "deny" (derived from section)
	Message string   `toml:"message"` // custom message
	Paths   []string `toml:"paths"`   // path patterns to match
	Append  *bool    `toml:"append"`  // if set, only applies to >> (append mode)
}

// HeredocsConfig holds heredoc rules.
type HeredocsConfig struct {
	Allow []HeredocRule `toml:"allow"` // allow rules
	Deny  []HeredocRule `toml:"deny"`  // deny rules
}

// HeredocRule controls heredoc (<<EOF) handling.
type HeredocRule struct {
	Action  string    `toml:"-"` // "allow" or "deny" (derived from section)
	Message string    `toml:"message"`
	Content *BoolExpr `toml:"content"` // content matching using boolean expressions
}

// FileToolConfig holds configuration for read/write/edit tools.
type FileToolConfig struct {
	Default        string        `toml:"default"`         // default action: "allow", "deny", or "ask"
	DefaultMessage string        `toml:"default_message"` // message when default action is triggered
	Allow          FileAllowDeny `toml:"allow"`
	Deny           FileAllowDeny `toml:"deny"`
}

// FileAllowDeny holds path lists for allow/deny.
type FileAllowDeny struct {
	Paths   []string `toml:"paths"`   // path patterns
	Message string   `toml:"message"` // message for this action
	Mode    string   `toml:"mode"`    // "merge" (default) or "replace" (only for allow)
}

// WebFetchConfig holds configuration for the WebFetch tool.
type WebFetchConfig struct {
	FileToolConfig                                       // embeds Default, DefaultMessage, Allow, Deny
	SafeBrowsing   SafeBrowsingConfig `toml:"safe_browsing"` // Google Safe Browsing integration
}

// SafeBrowsingConfig holds Google Safe Browsing API settings.
type SafeBrowsingConfig struct {
	Enabled bool   `toml:"enabled"` // enable Safe Browsing URL checks
	APIKey  string `toml:"api_key"` // Google Safe Browsing API key
}

// DebugConfig controls debug logging behavior.
type DebugConfig struct {
	LogFile string `toml:"log_file"` // path to debug log file
}

// Tracked holds a value of any type along with the config file path that set it.
// The zero value represents "unset" - use IsSet() to check.
type Tracked[T any] struct {
	Value  T
	Source string
}

// IsSet returns true if this tracked value was explicitly set.
func (t Tracked[T]) IsSet() bool {
	return t.Source != ""
}

// TrackedRule wraps a BashRule with source tracking and shadowing info.
type TrackedRule struct {
	BashRule
	Source    string
	Shadowed  bool
	Shadowing string
}

// TrackedRedirectRule wraps a RedirectRule with source tracking.
type TrackedRedirectRule struct {
	RedirectRule
	Source    string
	Shadowed  bool
	Shadowing string
}

// TrackedHeredocRule wraps a HeredocRule with source tracking.
type TrackedHeredocRule struct {
	HeredocRule
	Source    string
	Shadowed  bool
	Shadowing string
}

// TrackedCommandEntry tracks a single command name in allow/deny lists.
type TrackedCommandEntry struct {
	Name    string
	Source  string
	Message string
}

// TrackedFilePatternEntry tracks a single file pattern.
type TrackedFilePatternEntry struct {
	Pattern string
	Source  string
	Message string
}

// MergedFilesConfig holds merged file tool settings with source tracking.
type MergedFilesConfig struct {
	Default        Tracked[string]
	DefaultMessage map[string]Tracked[string]            // per-tool default messages: "Read", "Edit", "Write"
	Allow          map[string][]TrackedFilePatternEntry // keys are "Read", "Edit", "Write"
	Deny           map[string][]TrackedFilePatternEntry
}

// MergedPolicy holds policy settings with source tracking.
type MergedPolicy struct {
	Default             Tracked[string]
	DynamicCommands     Tracked[string]
	DefaultMessage      Tracked[string]
	UnresolvedCommands  Tracked[string]
	RespectFileRules    Tracked[bool]
	AllowedPaths        []string
	AllowedPathsSources []string
}

// MergedRedirectsConfig holds merged redirect policy settings.
type MergedRedirectsConfig struct {
	RespectFileRules Tracked[bool]
}

// MergedConstructs holds constructs settings with source tracking.
type MergedConstructs struct {
	Subshells           Tracked[string]
	FunctionDefinitions Tracked[string]
	Background          Tracked[string]
	Heredocs            Tracked[string]
}

// MergedConfig represents the result of merging all configs in the chain.
type MergedConfig struct {
	Sources         []string
	Policy          MergedPolicy
	Constructs      MergedConstructs
	Files           MergedFilesConfig
	RedirectsPolicy MergedRedirectsConfig
	CommandsDeny    []TrackedCommandEntry
	CommandsAllow   []TrackedCommandEntry
	Rules           []TrackedRule
	Redirects       []TrackedRedirectRule
	Heredocs        []TrackedHeredocRule
	Aliases         map[string]Alias // merged aliases from all configs
	SafeBrowsing    SafeBrowsingConfig
	Debug           DebugConfig
}

// ConfigChain holds multiple configs ordered from highest to lowest priority.
type ConfigChain struct {
	Configs        []*Config
	Merged         *MergedConfig
	MigrationHints []string // legacy config paths that should be moved to .config/
}

// Legacy config markers for v1 detection
var legacyV1Keys = []string{
	"policy",     // v1 had [policy], v2 has [bash] with these fields
	"commands",   // v1 had [commands], v2 has [bash.allow/deny]
	"files",      // v1 had [files], v2 has [read], [write], [edit]
	"rule",       // v1 had [[rule]], v2 has [[bash.allow.X]]
	"redirect",   // v1 had [[redirect]], v2 has [[bash.redirects.allow/deny]]
	"heredoc",    // v1 had [[heredoc]], v2 has [[bash.heredocs.allow/deny]]
	"allow",      // v1 had top-level [allow], v2 has [bash.allow]
	"deny",       // v1 had top-level [deny], v2 has [bash.deny]
	"ask",        // v1 had [ask], v2 removed
	"constructs", // v1 had [constructs], v2 has [bash.constructs]
	"redirects",  // v1 had [redirects] at top level, v2 has [bash.redirects]
}

// isLegacyV1Config checks if the raw TOML contains v1-style keys.
func isLegacyV1Config(raw map[string]any) bool {
	for _, key := range legacyV1Keys {
		if _, exists := raw[key]; exists {
			return true
		}
	}
	return false
}

// LegacyConfigError is returned when a v1 config is detected.
type LegacyConfigError struct {
	Path string
}

func (e LegacyConfigError) Error() string {
	return fmt.Sprintf("config uses legacy v1 format: %s\nSee https://github.com/anthropics/cc-allow/docs/config-v2.md for migration guide", e.Path)
}

// Specificity scoring constants for CSS-like rule matching.
const (
	specificityCommand      = 100 // exact command name (vs pattern)
	specificitySubcommand   = 50  // each subcommand level
	specificityPositionArg  = 20  // each args.position entry
	specificityBoolExprItem = 5   // each item in args.any/all/not/xor
	specificityPipeExact    = 10  // each exact pipe.to or pipe.from entry
	specificityPipePattern  = 5   // each pattern pipe.to or pipe.from entry
	specificityContentMatch = 10  // each content match pattern
	specificityAppend       = 5   // append mode specified
)

// Specificity computes a CSS-like specificity score for a bash rule.
func (r BashRule) Specificity() int {
	score := 0

	// Command name specificity
	if !strings.HasPrefix(r.Command, "path:") && !strings.HasPrefix(r.Command, "re:") {
		score += specificityCommand
	}

	// Subcommand depth
	score += len(r.Subcommands) * specificitySubcommand

	// Position args
	score += len(r.Args.Position) * specificityPositionArg

	// Boolean expression items
	score += countBoolExprItems(r.Args.Any) * specificityBoolExprItem
	score += countBoolExprItems(r.Args.All) * specificityBoolExprItem
	score += countBoolExprItems(r.Args.Not) * specificityBoolExprItem
	score += countBoolExprItems(r.Args.Xor) * specificityBoolExprItem

	// Pipe context
	for _, to := range r.Pipe.To {
		if !strings.HasPrefix(to, "path:") && !strings.HasPrefix(to, "re:") {
			score += specificityPipeExact
		} else {
			score += specificityPipePattern
		}
	}
	for _, from := range r.Pipe.From {
		if !strings.HasPrefix(from, "path:") && !strings.HasPrefix(from, "re:") {
			score += specificityPipeExact
		} else {
			score += specificityPipePattern
		}
	}

	return score
}

// countBoolExprItems counts the number of items in a boolean expression tree.
func countBoolExprItems(expr *BoolExpr) int {
	if expr == nil {
		return 0
	}
	count := len(expr.Patterns)
	if expr.IsSequence {
		count += len(expr.Sequence)
	}
	for _, child := range expr.Any {
		count += countBoolExprItems(child)
	}
	for _, child := range expr.All {
		count += countBoolExprItems(child)
	}
	if expr.Not != nil {
		count += countBoolExprItems(expr.Not)
	}
	for _, child := range expr.Xor {
		count += countBoolExprItems(child)
	}
	return count
}

// Specificity computes a specificity score for a redirect rule.
func (r RedirectRule) Specificity() int {
	score := 0
	score += len(r.Paths) * specificityPipePattern
	if r.Append != nil {
		score += specificityAppend
	}
	return score
}

// Specificity computes a specificity score for a heredoc rule.
func (r HeredocRule) Specificity() int {
	return countBoolExprItems(r.Content) * specificityContentMatch
}
