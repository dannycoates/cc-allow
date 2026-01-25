package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Current config version - bump when making breaking changes
const (
	ConfigVersionMajor = 1
	ConfigVersionMinor = 0
)

// Config represents the complete configuration for cc-allow.
type Config struct {
	Version         string                  `toml:"version"` // config format version (e.g., "1.0")
	Path            string                  `toml:"-"`       // path this config was loaded from (not in TOML)
	Aliases         map[string]Alias        `toml:"aliases"` // named pattern aliases for reuse
	Policy          PolicyConfig            `toml:"policy"`
	Commands        CommandsConfig          `toml:"commands"` // DEPRECATED: old format
	Files           FilesConfig             `toml:"files"`    // file tool permissions (Read, Edit, Write)
	Rules           []Rule                  `toml:"rule"`     // DEPRECATED: old [[rule]] format
	Allow           ActionSection           `toml:"allow"`    // NEW: [allow] section
	Deny            ActionSection           `toml:"deny"`     // NEW: [deny] section
	Ask             ActionSection           `toml:"ask"`      // NEW: [ask] section
	RedirectsPolicy RedirectsConfig         `toml:"redirects"` // redirect policy settings
	Redirects       []RedirectRule          `toml:"redirect"`  // redirect rules
	Heredocs        []HeredocRule           `toml:"heredoc"`
	Constructs      ConstructsConfig        `toml:"constructs"`
	Debug           DebugConfig             `toml:"debug"`
}

// Alias holds one or more patterns that can be referenced with alias:name.
// Can be parsed from either a string or array of strings in TOML.
type Alias struct {
	Patterns []string
}

// UnmarshalTOML implements custom TOML unmarshaling for Alias.
func (pa *Alias) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		pa.Patterns = []string{v}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				pa.Patterns = append(pa.Patterns, s)
			} else {
				return fmt.Errorf("array elements must be strings")
			}
		}
	default:
		return fmt.Errorf("expected string or array, got %T", data)
	}
	return nil
}

// ActionSection represents [allow], [deny], or [ask] sections.
// Contains bulk command lists and a map for [[allow.X]] complex rules.
type ActionSection struct {
	Commands []string `toml:"commands"` // bulk list of command names
	Message  string   `toml:"message"`  // shared message for bulk commands
	// Complex rules are parsed separately via raw TOML access
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
	Deny    []string `toml:"deny"`    // patterns to deny
	Message string   `toml:"message"` // custom message for denials
}

// Rule represents a detailed command rule with argument matching.
type Rule struct {
	Command          string      `toml:"command"`           // command name or "path:*" for any
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
	From []string `toml:"from"` // deny if receiving piped input from any of these
}

// Specificity scoring constants for CSS-like rule matching.
const (
	specificityCommand      = 100 // exact command name (vs pattern)
	specificityPositionArg  = 20  // each args.position entry
	specificityContainsArg  = 10  // each args.contains entry
	specificityPatternArg   = 5   // each args.any_match or args.all_match entry
	specificityPipeExact    = 10  // each exact pipe.to or pipe.from entry
	specificityPipePattern  = 5   // each pattern pipe.to or pipe.from entry
	specificityExact        = 10  // each exact match entry
	specificityPattern      = 5   // each pattern entry
	specificityAppend       = 5   // append mode specified
	specificityContentMatch = 10  // each content match pattern
)

// isExactPattern returns true if the pattern is a literal/exact match (no prefix).
func isExactPattern(pattern string) bool {
	p, err := ParsePattern(pattern)
	if err != nil {
		return false
	}
	return p.Type == PatternLiteral
}

// Specificity computes a CSS-like specificity score for a command rule.
func (r Rule) Specificity() int {
	score := 0

	if isExactPattern(r.Command) {
		score += specificityCommand
	}

	score += len(r.Args.Position) * specificityPositionArg
	score += len(r.Args.Contains) * specificityContainsArg
	score += len(r.Args.AnyMatch) * specificityPatternArg
	score += len(r.Args.AllMatch) * specificityPatternArg

	for _, to := range r.Pipe.To {
		if isExactPattern(to) {
			score += specificityPipeExact
		} else {
			score += specificityPipePattern
		}
	}
	for _, from := range r.Pipe.From {
		if isExactPattern(from) {
			score += specificityPipeExact
		} else {
			score += specificityPipePattern
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
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
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
	return cfg, nil
}

// parseConfigInternal parses TOML and extracts nested command rules.
func parseConfigInternal(data string) (*Config, error) {
	var cfg Config

	// First, decode the standard fields
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Validate config version
	if err := validateConfigVersion(cfg.Version); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Also decode into a raw map to extract nested rules
	var raw map[string]interface{}
	if _, err := toml.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Parse nested command rules from action sections
	nestedRules, err := parseNestedRules(raw, cfg.Aliases)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Append nested rules to the rules list
	cfg.Rules = append(cfg.Rules, nestedRules...)

	// Convert bulk command lists from action sections to rules
	bulkRules := convertBulkCommandsToRules(&cfg)
	cfg.Rules = append(cfg.Rules, bulkRules...)

	// Resolve aliases in all patterns
	if err := resolveAliasesInConfig(&cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	return &cfg, nil
}

// isReservedActionKey returns true if the key is a reserved field in action sections.
func isReservedActionKey(key string) bool {
	reserved := map[string]bool{
		"commands": true,
		"message":  true,
	}
	return reserved[key]
}

// isReservedRuleKey returns true if the key is a reserved field in rule tables.
func isReservedRuleKey(key string) bool {
	reserved := map[string]bool{
		"message":           true,
		"args":              true,
		"pipe":              true,
		"respect_file_rules": true,
		"file_access_type":  true,
	}
	return reserved[key]
}

// parseNestedRules extracts rules from [[allow.X]], [[deny.X]], [[ask.X]] tables.
func parseNestedRules(raw map[string]interface{}, aliases map[string]Alias) ([]Rule, error) {
	var rules []Rule

	for _, action := range []string{"allow", "deny", "ask"} {
		section, ok := raw[action]
		if !ok {
			continue
		}
		sectionMap, ok := section.(map[string]interface{})
		if !ok {
			continue
		}

		// Walk through non-reserved keys looking for command rules
		sectionRules, err := walkActionSection(sectionMap, action, []string{})
		if err != nil {
			return nil, fmt.Errorf("[%s]: %w", action, err)
		}
		rules = append(rules, sectionRules...)
	}

	return rules, nil
}

// walkActionSection recursively walks an action section to find command rules.
// path tracks the nesting level (e.g., ["git", "push"] for [[allow.git.push]])
func walkActionSection(node map[string]interface{}, action string, path []string) ([]Rule, error) {
	var rules []Rule

	for key, value := range node {
		// Skip reserved keys at the section level
		if len(path) == 0 && isReservedActionKey(key) {
			continue
		}

		switch v := value.(type) {
		case []interface{}:
			// Array of tables: [[allow.rm]] or [[deny.git.push]]
			for _, item := range v {
				table, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s]: %w", key, err)
				}
				rules = append(rules, rule)
			}
		case []map[string]interface{}:
			// Array of tables (alternate TOML representation)
			for _, table := range v {
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s]: %w", key, err)
				}
				rules = append(rules, rule)
			}
		case map[string]interface{}:
			// Could be nested path or a single table
			// Check if it looks like a rule table (has rule fields) or a nested path
			if looksLikeRuleTable(v) && len(path) > 0 {
				// Single rule table (e.g., [allow.rm] instead of [[allow.rm]])
				rule, err := parseRuleFromTable(action, append(path, key), v)
				if err != nil {
					return nil, fmt.Errorf("[%s]: %w", key, err)
				}
				rules = append(rules, rule)
			} else {
				// Nested path - recurse
				nestedRules, err := walkActionSection(v, action, append(path, key))
				if err != nil {
					return nil, err
				}
				rules = append(rules, nestedRules...)
			}
		}
	}

	return rules, nil
}

// looksLikeRuleTable checks if a map contains rule-specific fields.
func looksLikeRuleTable(m map[string]interface{}) bool {
	for key := range m {
		if isReservedRuleKey(key) {
			return true
		}
	}
	// Empty table is also a valid rule (just matches the command)
	return len(m) == 0
}

// parseRuleFromTable converts a TOML table to a Rule struct.
// path is like ["git", "push"] for [[deny.git.push]]
func parseRuleFromTable(action string, path []string, table map[string]interface{}) (Rule, error) {
	if len(path) == 0 {
		return Rule{}, fmt.Errorf("empty command path")
	}

	rule := Rule{
		Command: path[0], // First element is the command name
		Action:  action,
	}

	// Build position map from remaining path elements
	if len(path) > 1 {
		rule.Args.Position = make(map[string]FlexiblePattern)
		for i, pos := range path[1:] {
			rule.Args.Position[strconv.Itoa(i)] = FlexiblePattern{Patterns: []string{pos}}
		}
	}

	// Extract message if present
	if msg, ok := table["message"].(string); ok {
		rule.Message = msg
	}

	// Extract args if present
	if argsRaw, ok := table["args"].(map[string]interface{}); ok {
		args, err := parseArgsMatch(argsRaw)
		if err != nil {
			return Rule{}, fmt.Errorf("args: %w", err)
		}
		// Merge with existing position rules
		if rule.Args.Position == nil && len(args.Position) > 0 {
			rule.Args.Position = args.Position
		} else if len(args.Position) > 0 {
			// Merge position maps
			for k, v := range args.Position {
				rule.Args.Position[k] = v
			}
		}
		rule.Args.Contains = args.Contains
		rule.Args.AnyMatch = args.AnyMatch
		rule.Args.AllMatch = args.AllMatch
	}

	// Extract pipe if present
	if pipeRaw, ok := table["pipe"].(map[string]interface{}); ok {
		pipe, err := parsePipeContext(pipeRaw)
		if err != nil {
			return Rule{}, fmt.Errorf("pipe: %w", err)
		}
		rule.Pipe = pipe
	}

	// Extract respect_file_rules if present
	if rfr, ok := table["respect_file_rules"].(bool); ok {
		rule.RespectFileRules = &rfr
	}

	// Extract file_access_type if present
	if fat, ok := table["file_access_type"].(string); ok {
		rule.FileAccessType = fat
	}

	return rule, nil
}

// parseArgsMatch parses an args table from raw TOML.
func parseArgsMatch(raw map[string]interface{}) (ArgsMatch, error) {
	var args ArgsMatch

	// Parse contains
	if containsRaw, ok := raw["contains"].([]interface{}); ok {
		for _, item := range containsRaw {
			if s, ok := item.(string); ok {
				args.Contains = append(args.Contains, s)
			}
		}
	}

	// Parse any_match
	if anyMatchRaw, ok := raw["any_match"].([]interface{}); ok {
		for _, item := range anyMatchRaw {
			elem, err := parseMatchElementRaw(item)
			if err != nil {
				return ArgsMatch{}, fmt.Errorf("any_match: %w", err)
			}
			args.AnyMatch = append(args.AnyMatch, elem)
		}
	}

	// Parse all_match
	if allMatchRaw, ok := raw["all_match"].([]interface{}); ok {
		for _, item := range allMatchRaw {
			elem, err := parseMatchElementRaw(item)
			if err != nil {
				return ArgsMatch{}, fmt.Errorf("all_match: %w", err)
			}
			args.AllMatch = append(args.AllMatch, elem)
		}
	}

	// Parse position
	if posRaw, ok := raw["position"].(map[string]interface{}); ok {
		args.Position = make(map[string]FlexiblePattern)
		for key, val := range posRaw {
			fp, err := parseFlexiblePatternRaw(val)
			if err != nil {
				return ArgsMatch{}, fmt.Errorf("position[%s]: %w", key, err)
			}
			args.Position[key] = fp
		}
	}

	return args, nil
}

// parseMatchElementRaw parses a MatchElement from raw TOML (string or object).
func parseMatchElementRaw(raw interface{}) (MatchElement, error) {
	switch v := raw.(type) {
	case string:
		return MatchElement{Pattern: v}, nil
	case map[string]interface{}:
		elem := MatchElement{IsSequence: true, Sequence: make(map[string]FlexiblePattern)}
		for key, val := range v {
			fp, err := parseFlexiblePatternRaw(val)
			if err != nil {
				return MatchElement{}, fmt.Errorf("position %s: %w", key, err)
			}
			elem.Sequence[key] = fp
		}
		return elem, nil
	default:
		return MatchElement{}, fmt.Errorf("expected string or object, got %T", raw)
	}
}

// parseFlexiblePatternRaw parses a FlexiblePattern from raw TOML (string or array).
func parseFlexiblePatternRaw(raw interface{}) (FlexiblePattern, error) {
	var fp FlexiblePattern
	switch v := raw.(type) {
	case string:
		fp.Patterns = []string{v}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				fp.Patterns = append(fp.Patterns, s)
			} else {
				return FlexiblePattern{}, fmt.Errorf("array elements must be strings")
			}
		}
	default:
		return FlexiblePattern{}, fmt.Errorf("expected string or array, got %T", raw)
	}
	return fp, nil
}

// parsePipeContext parses a pipe table from raw TOML.
func parsePipeContext(raw map[string]interface{}) (PipeContext, error) {
	var pipe PipeContext

	if toRaw, ok := raw["to"].([]interface{}); ok {
		for _, item := range toRaw {
			if s, ok := item.(string); ok {
				pipe.To = append(pipe.To, s)
			}
		}
	}

	if fromRaw, ok := raw["from"].([]interface{}); ok {
		for _, item := range fromRaw {
			if s, ok := item.(string); ok {
				pipe.From = append(pipe.From, s)
			}
		}
	}

	return pipe, nil
}

// convertBulkCommandsToRules converts [allow].commands, [deny].commands, [ask].commands to rules.
func convertBulkCommandsToRules(cfg *Config) []Rule {
	var rules []Rule

	// Process [allow].commands
	for _, cmd := range cfg.Allow.Commands {
		rules = append(rules, Rule{
			Command: cmd,
			Action:  "allow",
			Message: cfg.Allow.Message,
		})
	}

	// Process [deny].commands
	for _, cmd := range cfg.Deny.Commands {
		rules = append(rules, Rule{
			Command: cmd,
			Action:  "deny",
			Message: cfg.Deny.Message,
		})
	}

	// Process [ask].commands
	for _, cmd := range cfg.Ask.Commands {
		rules = append(rules, Rule{
			Command: cmd,
			Action:  "ask",
			Message: cfg.Ask.Message,
		})
	}

	return rules
}

// resolveAliasesInConfig expands all alias: patterns to their underlying patterns.
func resolveAliasesInConfig(cfg *Config) error {
	// Initialize empty map if nil to simplify checks
	if cfg.Aliases == nil {
		cfg.Aliases = make(map[string]Alias)
	}

	// Helper to expand aliases in a slice of strings
	expandPatterns := func(patterns []string) ([]string, error) {
		var result []string
		for _, p := range patterns {
			expanded, err := expandAlias(p, cfg.Aliases)
			if err != nil {
				return nil, err
			}
			result = append(result, expanded...)
		}
		return result, nil
	}

	// Expand aliases in rules
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]

		// Expand args.contains
		if expanded, err := expandPatterns(rule.Args.Contains); err != nil {
			return fmt.Errorf("rule[%d] args.contains: %w", i, err)
		} else {
			rule.Args.Contains = expanded
		}

		// Expand args.any_match
		for j := range rule.Args.AnyMatch {
			if err := expandMatchElement(&rule.Args.AnyMatch[j], cfg.Aliases); err != nil {
				return fmt.Errorf("rule[%d] args.any_match[%d]: %w", i, j, err)
			}
		}

		// Expand args.all_match
		for j := range rule.Args.AllMatch {
			if err := expandMatchElement(&rule.Args.AllMatch[j], cfg.Aliases); err != nil {
				return fmt.Errorf("rule[%d] args.all_match[%d]: %w", i, j, err)
			}
		}

		// Expand args.position
		for key, fp := range rule.Args.Position {
			if expanded, err := expandPatterns(fp.Patterns); err != nil {
				return fmt.Errorf("rule[%d] args.position[%s]: %w", i, key, err)
			} else {
				rule.Args.Position[key] = FlexiblePattern{Patterns: expanded}
			}
		}
	}

	// Expand aliases in files config
	fileTools := []*FileToolConfig{&cfg.Files.Read, &cfg.Files.Edit, &cfg.Files.Write}
	toolNames := []string{"read", "edit", "write"}
	for i, tool := range fileTools {
		if expanded, err := expandPatterns(tool.Allow); err != nil {
			return fmt.Errorf("files.%s.allow: %w", toolNames[i], err)
		} else {
			tool.Allow = expanded
		}
		if expanded, err := expandPatterns(tool.Deny); err != nil {
			return fmt.Errorf("files.%s.deny: %w", toolNames[i], err)
		} else {
			tool.Deny = expanded
		}
	}

	// Expand aliases in redirect rules
	for i := range cfg.Redirects {
		redirect := &cfg.Redirects[i]
		if expanded, err := expandPatterns(redirect.To.Pattern); err != nil {
			return fmt.Errorf("redirect[%d].to.pattern: %w", i, err)
		} else {
			redirect.To.Pattern = expanded
		}
	}

	// Expand aliases in action section command lists
	if expanded, err := expandPatterns(cfg.Allow.Commands); err != nil {
		return fmt.Errorf("allow.commands: %w", err)
	} else {
		cfg.Allow.Commands = expanded
	}
	if expanded, err := expandPatterns(cfg.Deny.Commands); err != nil {
		return fmt.Errorf("deny.commands: %w", err)
	} else {
		cfg.Deny.Commands = expanded
	}
	if expanded, err := expandPatterns(cfg.Ask.Commands); err != nil {
		return fmt.Errorf("ask.commands: %w", err)
	} else {
		cfg.Ask.Commands = expanded
	}

	// Expand aliases in old format command lists (backwards compat)
	if expanded, err := expandPatterns(cfg.Commands.Allow.Names); err != nil {
		return fmt.Errorf("commands.allow.names: %w", err)
	} else {
		cfg.Commands.Allow.Names = expanded
	}
	if expanded, err := expandPatterns(cfg.Commands.Deny.Names); err != nil {
		return fmt.Errorf("commands.deny.names: %w", err)
	} else {
		cfg.Commands.Deny.Names = expanded
	}

	return nil
}

// expandAlias expands a single pattern, returning the underlying patterns if it's an alias.
func expandAlias(pattern string, aliases map[string]Alias) ([]string, error) {
	if !strings.HasPrefix(pattern, "alias:") {
		return []string{pattern}, nil
	}

	aliasName := strings.TrimPrefix(pattern, "alias:")
	alias, ok := aliases[aliasName]
	if !ok {
		return nil, fmt.Errorf("undefined alias: %s", aliasName)
	}

	// Recursively expand in case aliases reference other aliases
	var result []string
	for _, p := range alias.Patterns {
		expanded, err := expandAlias(p, aliases)
		if err != nil {
			return nil, err
		}
		result = append(result, expanded...)
	}

	return result, nil
}

// expandMatchElement expands aliases in a MatchElement.
func expandMatchElement(elem *MatchElement, aliases map[string]Alias) error {
	if elem.IsSequence {
		for key, fp := range elem.Sequence {
			var expanded []string
			for _, p := range fp.Patterns {
				e, err := expandAlias(p, aliases)
				if err != nil {
					return err
				}
				expanded = append(expanded, e...)
			}
			elem.Sequence[key] = FlexiblePattern{Patterns: expanded}
		}
	} else {
		if strings.HasPrefix(elem.Pattern, "alias:") {
			expanded, err := expandAlias(elem.Pattern, aliases)
			if err != nil {
				return err
			}
			// If alias expands to multiple patterns, we need to convert to something else
			// For now, just use the first pattern (this is a limitation)
			if len(expanded) > 0 {
				elem.Pattern = expanded[0]
			}
		}
	}
	return nil
}

// parseConfigRaw parses a TOML configuration string WITHOUT applying defaults.
// Empty strings mean "unset" - the caller is responsible for applying defaults
// after merging multiple configs.
func parseConfigRaw(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	// NO defaults applied - empty strings mean "unset"
	// Still validate patterns
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
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

// validateConfigVersion checks if the config version is supported.
// Empty version is allowed (assumes legacy format).
// Returns error if version is newer than supported.
func validateConfigVersion(version string) error {
	// Empty version is allowed - assumes legacy/current format
	if version == "" {
		return nil
	}

	// Parse major.minor
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid version format %q: expected major.minor (e.g., \"1.0\")", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid version major %q: %w", parts[0], err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid version minor %q: %w", parts[1], err)
	}

	// Check if version is supported
	if major > ConfigVersionMajor {
		return fmt.Errorf("config version %q is not supported (max supported: %d.%d)", version, ConfigVersionMajor, ConfigVersionMinor)
	}
	if major == ConfigVersionMajor && minor > ConfigVersionMinor {
		return fmt.Errorf("config version %q is not supported (max supported: %d.%d)", version, ConfigVersionMajor, ConfigVersionMinor)
	}

	return nil
}

// Validate checks that all patterns in the config are valid.
// This catches invalid regex patterns at load time rather than at evaluation time.
func (cfg *Config) Validate() error {
	// Validate aliases (check for reserved prefixes)
	for name := range cfg.Aliases {
		if strings.HasPrefix(name, "path:") || strings.HasPrefix(name, "glob:") ||
			strings.HasPrefix(name, "re:") || strings.HasPrefix(name, "flags:") ||
			strings.HasPrefix(name, "alias:") || strings.HasPrefix(name, "files:") {
			return fmt.Errorf("%w: aliases: name %q cannot start with a reserved prefix", ErrInvalidConfig, name)
		}
	}

	// Validate commands.allow.names patterns (old format - for backwards compat during transition)
	for i, name := range cfg.Commands.Allow.Names {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: commands.allow.names[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate commands.deny.names patterns (old format - for backwards compat during transition)
	for i, name := range cfg.Commands.Deny.Names {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: commands.deny.names[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate [allow].commands patterns (new format)
	for i, name := range cfg.Allow.Commands {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: allow.commands[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate [deny].commands patterns (new format)
	for i, name := range cfg.Deny.Commands {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: deny.commands[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate [ask].commands patterns (new format)
	for i, name := range cfg.Ask.Commands {
		if _, err := ParsePattern(name); err != nil {
			return fmt.Errorf("%w: ask.commands[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate command rules
	for i, rule := range cfg.Rules {
		// Validate rule.command pattern
		if rule.Command != "" {
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
