package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// loadConfig reads and parses a TOML configuration file without applying defaults.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := parseConfig(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// parseConfig parses a TOML configuration string without applying defaults.
func parseConfig(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadConfigWithDefaults reads and parses a TOML configuration file with defaults applied.
func LoadConfigWithDefaults(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %w", ErrConfigRead, path, err)
	}
	cfg, err := ParseConfigWithDefaults(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	return cfg, nil
}

// ParseConfigWithDefaults parses a TOML configuration string with defaults applied.
func ParseConfigWithDefaults(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	if cfg.Path == "" {
		cfg.Path = "(inline)"
	}
	applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseConfigInternal parses TOML and extracts nested command rules.
func parseConfigInternal(data string) (*Config, error) {
	// Decode once into raw map
	var raw map[string]any
	if _, err := toml.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Check version
	version, _ := raw["version"].(string)
	if err := validateConfigVersion(version, raw); err != nil {
		return nil, err
	}

	// Build config from raw map
	cfg, err := configFromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Resolve aliases in all patterns
	if err := resolveAliasesInConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	return cfg, nil
}

// configFromRaw builds a Config from a raw TOML map.
func configFromRaw(raw map[string]any) (*Config, error) {
	cfg := &Config{}

	// Extract version
	cfg.Version, _ = raw["version"].(string)

	// Extract aliases
	if aliasesRaw, ok := raw["aliases"].(map[string]any); ok {
		aliases, err := parseAliasesFromRaw(aliasesRaw)
		if err != nil {
			return nil, fmt.Errorf("aliases: %w", err)
		}
		cfg.Aliases = aliases
	}

	// Extract bash config
	if bashRaw, ok := raw["bash"].(map[string]any); ok {
		bashCfg, err := parseBashConfigFromRaw(bashRaw, cfg.Aliases)
		if err != nil {
			return nil, fmt.Errorf("bash: %w", err)
		}
		cfg.Bash = bashCfg.config
		cfg.parsedRules = bashCfg.rules
		cfg.parsedRedirects = bashCfg.redirects
		cfg.parsedHeredocs = bashCfg.heredocs
	}

	// Extract file tool configs
	if readRaw, ok := raw["read"].(map[string]any); ok {
		cfg.Read = parseFileToolConfigFromRaw(readRaw)
	}
	if writeRaw, ok := raw["write"].(map[string]any); ok {
		cfg.Write = parseFileToolConfigFromRaw(writeRaw)
	}
	if editRaw, ok := raw["edit"].(map[string]any); ok {
		cfg.Edit = parseFileToolConfigFromRaw(editRaw)
	}

	// Extract debug config
	if debugRaw, ok := raw["debug"].(map[string]any); ok {
		cfg.Debug.LogFile, _ = debugRaw["log_file"].(string)
	}

	return cfg, nil
}

// parseAliasesFromRaw parses the aliases section.
func parseAliasesFromRaw(raw map[string]any) (map[string]Alias, error) {
	aliases := make(map[string]Alias)
	for name, val := range raw {
		var alias Alias
		if err := alias.UnmarshalTOML(val); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		aliases[name] = alias
	}
	return aliases, nil
}

// bashConfigResult holds the parsed bash config and nested rules.
type bashConfigResult struct {
	config    BashConfig
	rules     []BashRule
	redirects []RedirectRule
	heredocs  []HeredocRule
}

// parseBashConfigFromRaw parses the bash section.
func parseBashConfigFromRaw(raw map[string]any, aliases map[string]Alias) (*bashConfigResult, error) {
	result := &bashConfigResult{}

	// Extract scalar fields
	result.config.Default, _ = raw["default"].(string)
	result.config.DynamicCommands, _ = raw["dynamic_commands"].(string)
	result.config.UnresolvedCommands, _ = raw["unresolved_commands"].(string)
	result.config.DefaultMessage, _ = raw["default_message"].(string)

	// Extract respect_file_rules
	if rfr, ok := raw["respect_file_rules"].(bool); ok {
		result.config.RespectFileRules = &rfr
	}

	// Extract constructs
	if constructsRaw, ok := raw["constructs"].(map[string]any); ok {
		result.config.Constructs.Subshells, _ = constructsRaw["subshells"].(string)
		result.config.Constructs.Background, _ = constructsRaw["background"].(string)
		result.config.Constructs.FunctionDefinitions, _ = constructsRaw["function_definitions"].(string)
		result.config.Constructs.Heredocs, _ = constructsRaw["heredocs"].(string)
	}

	// Extract allow section
	if allowRaw, ok := raw["allow"].(map[string]any); ok {
		result.config.Allow = parseBashAllowDenyFromRaw(allowRaw)
	}

	// Extract deny section
	if denyRaw, ok := raw["deny"].(map[string]any); ok {
		result.config.Deny = parseBashAllowDenyFromRaw(denyRaw)
	}

	// Parse nested command rules
	rules, err := parseBashRules(raw, aliases)
	if err != nil {
		return nil, err
	}
	result.rules = rules

	// Extract redirects section
	if redirectsRaw, ok := raw["redirects"].(map[string]any); ok {
		// Extract respect_file_rules for redirects
		if rfr, ok := redirectsRaw["respect_file_rules"].(bool); ok {
			result.config.Redirects.RespectFileRules = &rfr
		}

		// Parse redirect rules
		redirectRules, err := parseRedirectRules(redirectsRaw)
		if err != nil {
			return nil, fmt.Errorf("redirects: %w", err)
		}
		result.redirects = redirectRules
	}

	// Extract heredocs section
	if heredocsRaw, ok := raw["heredocs"].(map[string]any); ok {
		heredocRules, err := parseHeredocRules(heredocsRaw)
		if err != nil {
			return nil, fmt.Errorf("heredocs: %w", err)
		}
		result.heredocs = heredocRules
	}

	return result, nil
}

// parseBashAllowDenyFromRaw parses a bash.allow or bash.deny section.
func parseBashAllowDenyFromRaw(raw map[string]any) BashAllowDeny {
	var result BashAllowDeny

	// Extract commands array
	if cmds, ok := raw["commands"].([]any); ok {
		for _, cmd := range cmds {
			if s, ok := cmd.(string); ok {
				result.Commands = append(result.Commands, s)
			}
		}
	}

	// Extract message
	result.Message, _ = raw["message"].(string)

	// Extract mode
	result.Mode, _ = raw["mode"].(string)

	return result
}

// parseFileToolConfigFromRaw parses a read/write/edit section.
func parseFileToolConfigFromRaw(raw map[string]any) FileToolConfig {
	var cfg FileToolConfig

	cfg.Default, _ = raw["default"].(string)

	if allowRaw, ok := raw["allow"].(map[string]any); ok {
		cfg.Allow = parseFileAllowDenyFromRaw(allowRaw)
	}

	if denyRaw, ok := raw["deny"].(map[string]any); ok {
		cfg.Deny = parseFileAllowDenyFromRaw(denyRaw)
	}

	return cfg
}

// parseFileAllowDenyFromRaw parses a file tool allow/deny section.
func parseFileAllowDenyFromRaw(raw map[string]any) FileAllowDeny {
	var result FileAllowDeny

	if paths, ok := raw["paths"].([]any); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok {
				result.Paths = append(result.Paths, s)
			}
		}
	}

	result.Message, _ = raw["message"].(string)

	// Extract mode
	result.Mode, _ = raw["mode"].(string)

	return result
}

// validateConfigVersion checks the version and detects legacy format.
func validateConfigVersion(version string, raw map[string]any) error {
	// Check for legacy v1 format
	if isLegacyV1Config(raw) {
		return LegacyConfigError{Path: "(inline)"}
	}

	// Empty version is allowed for v2 if no legacy markers
	if version == "" {
		return nil
	}

	// Parse major.minor
	parts := strings.Split(version, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid version format %q: expected major.minor (e.g., \"2.0\")", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid version major %q: %w", parts[0], err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid version minor %q: %w", parts[1], err)
	}

	// v1.x configs should have been caught by legacy detection
	if major < ConfigVersionMajor {
		return fmt.Errorf("config version %q uses legacy format\nSee https://github.com/anthropics/cc-allow/docs/config-v2.md for migration guide", version)
	}

	// Check if version is too new
	if major > ConfigVersionMajor {
		return fmt.Errorf("config version %q is not supported (max supported: %d.%d)", version, ConfigVersionMajor, ConfigVersionMinor)
	}
	if major == ConfigVersionMajor && minor > ConfigVersionMinor {
		return fmt.Errorf("config version %q is not supported (max supported: %d.%d)", version, ConfigVersionMajor, ConfigVersionMinor)
	}

	return nil
}

// parseBashRules extracts rules from [bash.allow.X] and [bash.deny.X] tables.
func parseBashRules(bashRaw map[string]any, aliases map[string]Alias) ([]BashRule, error) {
	var rules []BashRule

	// Parse [bash.allow] section
	if allowRaw, ok := bashRaw["allow"].(map[string]any); ok {
		allowRules, err := parseActionSection(allowRaw, "allow", []string{})
		if err != nil {
			return nil, fmt.Errorf("allow: %w", err)
		}
		rules = append(rules, allowRules...)
	}

	// Parse [bash.deny] section
	if denyRaw, ok := bashRaw["deny"].(map[string]any); ok {
		denyRules, err := parseActionSection(denyRaw, "deny", []string{})
		if err != nil {
			return nil, fmt.Errorf("deny: %w", err)
		}
		rules = append(rules, denyRules...)
	}

	return rules, nil
}

// parseActionSection recursively walks an action section to find command rules.
func parseActionSection(node map[string]any, action string, path []string) ([]BashRule, error) {
	var rules []BashRule

	for key, value := range node {
		// Skip reserved keys at section level
		if len(path) == 0 && isReservedBashKey(key) {
			continue
		}

		switch v := value.(type) {
		case []map[string]any:
			// Array of tables: [[bash.allow.rm]] or [[bash.deny.git.push]]
			// TOML decodes these as []map[string]interface{}
			for i, table := range v {
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s][%d]: %w", key, i, err)
				}
				rules = append(rules, rule)
			}
		case []any:
			// Fallback for arrays (shouldn't normally happen for rule tables)
			for i, item := range v {
				table, ok := item.(map[string]any)
				if !ok {
					continue
				}
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s][%d]: %w", key, i, err)
				}
				rules = append(rules, rule)
			}
		case map[string]any:
			// Could be a single rule table or nested path
			if looksLikeRuleTable(v) && len(path) > 0 {
				// Single rule table
				rule, err := parseRuleFromTable(action, append(path, key), v)
				if err != nil {
					return nil, fmt.Errorf("[%s]: %w", key, err)
				}
				rules = append(rules, rule)
			} else {
				// Nested path - recurse
				nestedRules, err := parseActionSection(v, action, append(path, key))
				if err != nil {
					return nil, err
				}
				rules = append(rules, nestedRules...)
			}
		}
	}

	return rules, nil
}

// isReservedBashKey returns true if the key is a reserved field in bash sections.
func isReservedBashKey(key string) bool {
	reserved := map[string]bool{
		"commands": true,
		"message":  true,
		"mode":     true,
	}
	return reserved[key]
}

// isReservedRuleKey returns true if the key is a reserved field in rule tables.
func isReservedRuleKey(key string) bool {
	reserved := map[string]bool{
		"message":            true,
		"args":               true,
		"pipe":               true,
		"respect_file_rules": true,
		"file_access_type":   true,
	}
	return reserved[key]
}

// looksLikeRuleTable checks if a map contains rule-specific fields.
func looksLikeRuleTable(m map[string]any) bool {
	for key := range m {
		if isReservedRuleKey(key) {
			return true
		}
	}
	// Empty table is also a valid rule (just matches the command)
	return len(m) == 0
}

// parseRuleFromTable converts a TOML table to a BashRule.
func parseRuleFromTable(action string, path []string, table map[string]any) (BashRule, error) {
	if len(path) == 0 {
		return BashRule{}, fmt.Errorf("empty command path")
	}

	rule := BashRule{
		Command:     path[0],
		Subcommands: path[1:],
		Action:      action,
	}

	// Extract message
	if msg, ok := table["message"].(string); ok {
		rule.Message = msg
	}

	// Extract args
	if argsRaw, ok := table["args"].(map[string]any); ok {
		args, err := parseArgsMatch(argsRaw)
		if err != nil {
			return BashRule{}, fmt.Errorf("args: %w", err)
		}
		rule.Args = args
	}

	// Extract pipe
	if pipeRaw, ok := table["pipe"].(map[string]any); ok {
		pipe, err := parsePipeContext(pipeRaw)
		if err != nil {
			return BashRule{}, fmt.Errorf("pipe: %w", err)
		}
		rule.Pipe = pipe
	}

	// Extract respect_file_rules
	if rfr, ok := table["respect_file_rules"].(bool); ok {
		rule.RespectFileRules = &rfr
	}

	// Extract file_access_type
	if fat, ok := table["file_access_type"].(string); ok {
		rule.FileAccessType = fat
	}

	return rule, nil
}

// parseArgsMatch parses an args table.
func parseArgsMatch(raw map[string]any) (ArgsMatch, error) {
	var args ArgsMatch

	// Parse any - uses OR semantics
	if anyRaw, ok := raw["any"]; ok {
		expr, err := parseBoolExprItemWithSemantics(anyRaw, false)
		if err != nil {
			return ArgsMatch{}, fmt.Errorf("any: %w", err)
		}
		args.Any = expr
	}

	// Parse all - uses AND semantics
	if allRaw, ok := raw["all"]; ok {
		expr, err := parseBoolExprItemWithSemantics(allRaw, true)
		if err != nil {
			return ArgsMatch{}, fmt.Errorf("all: %w", err)
		}
		args.All = expr
	}

	// Parse not
	if notRaw, ok := raw["not"]; ok {
		expr, err := parseBoolExprItemWithSemantics(notRaw, false)
		if err != nil {
			return ArgsMatch{}, fmt.Errorf("not: %w", err)
		}
		args.Not = expr
	}

	// Parse xor
	if xorRaw, ok := raw["xor"]; ok {
		expr, err := parseBoolExprItem(xorRaw)
		if err != nil {
			return ArgsMatch{}, fmt.Errorf("xor: %w", err)
		}
		args.Xor = expr
	}

	// Parse position
	if posRaw, ok := raw["position"].(map[string]any); ok {
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

// parsePipeContext parses a pipe table.
func parsePipeContext(raw map[string]any) (PipeContext, error) {
	var pipe PipeContext

	if toRaw, ok := raw["to"]; ok {
		to, err := parseStringOrArray(toRaw)
		if err != nil {
			return PipeContext{}, fmt.Errorf("to: %w", err)
		}
		pipe.To = to
	}

	if fromRaw, ok := raw["from"]; ok {
		from, err := parseStringOrArray(fromRaw)
		if err != nil {
			return PipeContext{}, fmt.Errorf("from: %w", err)
		}
		pipe.From = from
	}

	return pipe, nil
}

// parseStringOrArray parses a value that can be either a string or array of strings.
func parseStringOrArray(val any) ([]string, error) {
	switch v := val.(type) {
	case string:
		return []string{v}, nil
	case []any:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			} else {
				return nil, fmt.Errorf("array elements must be strings")
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("expected string or array, got %T", val)
	}
}

// toTableSlice normalizes TOML array-of-tables to []map[string]interface{}.
// TOML libraries may decode [[section]] as either []map[string]interface{}
// or []interface{} depending on the content. This helper handles both.
func toTableSlice(raw any) []map[string]any {
	if raw == nil {
		return nil
	}
	// Try direct type first (more efficient)
	if tables, ok := raw.([]map[string]any); ok {
		return tables
	}
	// Fall back to []interface{} and convert
	if items, ok := raw.([]any); ok {
		tables := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if table, ok := item.(map[string]any); ok {
				tables = append(tables, table)
			}
		}
		return tables
	}
	return nil
}

// parseRedirectRules parses redirect rules from [bash.redirects].
func parseRedirectRules(raw map[string]any) ([]RedirectRule, error) {
	var rules []RedirectRule

	// Parse [[bash.redirects.allow]]
	for i, table := range toTableSlice(raw["allow"]) {
		rule, err := parseRedirectRule("allow", table)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	// Parse [[bash.redirects.deny]]
	for i, table := range toTableSlice(raw["deny"]) {
		rule, err := parseRedirectRule("deny", table)
		if err != nil {
			return nil, fmt.Errorf("deny[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRedirectRule parses a single redirect rule.
func parseRedirectRule(action string, table map[string]any) (RedirectRule, error) {
	rule := RedirectRule{Action: action}

	if msg, ok := table["message"].(string); ok {
		rule.Message = msg
	}

	if paths, ok := table["paths"].([]any); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok {
				rule.Paths = append(rule.Paths, s)
			}
		}
	}

	if append, ok := table["append"].(bool); ok {
		rule.Append = &append
	}

	return rule, nil
}

// parseHeredocRules parses heredoc rules from [bash.heredocs].
func parseHeredocRules(raw map[string]any) ([]HeredocRule, error) {
	var rules []HeredocRule

	// Parse [[bash.heredocs.allow]]
	for i, table := range toTableSlice(raw["allow"]) {
		rule, err := parseHeredocRule("allow", table)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	// Parse [[bash.heredocs.deny]]
	for i, table := range toTableSlice(raw["deny"]) {
		rule, err := parseHeredocRule("deny", table)
		if err != nil {
			return nil, fmt.Errorf("deny[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseHeredocRule parses a single heredoc rule.
func parseHeredocRule(action string, table map[string]any) (HeredocRule, error) {
	rule := HeredocRule{Action: action}

	if msg, ok := table["message"].(string); ok {
		rule.Message = msg
	}

	if contentRaw, ok := table["content"]; ok {
		expr, err := parseBoolExprItem(contentRaw)
		if err != nil {
			return HeredocRule{}, fmt.Errorf("content: %w", err)
		}
		rule.Content = expr
	}

	return rule, nil
}

// applyDefaults sets default values for unset fields.
func applyDefaults(cfg *Config) {
	if cfg.Bash.Default == "" {
		cfg.Bash.Default = "ask"
	}
	if cfg.Bash.DynamicCommands == "" {
		cfg.Bash.DynamicCommands = "ask"
	}
	if cfg.Bash.UnresolvedCommands == "" {
		cfg.Bash.UnresolvedCommands = "ask"
	}
	if cfg.Bash.DefaultMessage == "" {
		cfg.Bash.DefaultMessage = "Command not allowed"
	}
	if cfg.Bash.Constructs.Subshells == "" {
		cfg.Bash.Constructs.Subshells = "ask"
	}
	if cfg.Bash.Constructs.FunctionDefinitions == "" {
		cfg.Bash.Constructs.FunctionDefinitions = "ask"
	}
	if cfg.Bash.Constructs.Background == "" {
		cfg.Bash.Constructs.Background = "ask"
	}
	if cfg.Bash.Constructs.Heredocs == "" {
		cfg.Bash.Constructs.Heredocs = "allow"
	}
	if cfg.Read.Default == "" {
		cfg.Read.Default = "ask"
	}
	if cfg.Write.Default == "" {
		cfg.Write.Default = "ask"
	}
	if cfg.Edit.Default == "" {
		cfg.Edit.Default = "ask"
	}
}

// isValidAction checks if a string is a valid action value.
func isValidAction(action string) bool {
	switch action {
	case "allow", "deny", "ask", "":
		return true
	default:
		return false
	}
}

// validateAction checks that an action value is valid, returning an error if not.
func validateAction(action, field string) error {
	if !isValidAction(action) {
		return fmt.Errorf("%w: %s: invalid action %q (must be \"allow\", \"deny\", or \"ask\")", ErrInvalidConfig, field, action)
	}
	return nil
}

// validateAllowMode checks that an allow mode value is valid.
func validateAllowMode(mode, field string) error {
	if mode != "" && mode != "merge" && mode != "replace" {
		return fmt.Errorf("%w: %s: invalid mode %q (must be \"merge\" or \"replace\")", ErrInvalidConfig, field, mode)
	}
	return nil
}

// Validate checks that all patterns in the config are valid.
func (cfg *Config) Validate() error {
	// Validate action values
	if err := validateAction(cfg.Bash.Default, "bash.default"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.DynamicCommands, "bash.dynamic_commands"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.UnresolvedCommands, "bash.unresolved_commands"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.Constructs.Subshells, "bash.constructs.subshells"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.Constructs.Background, "bash.constructs.background"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.Constructs.FunctionDefinitions, "bash.constructs.function_definitions"); err != nil {
		return err
	}
	if err := validateAction(cfg.Bash.Constructs.Heredocs, "bash.constructs.heredocs"); err != nil {
		return err
	}
	if err := validateAction(cfg.Read.Default, "read.default"); err != nil {
		return err
	}
	if err := validateAction(cfg.Write.Default, "write.default"); err != nil {
		return err
	}
	if err := validateAction(cfg.Edit.Default, "edit.default"); err != nil {
		return err
	}
	// Validate allow mode values
	if err := validateAllowMode(cfg.Bash.Allow.Mode, "bash.allow.mode"); err != nil {
		return err
	}
	if err := validateAllowMode(cfg.Read.Allow.Mode, "read.allow.mode"); err != nil {
		return err
	}
	if err := validateAllowMode(cfg.Write.Allow.Mode, "write.allow.mode"); err != nil {
		return err
	}
	if err := validateAllowMode(cfg.Edit.Allow.Mode, "edit.allow.mode"); err != nil {
		return err
	}

	// Validate aliases
	for name, alias := range cfg.Aliases {
		if strings.HasPrefix(name, "path:") || strings.HasPrefix(name, "re:") ||
			strings.HasPrefix(name, "flags:") || strings.HasPrefix(name, "alias:") ||
			strings.HasPrefix(name, "ref:") {
			return fmt.Errorf("%w: aliases: name %q cannot start with a reserved prefix", ErrInvalidConfig, name)
		}
		// Aliases cannot reference other aliases (prevents circular references)
		for i, pattern := range alias.Patterns {
			if strings.HasPrefix(pattern, "alias:") {
				return fmt.Errorf("%w: aliases[%s][%d]: aliases cannot reference other aliases", ErrInvalidConfig, name, i)
			}
		}
	}

	// Validate bash.allow.commands patterns
	for i, cmd := range cfg.Bash.Allow.Commands {
		if _, err := ParsePattern(cmd); err != nil {
			return fmt.Errorf("%w: bash.allow.commands[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate bash.deny.commands patterns
	for i, cmd := range cfg.Bash.Deny.Commands {
		if _, err := ParsePattern(cmd); err != nil {
			return fmt.Errorf("%w: bash.deny.commands[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	// Validate parsed rules
	for i, rule := range cfg.getParsedRules() {
		if _, err := ParsePattern(rule.Command); err != nil {
			return fmt.Errorf("%w: bash rule[%d] command: %w", ErrInvalidConfig, i, err)
		}
		if err := validateArgsMatch(rule.Args, fmt.Sprintf("bash rule[%d]", i)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}

	// Validate redirect rules
	for i, rule := range cfg.getParsedRedirects() {
		for j, path := range rule.Paths {
			if _, err := ParsePattern(path); err != nil {
				return fmt.Errorf("%w: bash.redirects rule[%d] paths[%d]: %w", ErrInvalidConfig, i, j, err)
			}
		}
	}

	// Validate heredoc rules
	for i, rule := range cfg.getParsedHeredocs() {
		if err := validateBoolExpr(rule.Content, fmt.Sprintf("bash.heredocs rule[%d]", i)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}

	// Validate file tool patterns
	for i, path := range cfg.Read.Allow.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: read.allow.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}
	for i, path := range cfg.Read.Deny.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: read.deny.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}
	for i, path := range cfg.Write.Allow.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: write.allow.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}
	for i, path := range cfg.Write.Deny.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: write.deny.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}
	for i, path := range cfg.Edit.Allow.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: edit.allow.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}
	for i, path := range cfg.Edit.Deny.Paths {
		if _, err := ParsePattern(path); err != nil {
			return fmt.Errorf("%w: edit.deny.paths[%d]: %w", ErrInvalidConfig, i, err)
		}
	}

	return nil
}

// validateArgsMatch validates patterns in an ArgsMatch.
func validateArgsMatch(args ArgsMatch, context string) error {
	if err := validateBoolExpr(args.Any, context+" args.any"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.All, context+" args.all"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.Not, context+" args.not"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.Xor, context+" args.xor"); err != nil {
		return err
	}
	for key, fp := range args.Position {
		for i, pattern := range fp.Patterns {
			if _, err := ParsePattern(pattern); err != nil {
				return fmt.Errorf("%s args.position[%s][%d]: %w", context, key, i, err)
			}
		}
	}
	return nil
}

// validateBoolExpr validates patterns in a BoolExpr.
func validateBoolExpr(expr *BoolExpr, context string) error {
	if expr == nil {
		return nil
	}
	for i, pattern := range expr.Patterns {
		if _, err := ParsePattern(pattern); err != nil {
			return fmt.Errorf("%s[%d]: %w", context, i, err)
		}
	}
	if expr.IsSequence {
		for key, fp := range expr.Sequence {
			for i, pattern := range fp.Patterns {
				if _, err := ParsePattern(pattern); err != nil {
					return fmt.Errorf("%s sequence[%s][%d]: %w", context, key, i, err)
				}
			}
		}
	}
	for i, child := range expr.Any {
		if err := validateBoolExpr(child, fmt.Sprintf("%s.any[%d]", context, i)); err != nil {
			return err
		}
	}
	for i, child := range expr.All {
		if err := validateBoolExpr(child, fmt.Sprintf("%s.all[%d]", context, i)); err != nil {
			return err
		}
	}
	if err := validateBoolExpr(expr.Not, context+".not"); err != nil {
		return err
	}
	for i, child := range expr.Xor {
		if err := validateBoolExpr(child, fmt.Sprintf("%s.xor[%d]", context, i)); err != nil {
			return err
		}
	}
	return nil
}

// resolveAliasesInConfig expands all alias: patterns.
func resolveAliasesInConfig(cfg *Config) error {
	if cfg.Aliases == nil {
		cfg.Aliases = make(map[string]Alias)
	}

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

	// Expand in bash.allow.commands
	if expanded, err := expandPatterns(cfg.Bash.Allow.Commands); err != nil {
		return fmt.Errorf("bash.allow.commands: %w", err)
	} else {
		cfg.Bash.Allow.Commands = expanded
	}

	// Expand in bash.deny.commands
	if expanded, err := expandPatterns(cfg.Bash.Deny.Commands); err != nil {
		return fmt.Errorf("bash.deny.commands: %w", err)
	} else {
		cfg.Bash.Deny.Commands = expanded
	}

	// Expand in parsed rules
	for i := range cfg.parsedRules {
		if err := expandAliasesInArgsMatch(&cfg.parsedRules[i].Args, cfg.Aliases); err != nil {
			return fmt.Errorf("rule[%d] args: %w", i, err)
		}
	}

	// Expand in parsed redirect rules
	for i := range cfg.parsedRedirects {
		expanded, err := expandPatternsSlice(cfg.parsedRedirects[i].Paths, cfg.Aliases)
		if err != nil {
			return fmt.Errorf("redirect[%d] paths: %w", i, err)
		}
		cfg.parsedRedirects[i].Paths = expanded
	}

	// Expand in parsed heredoc rules
	for i := range cfg.parsedHeredocs {
		if cfg.parsedHeredocs[i].Content != nil {
			if err := expandAliasesInBoolExpr(cfg.parsedHeredocs[i].Content, cfg.Aliases); err != nil {
				return fmt.Errorf("heredoc[%d] content: %w", i, err)
			}
		}
	}

	// Expand in file tools
	for _, tool := range []struct {
		name   string
		config *FileToolConfig
	}{
		{"read", &cfg.Read},
		{"write", &cfg.Write},
		{"edit", &cfg.Edit},
	} {
		if expanded, err := expandPatterns(tool.config.Allow.Paths); err != nil {
			return fmt.Errorf("%s.allow.paths: %w", tool.name, err)
		} else {
			tool.config.Allow.Paths = expanded
		}
		if expanded, err := expandPatterns(tool.config.Deny.Paths); err != nil {
			return fmt.Errorf("%s.deny.paths: %w", tool.name, err)
		} else {
			tool.config.Deny.Paths = expanded
		}
	}

	return nil
}

// expandAliasesInArgsMatch expands aliases in an ArgsMatch struct.
func expandAliasesInArgsMatch(args *ArgsMatch, aliases map[string]Alias) error {
	if args.Any != nil {
		if err := expandAliasesInBoolExpr(args.Any, aliases); err != nil {
			return fmt.Errorf("any: %w", err)
		}
	}
	if args.All != nil {
		if err := expandAliasesInBoolExpr(args.All, aliases); err != nil {
			return fmt.Errorf("all: %w", err)
		}
	}
	if args.Not != nil {
		if err := expandAliasesInBoolExpr(args.Not, aliases); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}
	if args.Xor != nil {
		if err := expandAliasesInBoolExpr(args.Xor, aliases); err != nil {
			return fmt.Errorf("xor: %w", err)
		}
	}
	for key, fp := range args.Position {
		expanded, err := expandPatternsSlice(fp.Patterns, aliases)
		if err != nil {
			return fmt.Errorf("position[%s]: %w", key, err)
		}
		args.Position[key] = FlexiblePattern{Patterns: expanded}
	}
	return nil
}

// expandAliasesInBoolExpr expands aliases in a BoolExpr tree.
func expandAliasesInBoolExpr(expr *BoolExpr, aliases map[string]Alias) error {
	if expr == nil {
		return nil
	}
	// Expand flat patterns
	if len(expr.Patterns) > 0 {
		expanded, err := expandPatternsSlice(expr.Patterns, aliases)
		if err != nil {
			return err
		}
		expr.Patterns = expanded
	}
	// Expand sequence patterns
	for key, fp := range expr.Sequence {
		expanded, err := expandPatternsSlice(fp.Patterns, aliases)
		if err != nil {
			return fmt.Errorf("sequence[%s]: %w", key, err)
		}
		expr.Sequence[key] = FlexiblePattern{Patterns: expanded}
	}
	// Recurse into nested expressions
	for _, child := range expr.Any {
		if err := expandAliasesInBoolExpr(child, aliases); err != nil {
			return err
		}
	}
	for _, child := range expr.All {
		if err := expandAliasesInBoolExpr(child, aliases); err != nil {
			return err
		}
	}
	if err := expandAliasesInBoolExpr(expr.Not, aliases); err != nil {
		return err
	}
	for _, child := range expr.Xor {
		if err := expandAliasesInBoolExpr(child, aliases); err != nil {
			return err
		}
	}
	return nil
}

// expandPatternsSlice expands aliases in a slice of patterns.
func expandPatternsSlice(patterns []string, aliases map[string]Alias) ([]string, error) {
	var result []string
	for _, p := range patterns {
		expanded, err := expandAlias(p, aliases)
		if err != nil {
			return nil, err
		}
		result = append(result, expanded...)
	}
	return result, nil
}

// expandAlias expands a single pattern if it's an alias reference.
// Aliases cannot reference other aliases (validated at parse time),
// so this is a simple one-level expansion.
func expandAlias(pattern string, aliases map[string]Alias) ([]string, error) {
	if !strings.HasPrefix(pattern, "alias:") {
		return []string{pattern}, nil
	}

	aliasName := strings.TrimPrefix(pattern, "alias:")
	alias, ok := aliases[aliasName]
	if !ok {
		return nil, fmt.Errorf("undefined alias: %s", aliasName)
	}

	return alias.Patterns, nil
}

// DefaultConfig returns a minimal default configuration.
func DefaultConfig() *Config {
	cfg := &Config{
		Path: "(default)",
		Bash: BashConfig{
			Default:            "ask",
			DynamicCommands:    "ask",
			UnresolvedCommands: "ask",
			DefaultMessage:     "Command not allowed",
			Constructs: ConstructsConfig{
				Subshells:           "ask",
				FunctionDefinitions: "ask",
				Background:          "ask",
				Heredocs:            "allow",
			},
		},
		Read:  FileToolConfig{Default: "ask"},
		Write: FileToolConfig{Default: "ask"},
		Edit:  FileToolConfig{Default: "ask"},
	}
	return cfg
}

// LoadConfigChain loads configs from standard locations plus an optional explicit path.
func LoadConfigChain(explicitPath string) (*ConfigChain, error) {
	chain := &ConfigChain{}

	// 1. Load global config
	if globalPath := findGlobalConfig(); globalPath != "" {
		cfg, err := loadConfig(globalPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 2. Load project configs
	projectPath, localPath := findProjectConfigs()
	if projectPath != "" {
		cfg, err := loadConfig(projectPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}
	if localPath != "" {
		cfg, err := loadConfig(localPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 3. Load explicit config
	if explicitPath != "" {
		cfg, err := loadConfig(explicitPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// If no configs found, use default
	if len(chain.Configs) == 0 {
		chain.Configs = append(chain.Configs, DefaultConfig())
	}

	// Merge all configs
	chain.Merged = MergeConfigs(chain.Configs)

	return chain, nil
}
