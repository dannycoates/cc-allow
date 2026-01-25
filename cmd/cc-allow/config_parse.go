package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

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
	applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseConfigRaw parses without applying defaults (for config chain merging).
func parseConfigRaw(data string) (*Config, error) {
	cfg, err := parseConfigInternal(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadConfigRaw reads and parses without applying defaults.
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

// parseConfigInternal parses TOML and extracts nested command rules.
func parseConfigInternal(data string) (*Config, error) {
	// First decode into raw map to check for legacy format
	var raw map[string]interface{}
	if _, err := toml.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Check version
	version, _ := raw["version"].(string)
	if err := validateConfigVersion(version, raw); err != nil {
		return nil, err
	}

	// Decode standard fields
	var cfg Config
	if _, err := toml.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	// Parse nested command rules from [bash.allow.X] and [bash.deny.X]
	if bashRaw, ok := raw["bash"].(map[string]interface{}); ok {
		rules, err := parseBashRules(bashRaw, cfg.Aliases)
		if err != nil {
			return nil, fmt.Errorf("%w: bash: %w", ErrConfigParse, err)
		}
		cfg.parsedRules = rules

		// Parse redirect rules
		if redirectsRaw, ok := bashRaw["redirects"].(map[string]interface{}); ok {
			redirectRules, err := parseRedirectRules(redirectsRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: bash.redirects: %w", ErrConfigParse, err)
			}
			cfg.parsedRedirects = redirectRules
		}

		// Parse heredoc rules
		if heredocsRaw, ok := bashRaw["heredocs"].(map[string]interface{}); ok {
			heredocRules, err := parseHeredocRules(heredocsRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: bash.heredocs: %w", ErrConfigParse, err)
			}
			cfg.parsedHeredocs = heredocRules
		}
	}

	// Resolve aliases in all patterns
	if err := resolveAliasesInConfig(&cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigParse, err)
	}

	return &cfg, nil
}

// validateConfigVersion checks the version and detects legacy format.
func validateConfigVersion(version string, raw map[string]interface{}) error {
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
func parseBashRules(bashRaw map[string]interface{}, aliases map[string]Alias) ([]BashRule, error) {
	var rules []BashRule

	// Parse [bash.allow] section
	if allowRaw, ok := bashRaw["allow"].(map[string]interface{}); ok {
		allowRules, err := parseActionSection(allowRaw, "allow", []string{})
		if err != nil {
			return nil, fmt.Errorf("allow: %w", err)
		}
		rules = append(rules, allowRules...)
	}

	// Parse [bash.deny] section
	if denyRaw, ok := bashRaw["deny"].(map[string]interface{}); ok {
		denyRules, err := parseActionSection(denyRaw, "deny", []string{})
		if err != nil {
			return nil, fmt.Errorf("deny: %w", err)
		}
		rules = append(rules, denyRules...)
	}

	return rules, nil
}

// parseActionSection recursively walks an action section to find command rules.
func parseActionSection(node map[string]interface{}, action string, path []string) ([]BashRule, error) {
	var rules []BashRule

	for key, value := range node {
		// Skip reserved keys at section level
		if len(path) == 0 && isReservedBashKey(key) {
			continue
		}

		switch v := value.(type) {
		case []map[string]interface{}:
			// Array of tables: [[bash.allow.rm]] or [[bash.deny.git.push]]
			// TOML decodes these as []map[string]interface{}
			for i, table := range v {
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s][%d]: %w", key, i, err)
				}
				rules = append(rules, rule)
			}
		case []interface{}:
			// Fallback for arrays (shouldn't normally happen for rule tables)
			for i, item := range v {
				table, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				rule, err := parseRuleFromTable(action, append(path, key), table)
				if err != nil {
					return nil, fmt.Errorf("[%s][%d]: %w", key, i, err)
				}
				rules = append(rules, rule)
			}
		case map[string]interface{}:
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
func looksLikeRuleTable(m map[string]interface{}) bool {
	for key := range m {
		if isReservedRuleKey(key) {
			return true
		}
	}
	// Empty table is also a valid rule (just matches the command)
	return len(m) == 0
}

// parseRuleFromTable converts a TOML table to a BashRule.
func parseRuleFromTable(action string, path []string, table map[string]interface{}) (BashRule, error) {
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
	if argsRaw, ok := table["args"].(map[string]interface{}); ok {
		args, err := parseArgsMatch(argsRaw)
		if err != nil {
			return BashRule{}, fmt.Errorf("args: %w", err)
		}
		rule.Args = args
	}

	// Extract pipe
	if pipeRaw, ok := table["pipe"].(map[string]interface{}); ok {
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
func parseArgsMatch(raw map[string]interface{}) (ArgsMatch, error) {
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

// parsePipeContext parses a pipe table.
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

// parseRedirectRules parses redirect rules from [bash.redirects].
func parseRedirectRules(raw map[string]interface{}) ([]RedirectRule, error) {
	var rules []RedirectRule

	// Parse [[bash.redirects.allow]]
	if allowRaw, ok := raw["allow"].([]map[string]interface{}); ok {
		for i, table := range allowRaw {
			rule, err := parseRedirectRule("allow", table)
			if err != nil {
				return nil, fmt.Errorf("allow[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	} else if allowRaw, ok := raw["allow"].([]interface{}); ok {
		for i, item := range allowRaw {
			table, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			rule, err := parseRedirectRule("allow", table)
			if err != nil {
				return nil, fmt.Errorf("allow[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	}

	// Parse [[bash.redirects.deny]]
	if denyRaw, ok := raw["deny"].([]map[string]interface{}); ok {
		for i, table := range denyRaw {
			rule, err := parseRedirectRule("deny", table)
			if err != nil {
				return nil, fmt.Errorf("deny[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	} else if denyRaw, ok := raw["deny"].([]interface{}); ok {
		for i, item := range denyRaw {
			table, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			rule, err := parseRedirectRule("deny", table)
			if err != nil {
				return nil, fmt.Errorf("deny[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// parseRedirectRule parses a single redirect rule.
func parseRedirectRule(action string, table map[string]interface{}) (RedirectRule, error) {
	rule := RedirectRule{Action: action}

	if msg, ok := table["message"].(string); ok {
		rule.Message = msg
	}

	if paths, ok := table["paths"].([]interface{}); ok {
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
func parseHeredocRules(raw map[string]interface{}) ([]HeredocRule, error) {
	var rules []HeredocRule

	// Parse [[bash.heredocs.allow]]
	if allowRaw, ok := raw["allow"].([]map[string]interface{}); ok {
		for i, table := range allowRaw {
			rule, err := parseHeredocRule("allow", table)
			if err != nil {
				return nil, fmt.Errorf("allow[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	} else if allowRaw, ok := raw["allow"].([]interface{}); ok {
		for i, item := range allowRaw {
			table, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			rule, err := parseHeredocRule("allow", table)
			if err != nil {
				return nil, fmt.Errorf("allow[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	}

	// Parse [[bash.heredocs.deny]]
	if denyRaw, ok := raw["deny"].([]map[string]interface{}); ok {
		for i, table := range denyRaw {
			rule, err := parseHeredocRule("deny", table)
			if err != nil {
				return nil, fmt.Errorf("deny[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	} else if denyRaw, ok := raw["deny"].([]interface{}); ok {
		for i, item := range denyRaw {
			table, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			rule, err := parseHeredocRule("deny", table)
			if err != nil {
				return nil, fmt.Errorf("deny[%d]: %w", i, err)
			}
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

// parseHeredocRule parses a single heredoc rule.
func parseHeredocRule(action string, table map[string]interface{}) (HeredocRule, error) {
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

// Validate checks that all patterns in the config are valid.
func (cfg *Config) Validate() error {
	// Validate aliases
	for name := range cfg.Aliases {
		if strings.HasPrefix(name, "path:") || strings.HasPrefix(name, "re:") ||
			strings.HasPrefix(name, "flags:") || strings.HasPrefix(name, "alias:") ||
			strings.HasPrefix(name, "ref:") {
			return fmt.Errorf("%w: aliases: name %q cannot start with a reserved prefix", ErrInvalidConfig, name)
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
func expandAlias(pattern string, aliases map[string]Alias) ([]string, error) {
	if !strings.HasPrefix(pattern, "alias:") {
		return []string{pattern}, nil
	}

	aliasName := strings.TrimPrefix(pattern, "alias:")
	alias, ok := aliases[aliasName]
	if !ok {
		return nil, fmt.Errorf("undefined alias: %s", aliasName)
	}

	// Recursively expand
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
		cfg, err := loadConfigRaw(globalPath)
		if err != nil {
			return nil, err
		}
		chain.Configs = append(chain.Configs, cfg)
	}

	// 2. Load project configs
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

	// 3. Load explicit config
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

	// Merge all configs
	chain.Merged = MergeConfigs(chain.Configs)

	return chain, nil
}
