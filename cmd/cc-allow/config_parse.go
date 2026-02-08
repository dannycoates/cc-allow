package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

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
		bashCfg, err := parseBashConfigFromRaw(bashRaw)
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

	// Extract webfetch config
	if webfetchRaw, ok := raw["webfetch"].(map[string]any); ok {
		cfg.WebFetch = parseWebFetchConfigFromRaw(webfetchRaw)
	}

	// Extract debug config
	if debugRaw, ok := raw["debug"].(map[string]any); ok {
		cfg.Debug.LogDir, _ = debugRaw["log_dir"].(string)
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
func parseBashConfigFromRaw(raw map[string]any) (*bashConfigResult, error) {
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
	rules, err := parseBashRules(raw)
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
	cfg.DefaultMessage, _ = raw["default_message"].(string)

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

// parseWebFetchConfigFromRaw parses a [webfetch] section.
func parseWebFetchConfigFromRaw(raw map[string]any) WebFetchConfig {
	var cfg WebFetchConfig
	cfg.Default, _ = raw["default"].(string)
	cfg.DefaultMessage, _ = raw["default_message"].(string)

	if allowRaw, ok := raw["allow"].(map[string]any); ok {
		cfg.Allow = parseFileAllowDenyFromRaw(allowRaw)
	}
	if denyRaw, ok := raw["deny"].(map[string]any); ok {
		cfg.Deny = parseFileAllowDenyFromRaw(denyRaw)
	}
	if sbRaw, ok := raw["safe_browsing"].(map[string]any); ok {
		cfg.SafeBrowsing.Enabled, _ = sbRaw["enabled"].(bool)
		cfg.SafeBrowsing.APIKey, _ = sbRaw["api_key"].(string)
	}
	return cfg
}

// parseBashRules extracts rules from [bash.allow.X], [bash.deny.X], and [bash.ask.X] tables.
func parseBashRules(bashRaw map[string]any) ([]BashRule, error) {
	var rules []BashRule

	// Parse [bash.allow] section
	if allowRaw, ok := bashRaw["allow"].(map[string]any); ok {
		allowRules, err := parseActionSection(allowRaw, ActionAllow, []string{})
		if err != nil {
			return nil, fmt.Errorf("allow: %w", err)
		}
		rules = append(rules, allowRules...)
	}

	// Parse [bash.deny] section
	if denyRaw, ok := bashRaw["deny"].(map[string]any); ok {
		denyRules, err := parseActionSection(denyRaw, ActionDeny, []string{})
		if err != nil {
			return nil, fmt.Errorf("deny: %w", err)
		}
		rules = append(rules, denyRules...)
	}

	// Parse [bash.ask] section
	if askRaw, ok := bashRaw["ask"].(map[string]any); ok {
		askRules, err := parseActionSection(askRaw, ActionAsk, []string{})
		if err != nil {
			return nil, fmt.Errorf("ask: %w", err)
		}
		rules = append(rules, askRules...)
	}

	return rules, nil
}

// parseActionSection recursively walks an action section to find command rules.
func parseActionSection(node map[string]any, action Action, path []string) ([]BashRule, error) {
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
func parseRuleFromTable(action Action, path []string, table map[string]any) (BashRule, error) {
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
		rule.FileAccessType = ToolName(fat)
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
		rule, err := parseRedirectRule(ActionAllow, table)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	// Parse [[bash.redirects.deny]]
	for i, table := range toTableSlice(raw["deny"]) {
		rule, err := parseRedirectRule(ActionDeny, table)
		if err != nil {
			return nil, fmt.Errorf("deny[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRedirectRule parses a single redirect rule.
func parseRedirectRule(action Action, table map[string]any) (RedirectRule, error) {
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
		rule, err := parseHeredocRule(ActionAllow, table)
		if err != nil {
			return nil, fmt.Errorf("allow[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	// Parse [[bash.heredocs.deny]]
	for i, table := range toTableSlice(raw["deny"]) {
		rule, err := parseHeredocRule(ActionDeny, table)
		if err != nil {
			return nil, fmt.Errorf("deny[%d]: %w", i, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// parseHeredocRule parses a single heredoc rule.
func parseHeredocRule(action Action, table map[string]any) (HeredocRule, error) {
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
