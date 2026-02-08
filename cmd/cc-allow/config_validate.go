package main

import (
	"fmt"
	"strconv"
	"strings"
)

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

// validateAction checks that a raw string action value is valid, returning an error if not.
// Empty strings are allowed (indicating the field was not set).
func validateAction(action, field string) error {
	if action == "" {
		return nil
	}
	if !Action(action).IsValid() {
		return &ConfigValidationError{
			Location: field,
			Value:    action,
			Message:  "invalid action (must be \"allow\", \"deny\", or \"ask\")",
		}
	}
	return nil
}

// validateAllowMode checks that an allow mode value is valid.
func validateAllowMode(mode, field string) error {
	if mode != "" && mode != "merge" && mode != "replace" {
		return &ConfigValidationError{
			Location: field,
			Value:    mode,
			Message:  "invalid mode (must be \"merge\" or \"replace\")",
		}
	}
	return nil
}

// Validate checks that all patterns in the config are valid.
// Returns a ConfigValidationError with location and value context on failure.
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
	if err := validateAction(cfg.WebFetch.Default, "webfetch.default"); err != nil {
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
	if err := validateAllowMode(cfg.WebFetch.Allow.Mode, "webfetch.allow.mode"); err != nil {
		return err
	}

	// Validate aliases
	for name, alias := range cfg.Aliases {
		if strings.HasPrefix(name, "path:") || strings.HasPrefix(name, "re:") ||
			strings.HasPrefix(name, "flags:") || strings.HasPrefix(name, "alias:") ||
			strings.HasPrefix(name, "ref:") {
			return &ConfigValidationError{
				Location: fmt.Sprintf("aliases.%s", name),
				Value:    name,
				Message:  "alias name cannot start with a reserved prefix (path:, re:, flags:, alias:, ref:)",
			}
		}
		// Aliases cannot reference other aliases (prevents circular references)
		for i, pattern := range alias.Patterns {
			if strings.HasPrefix(pattern, "alias:") {
				return &ConfigValidationError{
					Location: fmt.Sprintf("aliases.%s[%d]", name, i),
					Value:    pattern,
					Message:  "aliases cannot reference other aliases",
				}
			}
		}
	}

	// Validate bash.allow.commands patterns
	for i, cmd := range cfg.Bash.Allow.Commands {
		if _, err := ParsePattern(cmd); err != nil {
			return &ConfigValidationError{
				Location: fmt.Sprintf("bash.allow.commands[%d]", i),
				Value:    cmd,
				Message:  "invalid pattern",
				Cause:    err,
			}
		}
	}

	// Validate bash.deny.commands patterns
	for i, cmd := range cfg.Bash.Deny.Commands {
		if _, err := ParsePattern(cmd); err != nil {
			return &ConfigValidationError{
				Location: fmt.Sprintf("bash.deny.commands[%d]", i),
				Value:    cmd,
				Message:  "invalid pattern",
				Cause:    err,
			}
		}
	}

	// Validate parsed rules
	for i, rule := range cfg.getParsedRules() {
		ruleLocation := formatRuleLocation(rule, i)
		if _, err := ParsePattern(rule.Command); err != nil {
			return &ConfigValidationError{
				Location: ruleLocation,
				Value:    rule.Command,
				Message:  "invalid command pattern",
				Cause:    err,
			}
		}
		if err := validateArgsMatch(rule.Args, ruleLocation); err != nil {
			return err
		}
	}

	// Validate redirect rules
	for i, rule := range cfg.getParsedRedirects() {
		for j, path := range rule.Paths {
			if _, err := ParsePattern(path); err != nil {
				return &ConfigValidationError{
					Location: fmt.Sprintf("bash.redirects.%s[%d].paths[%d]", rule.Action, i, j),
					Value:    path,
					Message:  "invalid pattern",
					Cause:    err,
				}
			}
		}
	}

	// Validate heredoc rules
	for i, rule := range cfg.getParsedHeredocs() {
		if err := validateBoolExpr(rule.Content, fmt.Sprintf("bash.heredocs.%s[%d].content", rule.Action, i)); err != nil {
			return err
		}
	}

	// Validate file tool patterns
	if err := validateFilePatterns(cfg.Read.Allow.Paths, "read.allow.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.Read.Deny.Paths, "read.deny.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.Write.Allow.Paths, "write.allow.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.Write.Deny.Paths, "write.deny.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.Edit.Allow.Paths, "edit.allow.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.Edit.Deny.Paths, "edit.deny.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.WebFetch.Allow.Paths, "webfetch.allow.paths"); err != nil {
		return err
	}
	if err := validateFilePatterns(cfg.WebFetch.Deny.Paths, "webfetch.deny.paths"); err != nil {
		return err
	}

	return nil
}

// formatRuleLocation creates a human-readable location string for a bash rule.
func formatRuleLocation(rule BashRule, index int) string {
	parts := []string{"bash", string(rule.Action), rule.Command}
	parts = append(parts, rule.Subcommands...)
	return strings.Join(parts, ".")
}

// validateFilePatterns validates a slice of file path patterns.
func validateFilePatterns(paths []string, location string) error {
	for i, path := range paths {
		if _, err := ParsePattern(path); err != nil {
			return &ConfigValidationError{
				Location: fmt.Sprintf("%s[%d]", location, i),
				Value:    path,
				Message:  "invalid pattern",
				Cause:    err,
			}
		}
	}
	return nil
}

// validateArgsMatch validates patterns in an ArgsMatch.
func validateArgsMatch(args ArgsMatch, context string) error {
	if err := validateBoolExpr(args.Any, context+".args.any"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.All, context+".args.all"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.Not, context+".args.not"); err != nil {
		return err
	}
	if err := validateBoolExpr(args.Xor, context+".args.xor"); err != nil {
		return err
	}
	for key, fp := range args.Position {
		for i, pattern := range fp.Patterns {
			if _, err := ParsePattern(pattern); err != nil {
				return &ConfigValidationError{
					Location: fmt.Sprintf("%s.args.position[%s][%d]", context, key, i),
					Value:    pattern,
					Message:  "invalid pattern",
					Cause:    err,
				}
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
			return &ConfigValidationError{
				Location: fmt.Sprintf("%s[%d]", context, i),
				Value:    pattern,
				Message:  "invalid pattern",
				Cause:    err,
			}
		}
	}
	if expr.IsSequence {
		for key, fp := range expr.Sequence {
			for i, pattern := range fp.Patterns {
				if _, err := ParsePattern(pattern); err != nil {
					return &ConfigValidationError{
						Location: fmt.Sprintf("%s.sequence[%s][%d]", context, key, i),
						Value:    pattern,
						Message:  "invalid pattern",
						Cause:    err,
					}
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
