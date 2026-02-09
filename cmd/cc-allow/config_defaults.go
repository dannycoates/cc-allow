package main

import (
	"fmt"
	"strings"
)

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
	if cfg.Glob.Default == "" {
		cfg.Glob.Default = "allow"
	}
	if cfg.Grep.Default == "" {
		cfg.Grep.Default = "allow"
	}
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
		Glob:  FileToolConfig{Default: "allow"},
		Grep:  FileToolConfig{Default: "allow"},
	}
	return cfg
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
		{"glob", &cfg.Glob},
		{"grep", &cfg.Grep},
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
