package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ruleWithScore pairs a rule with its computed specificity score for sorting.
type ruleWithScore struct {
	index       int
	rule        BashRule
	specificity int
	source      string
}

// redirectWithScore pairs a redirect rule with its computed specificity score.
type redirectWithScore struct {
	index       int
	rule        RedirectRule
	specificity int
	source      string
}

// heredocWithScore pairs a heredoc rule with its computed specificity score.
type heredocWithScore struct {
	index       int
	rule        HeredocRule
	specificity int
	source      string
}

// runFmt validates configs and displays rules sorted by specificity.
func runFmt(configPath string) ExitCode {
	paths := findFmtConfigFiles(configPath)

	if len(paths) == 0 {
		fmt.Println("No config files found.")
		fmt.Println("\nSearched locations:")
		fmt.Println("  - ~/.config/cc-allow.toml (global)")
		fmt.Println("  - <project>/.config/cc-allow.toml (project)")
		fmt.Println("  - <project>/.config/cc-allow.local.toml (local)")
		if configPath != "" {
			fmt.Printf("  - %s (explicit)\n", configPath)
		}
		return ExitError
	}

	var allRules []ruleWithScore
	var allRedirects []redirectWithScore
	var allHeredocs []heredocWithScore
	hasError := false

	fmt.Println("Config Files")
	fmt.Println("============")

	for i, path := range paths {
		cfg, err := LoadConfigWithDefaults(path)
		if err != nil {
			fmt.Printf("\n[%d] %s\n", i+1, path)
			fmt.Printf("    ERROR: %v\n", err)
			hasError = true
			continue
		}

		fmt.Printf("\n[%d] %s\n", i+1, path)
		fmt.Printf("    bash.default = %q\n", cfg.Bash.Default)
		fmt.Printf("    bash.dynamic_commands = %q\n", cfg.Bash.DynamicCommands)
		if cfg.Bash.RespectFileRules != nil {
			fmt.Printf("    bash.respect_file_rules = %v\n", *cfg.Bash.RespectFileRules)
		}
		if cfg.Bash.Redirects.RespectFileRules != nil {
			fmt.Printf("    bash.redirects.respect_file_rules = %v\n", *cfg.Bash.Redirects.RespectFileRules)
		}

		if len(cfg.Bash.Allow.Commands) > 0 {
			mode := cfg.Bash.Allow.Mode
			if mode == "" {
				mode = "merge"
			}
			fmt.Printf("    bash.allow.commands = %d command(s) (mode: %s)\n", len(cfg.Bash.Allow.Commands), mode)
		}
		if len(cfg.Bash.Deny.Commands) > 0 {
			fmt.Printf("    bash.deny.commands = %d command(s)\n", len(cfg.Bash.Deny.Commands))
		}

		// Collect rules with scores
		rules := cfg.getParsedRules()
		for j, rule := range rules {
			allRules = append(allRules, ruleWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		// Collect redirect rules with scores
		redirects := cfg.getParsedRedirects()
		for j, rule := range redirects {
			allRedirects = append(allRedirects, redirectWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		// Collect heredoc rules with scores
		heredocs := cfg.getParsedHeredocs()
		for j, rule := range heredocs {
			allHeredocs = append(allHeredocs, heredocWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		fmt.Printf("    %d rule(s), %d redirect(s), %d heredoc(s)\n", len(rules), len(redirects), len(heredocs))
		if cfg.Bash.Constructs.Heredocs != "" && cfg.Bash.Constructs.Heredocs != "allow" {
			fmt.Printf("    bash.constructs.heredocs = %q\n", cfg.Bash.Constructs.Heredocs)
		}

		// Display WebFetch config
		if cfg.WebFetch.Default != "" || len(cfg.WebFetch.Allow.Paths) > 0 || len(cfg.WebFetch.Deny.Paths) > 0 || cfg.WebFetch.SafeBrowsing.Enabled {
			fmt.Println("    WebFetch:")
			if cfg.WebFetch.Default != "" {
				fmt.Printf("      default = %q\n", cfg.WebFetch.Default)
			}
			if cfg.WebFetch.SafeBrowsing.Enabled {
				if cfg.WebFetch.SafeBrowsing.APIKey != "" {
					fmt.Println("      safe_browsing: enabled (key configured)")
				} else {
					fmt.Println("      safe_browsing: enabled (no key)")
				}
			}
			if len(cfg.WebFetch.Allow.Paths) > 0 {
				fmt.Printf("      allow: %d pattern(s)\n", len(cfg.WebFetch.Allow.Paths))
				for _, p := range cfg.WebFetch.Allow.Paths {
					fmt.Printf("        %s\n", p)
				}
			}
			if len(cfg.WebFetch.Deny.Paths) > 0 {
				fmt.Printf("      deny: %d pattern(s)\n", len(cfg.WebFetch.Deny.Paths))
				for _, p := range cfg.WebFetch.Deny.Paths {
					fmt.Printf("        %s\n", p)
				}
			}
		}
	}

	if hasError {
		fmt.Println("\nValidation failed with errors.")
		return ExitError
	}

	// Print rules sorted by specificity
	if len(allRules) > 0 {
		fmt.Println("\n\nCommand Rules (by specificity)")
		fmt.Println("==============================")

		sortRulesBySpecificity(allRules)

		for _, r := range allRules {
			fmt.Printf("\n[%d] %s\n", r.specificity, formatRule(r.rule))
			fmt.Printf("    source: %s\n", filepath.Base(r.source))
		}
	}

	// Print redirect rules
	if len(allRedirects) > 0 {
		fmt.Println("\n\nRedirect Rules (by specificity)")
		fmt.Println("================================")
		fmt.Println("Note: Redirect rules use first-match, not specificity-based selection.")

		sortRedirectsBySpecificity(allRedirects)

		for _, r := range allRedirects {
			fmt.Printf("\n[%d] %s\n", r.specificity, formatRedirectRule(r.rule))
			fmt.Printf("    source: %s\n", filepath.Base(r.source))
		}
	}

	// Print heredoc rules
	if len(allHeredocs) > 0 {
		fmt.Println("\n\nHeredoc Rules (by specificity)")
		fmt.Println("===============================")
		fmt.Println("Note: Heredoc rules use first-match. Only checked if bash.constructs.heredocs = \"allow\".")

		sortHeredocsBySpecificity(allHeredocs)

		for _, r := range allHeredocs {
			fmt.Printf("\n[%d] %s\n", r.specificity, formatHeredocRule(r.rule))
			fmt.Printf("    source: %s\n", filepath.Base(r.source))
		}
	}

	fmt.Println("\n\nValidation passed.")
	return ExitAllow
}

func findFmtConfigFiles(explicitPath string) []string {
	var paths []string

	if globalPath := findGlobalConfig(); globalPath != "" {
		paths = append(paths, globalPath)
	}

	discovery := findProjectConfigs()
	if discovery.ProjectConfig != "" {
		paths = append(paths, discovery.ProjectConfig)
	}
	if discovery.LocalConfig != "" {
		paths = append(paths, discovery.LocalConfig)
	}

	if explicitPath != "" {
		paths = append(paths, explicitPath)
	}

	return paths
}

func sortRulesBySpecificity(rules []ruleWithScore) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].specificity > rules[j].specificity
	})
}

func sortRedirectsBySpecificity(rules []redirectWithScore) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].specificity > rules[j].specificity
	})
}

func sortHeredocsBySpecificity(rules []heredocWithScore) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].specificity > rules[j].specificity
	})
}

func formatRule(r BashRule) string {
	result := fmt.Sprintf("command=%q action=%s", r.Command, r.Action)

	if len(r.Subcommands) > 0 {
		result += fmt.Sprintf(" subcommands=%v", r.Subcommands)
	}
	if r.Args.Any != nil {
		result += " args.any=..."
	}
	if r.Args.All != nil {
		result += " args.all=..."
	}
	if r.Args.Not != nil {
		result += " args.not=..."
	}
	if len(r.Args.Position) > 0 {
		result += fmt.Sprintf(" args.position=%v", formatPosition(r.Args.Position))
	}
	if len(r.Pipe.To) > 0 {
		result += fmt.Sprintf(" pipe.to=%v", r.Pipe.To)
	}
	if len(r.Pipe.From) > 0 {
		result += fmt.Sprintf(" pipe.from=%v", r.Pipe.From)
	}
	if r.RespectFileRules != nil {
		result += fmt.Sprintf(" respect_file_rules=%v", *r.RespectFileRules)
	}
	if r.FileAccessType != "" {
		result += fmt.Sprintf(" file_access_type=%q", r.FileAccessType)
	}

	return result
}

func formatPosition(pos map[string]FlexiblePattern) string {
	var parts []string
	for k, v := range pos {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v.Patterns))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func formatRedirectRule(r RedirectRule) string {
	result := fmt.Sprintf("action=%s", r.Action)

	if len(r.Paths) > 0 {
		result += fmt.Sprintf(" paths=%v", r.Paths)
	}
	if r.Append != nil {
		result += fmt.Sprintf(" append=%v", *r.Append)
	}

	return result
}

func formatHeredocRule(r HeredocRule) string {
	result := fmt.Sprintf("action=%s", r.Action)

	if r.Content != nil {
		result += " content=..."
	}

	return result
}
