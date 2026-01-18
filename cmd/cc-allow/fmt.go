package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ruleWithScore pairs a rule with its computed specificity score for sorting.
type ruleWithScore struct {
	index       int
	rule        Rule
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
func runFmt(configPath string) {
	paths := findFmtConfigFiles(configPath)

	if len(paths) == 0 {
		fmt.Println("No config files found.")
		fmt.Println("\nSearched locations:")
		fmt.Println("  - ~/.config/cc-allow.toml (global)")
		fmt.Println("  - <project>/.claude/cc-allow.toml (project)")
		fmt.Println("  - <project>/.claude/cc-allow.local.toml (local)")
		if configPath != "" {
			fmt.Printf("  - %s (explicit)\n", configPath)
		}
		os.Exit(1)
	}

	var allRules []ruleWithScore
	var allRedirects []redirectWithScore
	var allHeredocs []heredocWithScore
	hasError := false

	fmt.Println("Config Files")
	fmt.Println("============")

	for i, path := range paths {
		cfg, err := LoadConfig(path)
		if err != nil {
			fmt.Printf("\n[%d] %s\n", i+1, path)
			fmt.Printf("    ERROR: %v\n", err)
			hasError = true
			continue
		}

		fmt.Printf("\n[%d] %s\n", i+1, path)
		fmt.Printf("    policy.default = %q\n", cfg.Policy.Default)
		fmt.Printf("    policy.dynamic_commands = %q\n", cfg.Policy.DynamicCommands)

		if len(cfg.Commands.Allow.Names) > 0 {
			fmt.Printf("    commands.allow.names = %d command(s)\n", len(cfg.Commands.Allow.Names))
		}
		if len(cfg.Commands.Deny.Names) > 0 {
			fmt.Printf("    commands.deny.names = %d command(s)\n", len(cfg.Commands.Deny.Names))
		}

		// Collect rules with scores
		for j, rule := range cfg.Rules {
			allRules = append(allRules, ruleWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		// Collect redirect rules with scores
		for j, rule := range cfg.Redirects {
			allRedirects = append(allRedirects, redirectWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		// Collect heredoc rules with scores
		for j, rule := range cfg.Heredocs {
			allHeredocs = append(allHeredocs, heredocWithScore{
				index:       j,
				rule:        rule,
				specificity: rule.Specificity(),
				source:      path,
			})
		}

		fmt.Printf("    %d rule(s), %d redirect(s), %d heredoc(s)\n", len(cfg.Rules), len(cfg.Redirects), len(cfg.Heredocs))
		if cfg.Constructs.Heredocs != "" && cfg.Constructs.Heredocs != "allow" {
			fmt.Printf("    constructs.heredocs = %q\n", cfg.Constructs.Heredocs)
		}
	}

	if hasError {
		fmt.Println("\nValidation failed with errors.")
		os.Exit(1)
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
		fmt.Println("Note: Heredoc rules use first-match. Only checked if constructs.heredocs = \"allow\".")

		sortHeredocsBySpecificity(allHeredocs)

		for _, r := range allHeredocs {
			fmt.Printf("\n[%d] %s\n", r.specificity, formatHeredocRule(r.rule))
			fmt.Printf("    source: %s\n", filepath.Base(r.source))
		}
	}

	fmt.Println("\n\nValidation passed.")
}

func findFmtConfigFiles(explicitPath string) []string {
	var paths []string

	if globalPath := findGlobalConfig(); globalPath != "" {
		paths = append(paths, globalPath)
	}

	if projectPath := findProjectConfig(); projectPath != "" {
		paths = append(paths, projectPath)
	}

	if localPath := findProjectLocalConfig(); localPath != "" {
		paths = append(paths, localPath)
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

func formatRule(r Rule) string {
	result := fmt.Sprintf("command=%q action=%s", r.Command, r.Action)

	if len(r.Args.Contains) > 0 {
		result += fmt.Sprintf(" args.contains=%v", r.Args.Contains)
	}
	if len(r.Args.AnyMatch) > 0 {
		result += fmt.Sprintf(" args.any_match=%v", r.Args.AnyMatch)
	}
	if len(r.Args.AllMatch) > 0 {
		result += fmt.Sprintf(" args.all_match=%v", r.Args.AllMatch)
	}
	if len(r.Args.Position) > 0 {
		result += fmt.Sprintf(" args.position=%v", r.Args.Position)
	}
	if len(r.Pipe.To) > 0 {
		result += fmt.Sprintf(" pipe.to=%v", r.Pipe.To)
	}
	if len(r.Pipe.From) > 0 {
		result += fmt.Sprintf(" pipe.from=%v", r.Pipe.From)
	}

	return result
}

func formatRedirectRule(r RedirectRule) string {
	result := fmt.Sprintf("action=%s", r.Action)

	if len(r.To.Exact) > 0 {
		result += fmt.Sprintf(" to.exact=%v", r.To.Exact)
	}
	if len(r.To.Pattern) > 0 {
		result += fmt.Sprintf(" to.pattern=%v", r.To.Pattern)
	}
	if r.Append != nil {
		result += fmt.Sprintf(" append=%v", *r.Append)
	}

	return result
}

func formatHeredocRule(r HeredocRule) string {
	result := fmt.Sprintf("action=%s", r.Action)

	if len(r.ContentMatch) > 0 {
		result += fmt.Sprintf(" content_match=%v", r.ContentMatch)
	}

	return result
}
