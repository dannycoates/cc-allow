package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
)

// Config types (mirrored from cc-allow for standalone operation)

type Config struct {
	Path       string           `toml:"-"`
	Policy     PolicyConfig     `toml:"policy"`
	Commands   CommandsConfig   `toml:"commands"`
	Rules      []Rule           `toml:"rule"`
	Redirects  []RedirectRule   `toml:"redirect"`
	Heredocs   []HeredocRule    `toml:"heredoc"`
	Constructs ConstructsConfig `toml:"constructs"`
	Debug      DebugConfig      `toml:"debug"`
}

type PolicyConfig struct {
	Default         string `toml:"default"`
	DynamicCommands string `toml:"dynamic_commands"`
	DefaultMessage  string `toml:"default_message"`
}

type CommandsConfig struct {
	Deny  CommandList `toml:"deny"`
	Allow CommandList `toml:"allow"`
}

type CommandList struct {
	Names   []string `toml:"names"`
	Message string   `toml:"message"`
}

type Rule struct {
	Command string      `toml:"command"`
	Action  string      `toml:"action"`
	Message string      `toml:"message"`
	Args    ArgsMatch   `toml:"args"`
	Pipe    PipeContext `toml:"pipe"`
}

type ArgsMatch struct {
	Contains []string       `toml:"contains"`
	AnyMatch []string       `toml:"any_match"`
	AllMatch []string       `toml:"all_match"`
	Position map[int]string `toml:"position"`
}

type PipeContext struct {
	To   []string `toml:"to"`
	From []string `toml:"from"`
}

type RedirectRule struct {
	Action  string         `toml:"action"`
	Message string         `toml:"message"`
	To      RedirectTarget `toml:"to"`
	Append  *bool          `toml:"append"`
}

type RedirectTarget struct {
	Pattern []string `toml:"pattern"`
	Exact   []string `toml:"exact"`
}

type HeredocRule struct {
	Action       string   `toml:"action"`
	Message      string   `toml:"message"`
	ContentMatch []string `toml:"content_match"`
}

type ConstructsConfig struct {
	FunctionDefinitions string `toml:"function_definitions"`
	Background          string `toml:"background"`
	Subshells           string `toml:"subshells"`
	Heredocs            string `toml:"heredocs"`
}

type DebugConfig struct {
	LogFile string `toml:"log_file"`
}

// Specificity scoring constants (same as cc-allow)
const (
	specificityCommand      = 100
	specificityPositionArg  = 20
	specificityContainsArg  = 10
	specificityPatternArg   = 5
	specificityPipeNamed    = 10
	specificityPipeWildcard = 5
)

func calculateSpecificity(rule Rule) int {
	score := 0

	if rule.Command != "*" {
		score += specificityCommand
	}

	score += len(rule.Args.Position) * specificityPositionArg
	score += len(rule.Args.Contains) * specificityContainsArg
	score += len(rule.Args.AnyMatch) * specificityPatternArg
	score += len(rule.Args.AllMatch) * specificityPatternArg

	score += len(rule.Pipe.To) * specificityPipeNamed
	for _, from := range rule.Pipe.From {
		if from == "*" {
			score += specificityPipeWildcard
		} else {
			score += specificityPipeNamed
		}
	}

	return score
}

func calculateRedirectSpecificity(rule RedirectRule) int {
	score := 0
	score += len(rule.To.Exact) * 10
	score += len(rule.To.Pattern) * 5
	if rule.Append != nil {
		score += 5
	}
	return score
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{Path: path}

	// Set defaults
	cfg.Policy.Default = "ask"
	cfg.Policy.DynamicCommands = "ask"
	cfg.Constructs.FunctionDefinitions = "allow"
	cfg.Constructs.Background = "allow"
	cfg.Constructs.Subshells = "allow"

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func findConfigFiles(explicitPath string) []string {
	var paths []string

	// 1. Global config
	if home, err := os.UserHomeDir(); err == nil {
		globalPath := filepath.Join(home, ".config", "cc-allow.toml")
		if _, err := os.Stat(globalPath); err == nil {
			paths = append(paths, globalPath)
		}
	}

	// 2. Project config (search up from cwd)
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for {
			projectPath := filepath.Join(dir, ".claude", "cc-allow.toml")
			if _, err := os.Stat(projectPath); err == nil {
				paths = append(paths, projectPath)
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// 3. Explicit config
	if explicitPath != "" {
		paths = append(paths, explicitPath)
	}

	return paths
}

type ruleWithScore struct {
	index       int
	rule        Rule
	specificity int
	source      string
}

type redirectWithScore struct {
	index       int
	rule        RedirectRule
	specificity int
	source      string
}

type heredocWithScore struct {
	index       int
	rule        HeredocRule
	specificity int
	source      string
}

func main() {
	configPath := flag.String("config", "", "path to specific config file to validate")
	showAll := flag.Bool("all", false, "show all config files in the chain")
	flag.Parse()

	// Find config files
	var paths []string
	if *configPath != "" && !*showAll {
		// Just validate the specified file
		paths = []string{*configPath}
	} else {
		paths = findConfigFiles(*configPath)
	}

	if len(paths) == 0 {
		fmt.Println("No config files found.")
		fmt.Println("\nSearched locations:")
		fmt.Println("  - ~/.config/cc-allow.toml (global)")
		fmt.Println("  - <project>/.claude/cc-allow.toml (project)")
		if *configPath != "" {
			fmt.Printf("  - %s (explicit)\n", *configPath)
		}
		os.Exit(1)
	}

	// Load and validate each config
	var allRules []ruleWithScore
	var allRedirects []redirectWithScore
	var allHeredocs []heredocWithScore
	hasError := false

	fmt.Println("Config Files")
	fmt.Println("============")

	for i, path := range paths {
		cfg, err := loadConfig(path)
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
				specificity: calculateSpecificity(rule),
				source:      path,
			})
		}

		// Collect redirect rules with scores
		for j, rule := range cfg.Redirects {
			allRedirects = append(allRedirects, redirectWithScore{
				index:       j,
				rule:        rule,
				specificity: calculateRedirectSpecificity(rule),
				source:      path,
			})
		}

		// Collect heredoc rules with scores
		for j, rule := range cfg.Heredocs {
			allHeredocs = append(allHeredocs, heredocWithScore{
				index:       j,
				rule:        rule,
				specificity: calculateHeredocSpecificity(rule),
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

		// Sort by specificity descending
		sort.SliceStable(allRules, func(i, j int) bool {
			return allRules[i].specificity > allRules[j].specificity
		})

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

		sort.SliceStable(allRedirects, func(i, j int) bool {
			return allRedirects[i].specificity > allRedirects[j].specificity
		})

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

		sort.SliceStable(allHeredocs, func(i, j int) bool {
			return allHeredocs[i].specificity > allHeredocs[j].specificity
		})

		for _, r := range allHeredocs {
			fmt.Printf("\n[%d] %s\n", r.specificity, formatHeredocRule(r.rule))
			fmt.Printf("    source: %s\n", filepath.Base(r.source))
		}
	}

	fmt.Println("\n\nValidation passed.")
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

func calculateHeredocSpecificity(rule HeredocRule) int {
	// Heredoc rules with content_match are more specific
	return len(rule.ContentMatch) * 10
}
