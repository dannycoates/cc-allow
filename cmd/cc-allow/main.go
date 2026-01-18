package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Version info set via ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Debug logger (nil when debug mode is off)
var debugLog *log.Logger

// HookInput represents the JSON input from Claude Code hooks
type HookInput struct {
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// HookOutput represents the JSON output for Claude Code hooks
type HookOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// Exit codes per Claude Code hooks documentation
const (
	ExitAllow = 0 // Success, command explicitly allowed
	ExitAsk = 1 // Non-blocking, ask user via Claude Code's default behavior
	ExitDeny  = 2 // Blocking error, command explicitly denied
	ExitError = 3 // Processing error (parse failure, config error, etc.)
)

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file (adds to config chain)")
	hookMode := flag.Bool("hook", false, "parse Claude Code hook JSON input (extracts tool_input.command)")
	showVersion := flag.Bool("version", false, "print version and exit")
	debugMode := flag.Bool("debug", false, "enable debug logging to stderr and $TMPDIR/cc-allow.log")
	fmtMode := flag.Bool("fmt", false, "validate config and display rules sorted by specificity")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cc-allow %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if *fmtMode {
		runFmt(*configPath)
		return
	}

	// Load configuration chain from standard locations + explicit path
	chain, err := LoadConfigChain(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(ExitError)
	}

	// Initialize debug logging (after config load so we can use configured path)
	if *debugMode {
		logPath := getDebugLogPath(chain)
		initDebugLog(logPath)
	}
	logDebugConfigChain(chain)

	// Get the bash command to parse
	var input io.Reader = os.Stdin
	var commandStr string
	if *hookMode {
		// Parse JSON hook input and extract command
		var hookInput HookInput
		if err := json.NewDecoder(os.Stdin).Decode(&hookInput); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing hook JSON: %v\n", err)
			os.Exit(ExitError)
		}
		if hookInput.ToolInput.Command == "" {
			// No command to evaluate, defer to Claude Code
			outputHookResult(Result{Action: "ask"})
		}
		commandStr = hookInput.ToolInput.Command
		input = strings.NewReader(commandStr)
	} else {
		// Read stdin for plain mode to capture for debug logging
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(ExitError)
		}
		commandStr = string(data)
		input = strings.NewReader(commandStr)
	}
	logDebug("Input command: %q", commandStr)

	// Parse bash input
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(input, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
		os.Exit(ExitError)
	}

	// Extract commands and context from AST
	info := ExtractFromFile(f)
	logDebugExtractedInfo(info)

	// Evaluate against all configs (strictest wins)
	eval := NewEvaluator(chain)
	result := eval.Evaluate(info)
	logDebug("Result: action=%q message=%q command=%q source=%q", result.Action, result.Message, result.Command, result.Source)

	outputResult(result, *hookMode)
}

func outputResult(result Result, hookMode bool) {
	if hookMode {
		outputHookResult(result)
	} else {
		outputPlainResult(result)
	}
}

func outputHookResult(result Result) {
	var output HookOutput
	output.HookSpecificOutput.HookEventName = "PreToolUse"

	switch result.Action {
	case "allow":
		output.HookSpecificOutput.PermissionDecision = "allow"
		output.HookSpecificOutput.PermissionDecisionReason = "Allowed by cc-allow policy"
	case "deny":
		output.HookSpecificOutput.PermissionDecision = "deny"
		if result.Message != "" {
			output.HookSpecificOutput.PermissionDecisionReason = result.Message
		} else {
			output.HookSpecificOutput.PermissionDecisionReason = "Denied by cc-allow policy"
		}
	default: // "ask" - defer to Claude Code's default behavior
		output.HookSpecificOutput.PermissionDecision = "ask"
		reason := "No cc-allow rules matched"
		if result.Source != "" {
			reason = result.Source
		}
		if result.Command != "" {
			reason = result.Command + ": " + reason
		}
		output.HookSpecificOutput.PermissionDecisionReason = reason
	}

	json.NewEncoder(os.Stdout).Encode(output)
	os.Exit(0)
}

func outputPlainResult(result Result) {
	switch result.Action {
	case "allow":
		os.Exit(ExitAllow)
	case "deny":
		if result.Message != "" {
			if result.Source != "" {
				fmt.Fprintf(os.Stderr, "Deny: %s (%s)\n", result.Message, result.Source)
			} else {
				fmt.Fprintln(os.Stderr, result.Message)
			}
		}
		os.Exit(ExitDeny)
	default: // "ask" or empty
		reason := "no rules matched"
		if result.Source != "" {
			reason = result.Source
		}
		if result.Command != "" {
			fmt.Fprintf(os.Stderr, "Ask: %s: %s\n", result.Command, reason)
		} else {
			fmt.Fprintf(os.Stderr, "Ask: %s\n", reason)
		}
		os.Exit(ExitAsk)
	}
}

// Helper functions for word extraction (used by tests and walk.go)

func wordToString(word *syntax.Word) string {
	var parts []string
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			parts = append(parts, p.Value)
		case *syntax.SglQuoted:
			parts = append(parts, p.Value)
		case *syntax.DblQuoted:
			parts = append(parts, wordPartsToString(p.Parts))
		case *syntax.ParamExp:
			if p.Param != nil {
				parts = append(parts, "$"+p.Param.Value)
			}
		default:
			parts = append(parts, fmt.Sprintf("<%T>", p))
		}
	}
	return strings.Join(parts, "")
}

func wordPartsToString(wps []syntax.WordPart) string {
	var parts []string
	for _, part := range wps {
		switch p := part.(type) {
		case *syntax.Lit:
			parts = append(parts, p.Value)
		case *syntax.ParamExp:
			if p.Param != nil {
				parts = append(parts, "$"+p.Param.Value)
			}
		default:
			parts = append(parts, fmt.Sprintf("<%T>", p))
		}
	}
	return strings.Join(parts, "")
}

// Debug logging helpers

type multiWriter struct {
	writers []io.Writer
}

func (mw *multiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		w.Write(p) // Best-effort write to each
	}
	return len(p), nil
}

func initDebugLog(logPath string) {
	writers := []io.Writer{os.Stderr}

	// Also write to log file
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		writers = append(writers, f)
		fmt.Fprintf(os.Stderr, "[debug] Log file: %s\n", logPath)
	}

	debugLog = log.New(&multiWriter{writers}, "[cc-allow] ", log.Ltime)
}

// getDebugLogPath returns the debug log path from config chain, or default.
func getDebugLogPath(chain *ConfigChain) string {
	// Check each config in order for a configured log_file
	for _, cfg := range chain.Configs {
		if cfg.Debug.LogFile != "" {
			return cfg.Debug.LogFile
		}
	}
	// Default to temp directory
	return filepath.Join(os.TempDir(), "cc-allow.log")
}

func logDebug(format string, args ...interface{}) {
	if debugLog != nil {
		debugLog.Printf(format, args...)
	}
}

func logDebugConfigChain(chain *ConfigChain) {
	if debugLog == nil {
		return
	}
	logDebug("Config chain: %d config(s) loaded", len(chain.Configs))
	for i, cfg := range chain.Configs {
		logDebug("  [%d] policy.default=%s, policy.dynamic_commands=%s", i, cfg.Policy.Default, cfg.Policy.DynamicCommands)
		if len(cfg.Commands.Deny.Names) > 0 {
			logDebug("      commands.deny.names=%v", cfg.Commands.Deny.Names)
		}
		if len(cfg.Commands.Allow.Names) > 0 {
			logDebug("      commands.allow.names=%v", cfg.Commands.Allow.Names)
		}
		logDebug("      %d rule(s), %d redirect rule(s)", len(cfg.Rules), len(cfg.Redirects))
	}
}

func logDebugExtractedInfo(info *ExtractedInfo) {
	if debugLog == nil {
		return
	}
	logDebug("Extracted info:")
	logDebug("  Commands: %d", len(info.Commands))
	for i, cmd := range info.Commands {
		logDebug("    [%d] name=%q args=%v dynamic=%v pipesTo=%v pipesFrom=%v",
			i, cmd.Name, cmd.Args, cmd.IsDynamic, cmd.PipesTo, cmd.PipesFrom)
	}
	logDebug("  Redirects: %d", len(info.Redirects))
	for i, redir := range info.Redirects {
		logDebug("    [%d] target=%q append=%v dynamic=%v fd=%v", i, redir.Target, redir.Append, redir.IsDynamic, redir.IsFdRedirect)
	}
	logDebug("  Constructs: hasFuncDefs=%v hasBackground=%v", info.Constructs.HasFunctionDefs, info.Constructs.HasBackground)
}

// Fmt mode - validate config and display rules sorted by specificity

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

func runFmt(configPath string) {
	// Find config files
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

	// Load and validate each config
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

	// 1. Global config
	if globalPath := findGlobalConfig(); globalPath != "" {
		paths = append(paths, globalPath)
	}

	// 2. Project config
	if projectPath := findProjectConfig(); projectPath != "" {
		paths = append(paths, projectPath)
	}

	// 3. Project local config
	if localPath := findProjectLocalConfig(); localPath != "" {
		paths = append(paths, localPath)
	}

	// 4. Explicit config
	if explicitPath != "" {
		paths = append(paths, explicitPath)
	}

	return paths
}

func sortRulesBySpecificity(rules []ruleWithScore) {
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].specificity > rules[i].specificity {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
}

func sortRedirectsBySpecificity(rules []redirectWithScore) {
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].specificity > rules[i].specificity {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
}

func sortHeredocsBySpecificity(rules []heredocWithScore) {
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].specificity > rules[i].specificity {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}
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

func calculateHeredocSpecificity(rule HeredocRule) int {
	return len(rule.ContentMatch) * 10
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
