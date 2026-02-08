package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

//go:embed templates/stub.toml
var stubTemplate string

//go:embed templates/full.toml
var fullTemplate string

// Version info set via ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Debug logger (nil when debug mode is off)
var debugLog *log.Logger

// HookOutput represents the JSON output for Claude Code hooks
type HookOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file (adds to config chain)")
	agentType := flag.String("agent", "", "agent type to load config for (looks for .config/cc-allow/<agent>.toml)")
	hookMode := flag.Bool("hook", false, "parse Claude Code hook JSON input (extracts tool_input.command)")
	showVersion := flag.Bool("version", false, "print version and exit")
	debugMode := flag.Bool("debug", false, "enable debug logging to stderr and $TMPDIR/cc-allow.log")
	fmtMode := flag.Bool("fmt", false, "validate config and display rules sorted by specificity")
	initMode := flag.Bool("init", false, "create project config at .config/cc-allow.toml")

	// Tool-specific modes (stdin is the path or command to check)
	bashMode := flag.Bool("bash", false, "check bash command rules (stdin is bash command)")
	readMode := flag.Bool("read", false, "check file read rules (stdin is file path)")
	writeMode := flag.Bool("write", false, "check file write rules (stdin is file path)")
	editMode := flag.Bool("edit", false, "check file edit rules (stdin is file path)")
	fetchMode := flag.Bool("fetch", false, "check webfetch URL rules (stdin is URL)")
	flag.Parse()

	// --agent and --config are mutually exclusive
	if *agentType != "" && *configPath != "" {
		fmt.Fprintln(os.Stderr, "Error: --agent and --config cannot be used together")
		os.Exit(int(ExitError))
	}

	// Resolve --agent to a config path
	if *agentType != "" {
		if agentPath := findAgentConfig(*agentType); agentPath != "" {
			*configPath = agentPath
		}
	}

	// Fall back to env var if --config not specified
	if *configPath == "" {
		*configPath = os.Getenv("CC_ALLOW_CONFIG")
	}

	// Determine tool mode
	toolMode := ""
	modeCount := 0
	if *bashMode {
		toolMode = "Bash"
		modeCount++
	}
	if *readMode {
		toolMode = "Read"
		modeCount++
	}
	if *writeMode {
		toolMode = "Write"
		modeCount++
	}
	if *editMode {
		toolMode = "Edit"
		modeCount++
	}
	if *fetchMode {
		toolMode = "WebFetch"
		modeCount++
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "Error: only one of --bash, --read, --write, --edit, --fetch can be specified")
		os.Exit(int(ExitError))
	}

	switch {
	case *showVersion:
		fmt.Printf("cc-allow %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	case *initMode:
		os.Exit(int(runInit()))
	case *fmtMode:
		os.Exit(int(runFmt(*configPath)))
	default:
		os.Exit(int(runEval(*configPath, *hookMode, *debugMode, toolMode)))
	}
}

// runEval evaluates a tool request against the config chain.
// In hook mode, it reads JSON from stdin and outputs JSON.
// In pipe mode, it reads the input directly from stdin.
// toolMode specifies the tool type: "Bash", "Read", "Write", "Edit", or "" (defaults to Bash).
func runEval(configPath string, hookMode, debugMode bool, toolMode string) ExitCode {
	// Load configuration chain from standard locations + explicit path
	chain, err := LoadConfigChain(configPath)
	if err != nil {
		if hookMode {
			return outputHookConfigError(err)
		}
		fmt.Fprintln(os.Stderr, formatConfigError(err))
		return ExitError
	}

	// Initialize debug logging (after config load so we can use configured path)
	if debugMode {
		logPath := getDebugLogPath(chain)
		initDebugLog(logPath)
	}
	logDebugConfigChain(chain)

	// Build migration context for hook output
	var migrationContext string
	if len(chain.MigrationHints) > 0 {
		migrationContext = buildMigrationMessage(chain.MigrationHints)
	}

	// Build input
	input, err := buildInput(hookMode, toolMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	// Dispatch
	dispatcher := NewToolDispatcher(chain)
	result := dispatcher.Dispatch(input)

	// Output
	if hookMode {
		return outputHookResult(result, migrationContext)
	}
	return outputPlainResult(result)
}

// buildInput constructs a HookInput from stdin based on mode.
func buildInput(hookMode bool, toolMode string) (HookInput, error) {
	if hookMode {
		var input HookInput
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			return HookInput{}, fmt.Errorf("parsing hook JSON: %w", err)
		}
		return input, nil
	}

	// Pipe mode: read raw input from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return HookInput{}, fmt.Errorf("reading stdin: %w", err)
	}
	value := strings.TrimSpace(string(data))

	// Default to Bash
	if toolMode == "" {
		toolMode = "Bash"
	}

	var input HookInput
	input.ToolName = toolMode
	switch toolMode {
	case "Bash":
		input.ToolInput.Command = value
	case "Read", "Write", "Edit":
		input.ToolInput.FilePath = value
	case "WebFetch":
		input.ToolInput.URL = value
	}
	return input, nil
}

func outputHookResult(result Result, additionalContext string) ExitCode {
	var output HookOutput
	output.HookSpecificOutput.HookEventName = "PreToolUse"

	switch result.Action {
	case ActionAllow:
		output.HookSpecificOutput.PermissionDecision = string(ActionAllow)
		output.HookSpecificOutput.PermissionDecisionReason = "Allowed by cc-allow policy"
	case ActionDeny:
		output.HookSpecificOutput.PermissionDecision = string(ActionDeny)
		if result.Message != "" {
			output.HookSpecificOutput.PermissionDecisionReason = result.Message
		} else {
			output.HookSpecificOutput.PermissionDecisionReason = "Denied by cc-allow policy"
		}
	default: // ActionAsk - defer to Claude Code's default behavior
		output.HookSpecificOutput.PermissionDecision = string(ActionAsk)
		reason := "No cc-allow rules matched"
		if result.Message != "" {
			reason = result.Message
		} else if result.Source != "" {
			reason = result.Source
		}
		if result.Command != "" {
			reason = result.Command + ": " + reason
		}
		output.HookSpecificOutput.PermissionDecisionReason = reason
	}

	if additionalContext != "" {
		output.HookSpecificOutput.AdditionalContext = additionalContext
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		return ExitError
	}
	return ExitAllow
}

// outputHookConfigError outputs a hook error response for config loading failures.
// For version-related errors (legacy v1 config), it includes migration guidance in additionalContext.
// For validation errors, it offers to help fix the config.
func outputHookConfigError(err error) ExitCode {
	var output HookOutput
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.PermissionDecision = string(ActionAsk)

	// Format the error message based on error type
	var cfgErr *ConfigError
	var valErr *ConfigValidationError
	if errors.As(err, &cfgErr) {
		output.HookSpecificOutput.PermissionDecisionReason = "cc-allow config error: " + cfgErr.Error()
	} else if errors.As(err, &valErr) {
		output.HookSpecificOutput.PermissionDecisionReason = "cc-allow config error: " + valErr.Error()
	} else {
		output.HookSpecificOutput.PermissionDecisionReason = fmt.Sprintf("cc-allow config error: %v", err)
	}

	// Check if this is a version-related error and add migration guidance
	// This catches both LegacyConfigError (v1 keys detected) and explicit v1.x version strings
	var legacyErr LegacyConfigError
	isVersionError := errors.As(err, &legacyErr) || strings.Contains(err.Error(), "legacy format")
	if isVersionError {
		output.HookSpecificOutput.AdditionalContext = "The cc-allow config file uses the legacy v1 format. " +
			"Please ask the user if they would like help migrating their config to the v2 format. " +
			"The migration guide is available at: https://raw.githubusercontent.com/dannycoates/cc-allow/main/docs/migration.md"
	} else {
		// For other config errors (validation, parse errors), offer to fix
		configPath := extractConfigPath(err)
		if configPath != "" {
			output.HookSpecificOutput.AdditionalContext = fmt.Sprintf(
				"There is an error in the cc-allow config file at %s. "+
					"Offer to fix the error for the user using the /allow-rules skill.",
				configPath)
		} else {
			output.HookSpecificOutput.AdditionalContext = "There is an error in the cc-allow config. " +
				"Offer to help the user fix the configuration error using the /allow-rules skill."
		}
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		return ExitError
	}
	return ExitAllow
}

// extractConfigPath extracts the config file path from a config error.
func extractConfigPath(err error) string {
	var cfgErr *ConfigError
	if errors.As(err, &cfgErr) && cfgErr.Path != "" {
		return cfgErr.Path
	}
	return ""
}

func outputPlainResult(result Result) ExitCode {
	switch result.Action {
	case ActionAllow:
		// No output for allow
	case ActionDeny:
		if result.Message != "" {
			if result.Source != "" {
				fmt.Fprintf(os.Stderr, "Deny: %s (%s)\n", result.Message, result.Source)
			} else {
				fmt.Fprintln(os.Stderr, result.Message)
			}
		}
	default: // ActionAsk or empty
		reason := "no rules matched"
		if result.Message != "" {
			reason = result.Message
		} else if result.Source != "" {
			reason = result.Source
		}
		if result.Command != "" {
			fmt.Fprintf(os.Stderr, "Ask: %s: %s\n", result.Command, reason)
		} else {
			fmt.Fprintf(os.Stderr, "Ask: %s\n", reason)
		}
	}
	return result.Action.ExitCode()
}

// formatConfigError formats a config error for human-readable output.
// It handles ConfigError and ConfigValidationError specially to provide
// structured output with file path, location, and value context.
func formatConfigError(err error) string {
	var cfgErr *ConfigError
	var valErr *ConfigValidationError

	if errors.As(err, &cfgErr) {
		return "Error: " + cfgErr.Error()
	}

	if errors.As(err, &valErr) {
		return "Error: " + valErr.Error()
	}

	return "Error loading config: " + err.Error()
}

// buildMigrationMessage constructs an additionalContext message for legacy config locations.
func buildMigrationMessage(legacyPaths []string) string {
	var moves []string
	for _, oldPath := range legacyPaths {
		dir := filepath.Dir(filepath.Dir(oldPath)) // go up from .claude/
		base := filepath.Base(oldPath)
		newPath := filepath.Join(dir, ".config", base)
		moves = append(moves, fmt.Sprintf("mv %s %s", oldPath, newPath))
	}
	return fmt.Sprintf(
		"The cc-allow project config was found at a legacy location (.claude/). "+
			"The default location has changed to .config/. "+
			"Please offer to move the config file(s) for the user by running: %s",
		strings.Join(moves, " && "),
	)
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

func initDebugLog(logPath string) {
	writers := []io.Writer{os.Stderr}

	// Also write to log file
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		writers = append(writers, f)
		fmt.Fprintf(os.Stderr, "[debug] Log file: %s\n", logPath)
	}

	debugLog = log.New(io.MultiWriter(writers...), "[cc-allow] ", log.Ltime)
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

func logDebug(format string, args ...any) {
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
		logDebug("  [%d] %s", i, cfg.Path)
		logDebug("      bash: default=%s, dynamic_commands=%s", cfg.Bash.Default, cfg.Bash.DynamicCommands)
		if len(cfg.Bash.Deny.Commands) > 0 {
			logDebug("      bash.deny.commands: %s", strings.Join(cfg.Bash.Deny.Commands, ", "))
		}
		if len(cfg.Bash.Allow.Commands) > 0 {
			logDebug("      bash.allow.commands: %s", strings.Join(cfg.Bash.Allow.Commands, ", "))
		}
		logDebug("      %d rule(s), %d redirect(s), %d heredoc(s)", len(cfg.getParsedRules()), len(cfg.getParsedRedirects()), len(cfg.getParsedHeredocs()))
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

// Init mode - create project config file

func runInit() ExitCode {
	// 1. Find project root
	root := findProjectRoot()
	if root == "" {
		fmt.Fprintln(os.Stderr, "Could not determine project root (no .config/cc-allow.toml, .claude/, or .git/ found)")
		return ExitError
	}

	// 2. Check if config already exists at new location
	configPath := filepath.Join(root, ".config", "cc-allow.toml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config already exists: %s\n", configPath)
		return ExitAllow
	}

	// 3. Check legacy location and warn
	legacyPath := filepath.Join(root, ".claude", "cc-allow.toml")
	if _, err := os.Stat(legacyPath); err == nil {
		fmt.Printf("Config exists at legacy location: %s\n", legacyPath)
		fmt.Printf("Move it to the new location: mv %s %s\n", legacyPath, configPath)
		return ExitAllow
	}

	// 4. Ensure .config directory exists
	configDir := filepath.Join(root, ".config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create .config directory: %v\n", err)
		return ExitError
	}

	// 5. Choose template based on user config existence
	var content string
	if findGlobalConfig() == "" {
		content = fullTemplate
	} else {
		content = stubTemplate
	}

	// 6. Write config
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		return ExitError
	}

	fmt.Printf("Created %s\n", configPath)
	return ExitAllow
}
