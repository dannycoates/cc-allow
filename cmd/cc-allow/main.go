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

// Exit codes per Claude Code hooks documentation
const (
	ExitAllow = 0 // Success, command explicitly allowed
	ExitAsk   = 1 // Non-blocking, ask user via Claude Code's default behavior
	ExitDeny  = 2 // Blocking error, command explicitly denied
	ExitError = 3 // Processing error (parse failure, config error, etc.)
)

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file (adds to config chain)")
	hookMode := flag.Bool("hook", false, "parse Claude Code hook JSON input (extracts tool_input.command)")
	showVersion := flag.Bool("version", false, "print version and exit")
	debugMode := flag.Bool("debug", false, "enable debug logging to stderr and $TMPDIR/cc-allow.log")
	fmtMode := flag.Bool("fmt", false, "validate config and display rules sorted by specificity")
	initMode := flag.Bool("init", false, "create project config at .claude/cc-allow.toml")

	// Tool-specific modes (stdin is the path or command to check)
	bashMode := flag.Bool("bash", false, "check bash command rules (stdin is bash command)")
	readMode := flag.Bool("read", false, "check file read rules (stdin is file path)")
	writeMode := flag.Bool("write", false, "check file write rules (stdin is file path)")
	editMode := flag.Bool("edit", false, "check file edit rules (stdin is file path)")
	flag.Parse()

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
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "Error: only one of --bash, --read, --write, --edit can be specified")
		os.Exit(ExitError)
	}

	switch {
	case *showVersion:
		fmt.Printf("cc-allow %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	case *initMode:
		runInit()
	case *fmtMode:
		runFmt(*configPath)
	default:
		runEval(*configPath, *hookMode, *debugMode, toolMode)
	}
}

// runEval evaluates a tool request against the config chain.
// In hook mode, it reads JSON from stdin and outputs JSON.
// In pipe mode, it reads the input directly from stdin.
// toolMode specifies the tool type: "Bash", "Read", "Write", "Edit", or "" (defaults to Bash).
func runEval(configPath string, hookMode, debugMode bool, toolMode string) {
	// Load configuration chain from standard locations + explicit path
	chain, err := LoadConfigChain(configPath)
	if err != nil {
		if hookMode {
			outputHookConfigError(err)
		} else {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(ExitError)
		}
		return
	}

	// Initialize debug logging (after config load so we can use configured path)
	if debugMode {
		logPath := getDebugLogPath(chain)
		initDebugLog(logPath)
	}
	logDebugConfigChain(chain)

	// Build input
	input, err := buildInput(hookMode, toolMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(ExitError)
	}

	// Dispatch
	dispatcher := NewToolDispatcher(chain)
	result := dispatcher.Dispatch(input)

	// Output
	if hookMode {
		outputHookResult(result)
	} else {
		outputPlainResult(result)
	}
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
	}
	return input, nil
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

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		os.Exit(ExitError)
	}
	os.Exit(0)
}

// outputHookConfigError outputs a hook error response for config loading failures.
// For version-related errors (legacy v1 config), it includes migration guidance in additionalContext.
func outputHookConfigError(err error) {
	var output HookOutput
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.PermissionDecision = "ask"
	output.HookSpecificOutput.PermissionDecisionReason = fmt.Sprintf("cc-allow config error: %v", err)

	// Check if this is a version-related error and add migration guidance
	// This catches both LegacyConfigError (v1 keys detected) and explicit v1.x version strings
	var legacyErr LegacyConfigError
	isVersionError := errors.As(err, &legacyErr) || strings.Contains(err.Error(), "legacy format")
	if isVersionError {
		output.HookSpecificOutput.AdditionalContext = "The cc-allow config file uses the legacy v1 format. " +
			"Please ask the user if they would like help migrating their config to the v2 format. " +
			"The migration guide is available at: https://raw.githubusercontent.com/dannycoates/cc-allow/main/docs/migration.md"
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		os.Exit(ExitError)
	}
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

func runInit() {
	// 1. Find project root
	root := findProjectRoot()
	if root == "" {
		fmt.Fprintln(os.Stderr, "Could not determine project root (no .claude/ or .git/ found)")
		os.Exit(1)
	}

	// 2. Check if config already exists
	configPath := filepath.Join(root, ".claude", "cc-allow.toml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config already exists: %s\n", configPath)
		os.Exit(0)
	}

	// 3. Ensure .claude directory exists
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create .claude directory: %v\n", err)
		os.Exit(1)
	}

	// 4. Choose template based on user config existence
	var content string
	if findGlobalConfig() == "" {
		content = fullTemplate
	} else {
		content = stubTemplate
	}

	// 5. Write config
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created %s\n", configPath)
}
