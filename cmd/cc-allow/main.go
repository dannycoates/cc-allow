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
	"time"

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

// Debug loggers (nil when debug mode is off)
var debugStderr *log.Logger
var debugFile *os.File

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
	debugMode := flag.Bool("debug", false, "enable debug logging to stderr and per-session JSONL log files")
	fmtMode := flag.Bool("fmt", false, "validate config and display rules sorted by specificity")
	initMode := flag.Bool("init", false, "create project config at .config/cc-allow.toml")
	sessionID := flag.String("session", "", "session ID for session-scoped config lookup")

	// Tool-specific modes (stdin is the path or command to check)
	bashMode := flag.Bool("bash", false, "check bash command rules (stdin is bash command)")
	readMode := flag.Bool("read", false, "check file read rules (stdin is file path)")
	writeMode := flag.Bool("write", false, "check file write rules (stdin is file path)")
	editMode := flag.Bool("edit", false, "check file edit rules (stdin is file path)")
	fetchMode := flag.Bool("fetch", false, "check webfetch URL rules (stdin is URL)")
	globMode := flag.Bool("glob", false, "check glob search rules (stdin is search path)")
	grepMode := flag.Bool("grep", false, "check grep search rules (stdin is search path)")
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
	var toolMode ToolName
	modeCount := 0
	if *bashMode {
		toolMode = ToolBash
		modeCount++
	}
	if *readMode {
		toolMode = ToolRead
		modeCount++
	}
	if *writeMode {
		toolMode = ToolWrite
		modeCount++
	}
	if *editMode {
		toolMode = ToolEdit
		modeCount++
	}
	if *fetchMode {
		toolMode = ToolWebFetch
		modeCount++
	}
	if *globMode {
		toolMode = ToolGlob
		modeCount++
	}
	if *grepMode {
		toolMode = ToolGrep
		modeCount++
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "Error: only one of --bash, --read, --write, --edit, --fetch, --glob, --grep can be specified")
		os.Exit(int(ExitError))
	}

	switch {
	case *showVersion:
		fmt.Printf("cc-allow %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	case *initMode:
		os.Exit(int(runInit(*hookMode)))
	case *fmtMode:
		os.Exit(int(runFmt(*configPath, *sessionID)))
	default:
		os.Exit(int(runEval(*configPath, *sessionID, *hookMode, *debugMode, toolMode)))
	}
}

// runEval evaluates a tool request against the config chain.
// In hook mode, it reads JSON from stdin and outputs JSON.
// In pipe mode, it reads the input directly from stdin.
// toolMode specifies the tool type: "Bash", "Read", "Write", "Edit", or "" (defaults to Bash).
func runEval(configPath string, sessionID string, hookMode, debugMode bool, toolMode ToolName) ExitCode {
	// 1. Build input first (need session ID from hook JSON)
	input, err := buildInput(hookMode, toolMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}

	// 2. Determine effective session ID: hook JSON overrides flag
	effectiveSessionID := sessionID
	if hookMode && input.SessionID != "" {
		effectiveSessionID = input.SessionID
	}

	// 3. Load config chain with session ID
	chain, err := LoadConfigChain(configPath, effectiveSessionID)
	if err != nil {
		if hookMode {
			return outputHookConfigError(err)
		}
		fmt.Fprintln(os.Stderr, formatConfigError(err))
		return ExitError
	}

	// 4. Session cleanup (best-effort)
	if chain.Merged.Settings.SessionMaxAge != "" {
		if maxAge, err := parseSessionMaxAge(chain.Merged.Settings.SessionMaxAge); err == nil {
			cleanupSessionConfigs(chain.ProjectRoot, maxAge)
		}
	}

	// 5. Init debug logging
	if debugMode {
		logPath := getDebugLogPath(chain, effectiveSessionID)
		initDebugLog(logPath)
	}
	logDebugConfigChain(chain)

	// Build additional context for hook output
	var additionalContext string
	if len(chain.MigrationHints) > 0 {
		additionalContext = buildMigrationMessage(chain.MigrationHints)
	}

	// Warn if cwd has drifted from project root
	if hookMode && chain.ProjectRoot != "" {
		if cwd, err := os.Getwd(); err == nil && cwd != chain.ProjectRoot {
			msg := "<system-reminder>your cwd is not at your project root. cd back to " + chain.ProjectRoot + "</system-reminder>"
			if additionalContext != "" {
				additionalContext += "\n" + msg
			} else {
				additionalContext = msg
			}
		}
	}

	// Dispatch
	dispatcher := NewToolDispatcher(chain)
	result := dispatcher.Dispatch(input)

	// Structured debug log entry
	logDebugEval(input, result)
	logDebug("decision: %s", result.Action)

	// Output
	if hookMode {
		return outputHookResult(result, additionalContext)
	}
	return outputPlainResult(result)
}

// buildInput constructs a HookInput from stdin based on mode.
func buildInput(hookMode bool, toolMode ToolName) (HookInput, error) {
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
		toolMode = ToolBash
	}

	var input HookInput
	input.ToolName = toolMode
	switch toolMode {
	case ToolBash:
		input.ToolInput.Command = value
	case ToolRead, ToolWrite, ToolEdit:
		input.ToolInput.FilePath = value
	case ToolWebFetch:
		input.ToolInput.URL = value
	case ToolGlob, ToolGrep:
		input.ToolInput.Path = value
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
	debugStderr = log.New(os.Stderr, "[cc-allow] ", log.Ltime)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		debugFile = f
		fmt.Fprintf(os.Stderr, "[debug] Log file: %s\n", logPath)
	}
}

// getDebugLogPath returns the debug log path from config chain, or default.
func getDebugLogPath(chain *ConfigChain, sessionID string) string {
	// Find configured log_dir
	var dir string
	for _, cfg := range chain.Configs {
		if cfg.Debug.LogDir != "" {
			dir = cfg.Debug.LogDir
		}
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "cc-allow-debug")
	}
	os.MkdirAll(dir, 0755)

	// Per-session log file if session ID available
	if sessionID != "" {
		return filepath.Join(dir, sessionID+".log")
	}
	return filepath.Join(dir, "cc-allow.log")
}

func logDebug(format string, args ...any) {
	if debugStderr == nil {
		return
	}
	debugStderr.Printf(format+"\n", args...)
}

// logDebugEntry writes a structured JSONL entry to the debug log file.
func logDebugEntry(v any) {
	if debugFile == nil {
		return
	}
	entry, _ := json.Marshal(v)
	debugFile.Write(append(entry, '\n'))
}

func logDebugConfigChain(chain *ConfigChain) {
	if debugStderr == nil {
		return
	}
	logDebug("Config chain: %d config(s) loaded", len(chain.Configs))
	for i, cfg := range chain.Configs {
		logDebug("  [%d] %s (%d rules, %d redirects, %d heredocs)",
			i, cfg.Path, len(cfg.getParsedRules()), len(cfg.getParsedRedirects()), len(cfg.getParsedHeredocs()))
	}
}

func logDebugExtractedInfo(info *ExtractedInfo) {
	if debugStderr == nil {
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

// logDebugEval writes a structured evaluation entry to both stderr and JSONL.
func logDebugEval(input HookInput, result Result) {
	if debugStderr == nil {
		return
	}

	// Determine the input value for display
	var inputValue string
	switch input.ToolName {
	case ToolRead, ToolWrite, ToolEdit:
		inputValue = input.ToolInput.FilePath
	case ToolWebFetch:
		inputValue = input.ToolInput.URL
	case ToolGlob, ToolGrep:
		inputValue = input.ToolInput.Path
	default:
		inputValue = input.ToolInput.Command
	}

	// Stderr: concise text summary
	logDebug("=> %s %s action=%s source=%q", input.ToolName, inputValue, result.Action, result.Source)
	if result.Message != "" {
		logDebug("   message=%q", result.Message)
	}

	// JSONL: structured entry
	type logEntry struct {
		Ts      string `json:"ts"`
		Tool    string `json:"tool"`
		Input   string `json:"input"`
		Action  string `json:"action"`
		Source  string `json:"source,omitempty"`
		Command string `json:"command,omitempty"`
		Message string `json:"message,omitempty"`
	}
	logDebugEntry(logEntry{
		Ts:      time.Now().Format(time.RFC3339Nano),
		Tool:    string(input.ToolName),
		Input:   inputValue,
		Action:  string(result.Action),
		Source:  result.Source,
		Command: result.Command,
		Message: result.Message,
	})
}

// Init mode - create project config file

func runInit(hookMode bool) ExitCode {
	// In hook mode, read SessionStart JSON and only init on "startup"
	if hookMode {
		var event struct {
			Source string `json:"source"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&event); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse hook JSON: %v\n", err)
			return ExitError
		}
		if event.Source != "startup" {
			return ExitAllow
		}
	}

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

	// 5. Ensure sessions directory with .gitignore exists
	sessionsDir := filepath.Join(root, ".config", "cc-allow", "sessions")
	if err := os.MkdirAll(sessionsDir, 0755); err == nil {
		gitignorePath := filepath.Join(sessionsDir, ".gitignore")
		if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
			os.WriteFile(gitignorePath, []byte("*\n!.gitignore\n"), 0644)
		}
	}

	// 6. Choose template based on user config existence
	var content string
	if findGlobalConfig() == "" {
		content = fullTemplate
	} else {
		content = stubTemplate
	}

	// 7. Write config
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		return ExitError
	}

	fmt.Printf("Created %s\n", configPath)
	return ExitAllow
}
