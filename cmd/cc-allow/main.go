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
	flag.Parse()

	if *showVersion {
		fmt.Printf("cc-allow %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
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
