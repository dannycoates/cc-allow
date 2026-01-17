package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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
	ExitPass  = 1 // Non-blocking, pass through to Claude Code's default behavior
	ExitDeny  = 2 // Blocking error, command explicitly denied
	ExitError = 3 // Processing error (parse failure, config error, etc.)
)

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file (adds to config chain)")
	hookMode := flag.Bool("hook", false, "parse Claude Code hook JSON input (extracts tool_input.command)")
	flag.Parse()

	// Load configuration chain from standard locations + explicit path
	chain, err := LoadConfigChain(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(ExitError)
	}

	// Get the bash command to parse
	var input io.Reader = os.Stdin
	if *hookMode {
		// Parse JSON hook input and extract command
		var hookInput HookInput
		if err := json.NewDecoder(os.Stdin).Decode(&hookInput); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing hook JSON: %v\n", err)
			os.Exit(ExitError)
		}
		if hookInput.ToolInput.Command == "" {
			// No command to evaluate, defer to Claude Code
			outputHookResult(Result{Action: "pass"})
		}
		input = strings.NewReader(hookInput.ToolInput.Command)
	}

	// Parse bash input
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(input, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
		os.Exit(ExitError)
	}

	// Extract commands and context from AST
	info := ExtractFromFile(f)

	// Evaluate against all configs (strictest wins)
	eval := NewEvaluator(chain)
	result := eval.Evaluate(info)

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
	default: // "pass" - defer to Claude Code's default behavior
		output.HookSpecificOutput.PermissionDecision = "ask"
		output.HookSpecificOutput.PermissionDecisionReason = "No cc-allow rules matched"
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
			fmt.Fprintln(os.Stderr, result.Message)
		}
		os.Exit(ExitDeny)
	default: // "pass" or empty
		fmt.Fprintln(os.Stderr, "Pass: no rules matched")
		os.Exit(ExitPass)
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
