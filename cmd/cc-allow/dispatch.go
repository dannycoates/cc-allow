package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HookInput represents the JSON input from Claude Code hooks
type HookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`   // Bash tool
		FilePath string `json:"file_path"` // Read, Edit, Write tools
	} `json:"tool_input"`
}

// ToolDispatcher routes tool requests to appropriate evaluators
type ToolDispatcher struct {
	chain *ConfigChain
}

// NewToolDispatcher creates a dispatcher with the given config chain
func NewToolDispatcher(chain *ConfigChain) *ToolDispatcher {
	return &ToolDispatcher{chain: chain}
}

// Dispatch routes the hook input to the appropriate tool evaluator
func (d *ToolDispatcher) Dispatch(input HookInput) Result {
	switch input.ToolName {
	case "Read", "Edit", "Write":
		return d.evaluateFile(input)
	case "Bash", "":
		return d.evaluateBash(input)
	default:
		return Result{Action: "ask", Source: "unknown tool: " + input.ToolName}
	}
}

func (d *ToolDispatcher) evaluateFile(input HookInput) Result {
	if input.ToolInput.FilePath == "" {
		return Result{Action: "ask", Source: "no file path"}
	}
	logDebug("File tool: %s path=%q", input.ToolName, input.ToolInput.FilePath)
	result := evaluateFileTool(d.chain, input.ToolName, input.ToolInput.FilePath)
	logDebug("File result: action=%q message=%q source=%q", result.Action, result.Message, result.Source)
	return result
}

func (d *ToolDispatcher) evaluateBash(input HookInput) Result {
	if input.ToolInput.Command == "" {
		return Result{Action: "ask", Source: "no command"}
	}
	logDebug("Input command: %q", input.ToolInput.Command)

	// Parse bash AST
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(input.ToolInput.Command), "")
	if err != nil {
		return Result{Action: "ask", Source: "parse error: " + err.Error()}
	}

	// Extract and evaluate
	info := ExtractFromFile(f)
	logDebugExtractedInfo(info)

	eval := NewEvaluator(d.chain)
	result := eval.Evaluate(info)
	logDebug("Result: action=%q message=%q command=%q source=%q",
		result.Action, result.Message, result.Command, result.Source)
	return result
}
