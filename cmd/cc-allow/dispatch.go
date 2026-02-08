package main

import (
	"os"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HookInput represents the JSON input from Claude Code hooks
type HookInput struct {
	SessionID string `json:"session_id"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`   // Bash tool
		FilePath string `json:"file_path"` // Read, Edit, Write tools
		URL      string `json:"url"`       // WebFetch tool
		Prompt   string `json:"prompt"`    // WebFetch tool
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
	case "WebFetch":
		return d.evaluateWebFetch(input)
	case "Bash", "":
		return d.evaluateBash(input)
	default:
		return Result{Action: ActionAsk, Source: "unknown tool: " + input.ToolName}
	}
}

func (d *ToolDispatcher) evaluateFile(input HookInput) Result {
	if input.ToolInput.FilePath == "" {
		return Result{Action: ActionAsk, Source: "no file path"}
	}
	eval := NewEvaluator(d.chain)
	return eval.evaluateFileTool(input.ToolName, input.ToolInput.FilePath)
}

func (d *ToolDispatcher) evaluateWebFetch(input HookInput) Result {
	if input.ToolInput.URL == "" {
		return Result{Action: ActionAsk, Source: "no URL"}
	}
	eval := NewEvaluator(d.chain)
	return eval.evaluateWebFetchTool(input.ToolInput.URL)
}

func (d *ToolDispatcher) evaluateBash(input HookInput) Result {
	if input.ToolInput.Command == "" {
		return Result{Action: ActionAsk, Source: "no command"}
	}
	// Parse bash AST
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(input.ToolInput.Command), "")
	if err != nil {
		return Result{Action: ActionAsk, Source: "parse error: " + err.Error()}
	}

	// Extract and evaluate
	cwd, _ := os.Getwd()
	info := ExtractFromFile(f, cwd)
	logDebugExtractedInfo(info)

	eval := NewEvaluator(d.chain)
	return eval.Evaluate(info)
}
