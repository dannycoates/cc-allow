package main

import (
	"path/filepath"
	"strings"
	"text/template"
)

// TemplateContext provides data for message template evaluation.
// Different rule types populate different fields - unpopulated fields are empty.
type TemplateContext struct {
	// Command context (populated for command rules)
	Command      string   // command name
	Args         []string // all arguments including command name
	ResolvedPath string   // absolute path to command binary
	Cwd          string   // effective working directory
	PipesTo      []string // commands this pipes to
	PipesFrom    []string // commands piped from

	// Redirect context (populated for redirect rules)
	Target string // redirect target path
	Append bool   // true if >> append mode

	// Heredoc context (populated for heredoc rules)
	Delimiter string // heredoc delimiter
	Body      string // heredoc content (truncated)

	// File context (populated for file rules)
	FilePath string // the file path being accessed
	Tool     string // "Read", "Write", or "Edit"

	// Environment context (always available when MatchContext is present)
	Home        string // $HOME directory
	ProjectRoot string // $PROJECT_ROOT
	PluginRoot  string // $CLAUDE_PLUGIN_ROOT (if set)
}

// ArgsStr returns args joined by space.
func (c TemplateContext) ArgsStr() string {
	return strings.Join(c.Args, " ")
}

// Arg returns the argument at position i (0-indexed, excluding command name).
// Returns empty string if index is out of bounds.
func (c TemplateContext) Arg(i int) string {
	// Args[0] is command name, so Arg(0) returns first real arg (Args[1])
	if i+1 < len(c.Args) {
		return c.Args[i+1]
	}
	return ""
}

// FileName returns the base name of FilePath.
func (c TemplateContext) FileName() string {
	if c.FilePath != "" {
		return filepath.Base(c.FilePath)
	}
	return ""
}

// FileDir returns the directory of FilePath.
func (c TemplateContext) FileDir() string {
	if c.FilePath != "" {
		return filepath.Dir(c.FilePath)
	}
	return ""
}

// TargetFileName returns the base name of redirect Target.
func (c TemplateContext) TargetFileName() string {
	if c.Target != "" {
		return filepath.Base(c.Target)
	}
	return ""
}

// TargetDir returns the directory of redirect Target.
func (c TemplateContext) TargetDir() string {
	if c.Target != "" {
		return filepath.Dir(c.Target)
	}
	return ""
}

// templateMessage evaluates a message as a Go text/template.
// Returns the raw message unchanged if it contains no template syntax
// or if template parsing/execution fails.
func templateMessage(rawMsg string, ctx TemplateContext) string {
	if rawMsg == "" || !strings.Contains(rawMsg, "{{") {
		return rawMsg
	}

	tmpl, err := template.New("msg").Parse(rawMsg)
	if err != nil {
		logDebug("template parse error in message %q: %v", rawMsg, err)
		return rawMsg
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, ctx); err != nil {
		logDebug("template execute error in message %q: %v", rawMsg, err)
		return rawMsg
	}

	return buf.String()
}

// newCommandTemplateContext creates a context from a Command and match context.
func newCommandTemplateContext(cmd Command, matchCtx *MatchContext) TemplateContext {
	ctx := TemplateContext{
		Command:      cmd.Name,
		Args:         cmd.Args,
		ResolvedPath: cmd.ResolvedPath,
		Cwd:          cmd.EffectiveCwd,
		PipesTo:      cmd.PipesTo,
		PipesFrom:    cmd.PipesFrom,
	}
	if matchCtx != nil && matchCtx.PathVars != nil {
		ctx.Home = matchCtx.PathVars.Home
		ctx.ProjectRoot = matchCtx.PathVars.ProjectRoot
		ctx.PluginRoot = matchCtx.PathVars.PluginRoot
	}
	return ctx
}

// newRedirectTemplateContext creates a context from a Redirect and match context.
func newRedirectTemplateContext(redir Redirect, matchCtx *MatchContext) TemplateContext {
	ctx := TemplateContext{
		Target: redir.Target,
		Append: redir.Append,
	}
	if matchCtx != nil && matchCtx.PathVars != nil {
		ctx.Home = matchCtx.PathVars.Home
		ctx.ProjectRoot = matchCtx.PathVars.ProjectRoot
		ctx.PluginRoot = matchCtx.PathVars.PluginRoot
	}
	return ctx
}

// newHeredocTemplateContext creates a context from a Heredoc and match context.
func newHeredocTemplateContext(hdoc Heredoc, matchCtx *MatchContext) TemplateContext {
	ctx := TemplateContext{
		Delimiter: hdoc.Delimiter,
		Body:      truncateString(hdoc.Body, 100),
	}
	if matchCtx != nil && matchCtx.PathVars != nil {
		ctx.Home = matchCtx.PathVars.Home
		ctx.ProjectRoot = matchCtx.PathVars.ProjectRoot
		ctx.PluginRoot = matchCtx.PathVars.PluginRoot
	}
	return ctx
}

// newFileTemplateContext creates a context for file tool evaluation.
func newFileTemplateContext(toolName, filePath string, matchCtx *MatchContext) TemplateContext {
	ctx := TemplateContext{
		Tool:     toolName,
		FilePath: filePath,
	}
	if matchCtx != nil && matchCtx.PathVars != nil {
		ctx.Home = matchCtx.PathVars.Home
		ctx.ProjectRoot = matchCtx.PathVars.ProjectRoot
		ctx.PluginRoot = matchCtx.PathVars.PluginRoot
	}
	return ctx
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
