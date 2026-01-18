package main

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command represents an extracted command with its context.
type Command struct {
	Name      string       // command name (may contain $VAR for dynamic)
	Args      []string     // all arguments including command name
	IsDynamic bool         // true if command name contains variables/substitutions
	PipesTo   []string     // commands this pipes to (immediate next in pipeline)
	PipesFrom []string     // all commands upstream in the pipeline
	Stmt      *syntax.Stmt // original statement for redirect access
}

// Redirect represents an extracted redirect operation.
type Redirect struct {
	Target     string // file path being redirected to
	Append     bool   // true if >> (append mode)
	IsDynamic  bool   // true if target contains variables
	IsFdRedirect bool // true if redirecting to a file descriptor (e.g., 2>&1)
}

// FuncDef represents a function definition.
type FuncDef struct {
	Name string
}

// BackgroundCmd represents a background command (&).
type BackgroundCmd struct {
	Command *Command
}

// Constructs holds all detected shell constructs.
type Constructs struct {
	HasFunctionDefs bool
	HasBackground   bool
	FuncDefs        []FuncDef
}

// ExtractedInfo holds all extracted information from an AST.
type ExtractedInfo struct {
	Commands   []Command
	Redirects  []Redirect
	Constructs Constructs
	ParseError error
}

// ExtractFromFile extracts all relevant information from a parsed file.
func ExtractFromFile(f *syntax.File) *ExtractedInfo {
	info := &ExtractedInfo{}

	// First pass: find function definitions
	syntax.Walk(f, func(node syntax.Node) bool {
		if fd, ok := node.(*syntax.FuncDecl); ok {
			info.Constructs.HasFunctionDefs = true
			info.Constructs.FuncDefs = append(info.Constructs.FuncDefs, FuncDef{
				Name: fd.Name.Value,
			})
		}
		return true
	})

	// Second pass: extract commands and their contexts
	for _, stmt := range f.Stmts {
		extractFromStmt(stmt, info, nil, nil)
	}

	return info
}

// extractFromStmt processes a statement and extracts commands/redirects.
// pipeToContext: commands this statement pipes TO (downstream)
// pipeFromContext: commands this statement receives FROM (upstream)
func extractFromStmt(stmt *syntax.Stmt, info *ExtractedInfo, pipeToContext []string, pipeFromContext []string) {
	// Check for background execution
	if stmt.Background {
		info.Constructs.HasBackground = true
	}

	// Extract redirects from the statement
	for _, redir := range stmt.Redirs {
		if redir.Word != nil {
			target, isDynamic := extractWord(redir.Word)
			// Check if this is a file descriptor redirect (>&N or N>&M)
			isFdRedirect := redir.Op == syntax.DplOut || redir.Op == syntax.DplIn
			info.Redirects = append(info.Redirects, Redirect{
				Target:       target,
				Append:       redir.Op == syntax.AppOut, // >> only
				IsDynamic:    isDynamic,
				IsFdRedirect: isFdRedirect,
			})
		}
	}

	// Process the command
	if stmt.Cmd != nil {
		extractFromCmd(stmt.Cmd, info, pipeToContext, pipeFromContext, stmt)
	}
}

// extractFromCmd processes different command types.
// pipeToContext: commands this pipes TO (downstream)
// pipeFromContext: commands this receives FROM (upstream)
func extractFromCmd(cmd syntax.Command, info *ExtractedInfo, pipeToContext []string, pipeFromContext []string, stmt *syntax.Stmt) {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) > 0 {
			name, isDynamic := extractWord(c.Args[0])
			args := make([]string, len(c.Args))
			for i, arg := range c.Args {
				args[i], _ = extractWord(arg)
			}
			info.Commands = append(info.Commands, Command{
				Name:      name,
				Args:      args,
				IsDynamic: isDynamic,
				PipesTo:   pipeToContext,
				PipesFrom: pipeFromContext,
				Stmt:      stmt,
			})
		}

	case *syntax.BinaryCmd:
		// Handle pipes
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			// Get commands on each side
			rightCmds := extractCommandNames(c.Y)
			leftCmds := extractCommandNames(c.X)

			// Left side: pipes to right side, receives from current upstream
			extractFromStmt(c.X, info, rightCmds, pipeFromContext)

			// Right side: pipes to outer context, receives from left + current upstream
			newFromContext := append([]string{}, pipeFromContext...)
			newFromContext = append(newFromContext, leftCmds...)
			extractFromStmt(c.Y, info, pipeToContext, newFromContext)
		} else {
			// && or || - both sides get same pipe context (no pipe relationship)
			extractFromStmt(c.X, info, pipeToContext, pipeFromContext)
			extractFromStmt(c.Y, info, pipeToContext, pipeFromContext)
		}

	case *syntax.Subshell:
		for _, s := range c.Stmts {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}

	case *syntax.Block:
		for _, s := range c.Stmts {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}

	case *syntax.IfClause:
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}
		for _, s := range c.Then {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}
		if c.Else != nil {
			extractFromCmd(c.Else, info, pipeToContext, pipeFromContext, stmt)
		}

	case *syntax.WhileClause:
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}

	case *syntax.ForClause:
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext)
		}

	case *syntax.CaseClause:
		for _, item := range c.Items {
			for _, s := range item.Stmts {
				extractFromStmt(s, info, pipeToContext, pipeFromContext)
			}
		}

	case *syntax.ArithmCmd, *syntax.TestClause, *syntax.DeclClause, *syntax.LetClause:
		// These don't contain executable commands we need to check

	case *syntax.CoprocClause:
		if c.Stmt != nil {
			extractFromStmt(c.Stmt, info, pipeToContext, pipeFromContext)
		}

	case *syntax.TimeClause:
		if c.Stmt != nil {
			extractFromStmt(c.Stmt, info, pipeToContext, pipeFromContext)
		}
	}
}

// extractCommandNames gets all command names from a statement (for pipe context).
func extractCommandNames(stmt *syntax.Stmt) []string {
	var names []string
	if stmt.Cmd != nil {
		switch c := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(c.Args) > 0 {
				name, _ := extractWord(c.Args[0])
				names = append(names, name)
			}
		case *syntax.BinaryCmd:
			if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
				names = append(names, extractCommandNames(c.X)...)
				names = append(names, extractCommandNames(c.Y)...)
			} else {
				names = append(names, extractCommandNames(c.X)...)
				names = append(names, extractCommandNames(c.Y)...)
			}
		}
	}
	return names
}

// extractWord converts a Word to a string and indicates if it's dynamic.
func extractWord(word *syntax.Word) (string, bool) {
	var parts []string
	isDynamic := false

	for _, part := range word.Parts {
		s, dyn := extractWordPart(part)
		parts = append(parts, s)
		if dyn {
			isDynamic = true
		}
	}
	return strings.Join(parts, ""), isDynamic
}

// extractWordPart handles individual word parts.
func extractWordPart(part syntax.WordPart) (string, bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value, false
	case *syntax.SglQuoted:
		return p.Value, false
	case *syntax.DblQuoted:
		return extractDblQuoted(p)
	case *syntax.ParamExp:
		if p.Param != nil {
			return "$" + p.Param.Value, true
		}
		return "$?", true
	case *syntax.CmdSubst:
		return "$(…)", true
	case *syntax.ArithmExp:
		return "$((…))", true
	case *syntax.ProcSubst:
		if p.Op == syntax.CmdIn {
			return "<(…)", true
		}
		return ">(…)", true
	case *syntax.ExtGlob:
		return fmt.Sprintf("%c(%s)", p.Op, p.Pattern.Value), false
	case *syntax.BraceExp:
		// Brace expansion like {a,b,c}
		var parts []string
		for _, elem := range p.Elems {
			s, _ := extractWord(elem)
			parts = append(parts, s)
		}
		return "{" + strings.Join(parts, ",") + "}", false
	default:
		return fmt.Sprintf("<%T>", p), true
	}
}

// extractDblQuoted handles double-quoted strings.
func extractDblQuoted(dq *syntax.DblQuoted) (string, bool) {
	var parts []string
	isDynamic := false

	for _, part := range dq.Parts {
		s, dyn := extractWordPart(part)
		parts = append(parts, s)
		if dyn {
			isDynamic = true
		}
	}
	return strings.Join(parts, ""), isDynamic
}
