package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command represents an extracted command with its context.
type Command struct {
	Name         string       // command name (may contain $VAR for dynamic)
	Args         []string     // all arguments including command name
	IsDynamic    bool         // true if command name contains variables/substitutions
	PipesTo      []string     // commands this pipes to (immediate next in pipeline)
	PipesFrom    []string     // all commands upstream in the pipeline
	Stmt         *syntax.Stmt // original statement for redirect access
	ResolvedPath string       // absolute path to command (empty for builtins/unresolved)
	IsBuiltin    bool         // true if shell builtin (bypasses path resolution)
	EffectiveCwd string       // working directory this command would run in (after cd tracking)
}

// Redirect represents an extracted redirect operation.
type Redirect struct {
	Target       string // file path being redirected to
	Append       bool   // true if >> (append mode)
	IsDynamic    bool   // true if target contains variables
	IsFdRedirect bool   // true if redirecting to a file descriptor (e.g., 2>&1)
}

// Heredoc represents an extracted heredoc (<<EOF ... EOF) or here-string (<<<).
type Heredoc struct {
	Delimiter    string // the delimiter word (e.g., "EOF"); empty for here-strings
	Body         string // the heredoc/here-string content
	IsDynamic    bool   // true if body contains variable expansions (unquoted delimiter)
	IsHereString bool   // true if this is a here-string (<<<) rather than heredoc (<<)
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
	HasHeredocs     bool
	FuncDefs        []FuncDef
}

// ExtractedInfo holds all extracted information from an AST.
type ExtractedInfo struct {
	Commands   []Command
	Redirects  []Redirect
	Heredocs   []Heredoc
	Constructs Constructs
	ParseError error
}

// walkState tracks state during AST walking, particularly the effective
// working directory after cd commands.
type walkState struct {
	effectiveCwd string
}

// newWalkState creates a new walkState initialized with the current working directory.
func newWalkState() *walkState {
	cwd, _ := os.Getwd()
	return &walkState{effectiveCwd: cwd}
}

// resolveCdTarget returns the new working directory after a cd command.
// Returns empty string if the target cannot be statically determined.
func resolveCdTarget(args []string, currentCwd string) string {
	if len(args) <= 1 {
		// cd with no args goes to home
		return os.Getenv("HOME")
	}
	target := args[1] // args[0] is "cd" itself

	// Can't track dynamic args, -, or OLDPWD
	if strings.HasPrefix(target, "$") || target == "-" {
		return ""
	}

	// Handle ~ expansion
	if target == "~" || strings.HasPrefix(target, "~/") {
		home := os.Getenv("HOME")
		if target == "~" {
			return home
		}
		return filepath.Join(home, target[2:])
	}

	// Absolute path
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}

	// Relative path
	return filepath.Clean(filepath.Join(currentCwd, target))
}

// ExtractFromFile extracts all relevant information from a parsed file.
func ExtractFromFile(f *syntax.File) *ExtractedInfo {
	info := &ExtractedInfo{}
	state := newWalkState()

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
	// Propagate state through sequential statements (;-separated become separate Stmts)
	for _, stmt := range f.Stmts {
		state = extractFromStmt(stmt, info, nil, nil, state)
	}

	return info
}

// extractFromStmt processes a statement and extracts commands/redirects.
// pipeToContext: commands this statement pipes TO (downstream)
// pipeFromContext: commands this statement receives FROM (upstream)
// state: current walk state including effective working directory
// Returns the updated walk state after processing this statement.
func extractFromStmt(stmt *syntax.Stmt, info *ExtractedInfo, pipeToContext []string, pipeFromContext []string, state *walkState) *walkState {
	// Check for background execution
	if stmt.Background {
		info.Constructs.HasBackground = true
	}

	// Extract redirects and heredocs from the statement
	for _, redir := range stmt.Redirs {
		// Check if this is a heredoc (<<, <<-)
		if redir.Hdoc != nil {
			info.Constructs.HasHeredocs = true
			delimiter, _ := extractWord(redir.Word)
			body, isDynamic := extractWord(redir.Hdoc)
			info.Heredocs = append(info.Heredocs, Heredoc{
				Delimiter: delimiter,
				Body:      body,
				IsDynamic: isDynamic,
			})
			continue
		}

		// Check if this is a here-string (<<<)
		if redir.Op == syntax.WordHdoc {
			info.Constructs.HasHeredocs = true
			body, isDynamic := extractWord(redir.Word)
			info.Heredocs = append(info.Heredocs, Heredoc{
				Body:         body,
				IsDynamic:    isDynamic,
				IsHereString: true,
			})
			continue
		}

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
		return extractFromCmd(stmt.Cmd, info, pipeToContext, pipeFromContext, stmt, state)
	}
	return state
}

// extractFromCmd processes different command types.
// pipeToContext: commands this pipes TO (downstream)
// pipeFromContext: commands this receives FROM (upstream)
// state: current walk state including effective working directory
// Returns the updated walk state after processing this command.
func extractFromCmd(cmd syntax.Command, info *ExtractedInfo, pipeToContext []string, pipeFromContext []string, stmt *syntax.Stmt, state *walkState) *walkState {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) > 0 {
			name, isDynamic := extractWord(c.Args[0])
			args := make([]string, len(c.Args))
			for i, arg := range c.Args {
				args[i], _ = extractWord(arg)
			}
			info.Commands = append(info.Commands, Command{
				Name:         name,
				Args:         args,
				IsDynamic:    isDynamic,
				PipesTo:      pipeToContext,
				PipesFrom:    pipeFromContext,
				Stmt:         stmt,
				EffectiveCwd: state.effectiveCwd,
			})

			// Check if this is cd and update state for subsequent commands
			if name == "cd" {
				if newCwd := resolveCdTarget(args, state.effectiveCwd); newCwd != "" {
					return &walkState{effectiveCwd: newCwd}
				}
				// Can't determine new CWD, reset to empty (will use os.Getwd at eval time)
				return &walkState{effectiveCwd: ""}
			}
		}
		return state

	case *syntax.BinaryCmd:
		// Handle pipes
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			// Get commands on each side
			rightCmds := extractCommandNames(c.Y)
			leftCmds := extractCommandNames(c.X)

			// Left side: pipes to right side, receives from current upstream
			// Pipes don't propagate cd effects (concurrent execution)
			extractFromStmt(c.X, info, rightCmds, pipeFromContext, state)

			// Right side: pipes to outer context, receives from left + current upstream
			newFromContext := append([]string{}, pipeFromContext...)
			newFromContext = append(newFromContext, leftCmds...)
			extractFromStmt(c.Y, info, pipeToContext, newFromContext, state)
			return state
		} else if c.Op == syntax.AndStmt {
			// &&: propagate state from left to right (cd succeeded, next command runs)
			newState := extractFromStmt(c.X, info, pipeToContext, pipeFromContext, state)
			return extractFromStmt(c.Y, info, pipeToContext, pipeFromContext, newState)
		} else {
			// || (OrStmt): don't propagate state (right runs only if left fails)
			extractFromStmt(c.X, info, pipeToContext, pipeFromContext, state)
			extractFromStmt(c.Y, info, pipeToContext, pipeFromContext, state)
			return state
		}

	case *syntax.Subshell:
		// Subshell has isolated environment - cd changes don't propagate out
		subState := &walkState{effectiveCwd: state.effectiveCwd}
		for _, s := range c.Stmts {
			subState = extractFromStmt(s, info, pipeToContext, pipeFromContext, subState)
		}
		return state // Return original state, not subshell's modified state

	case *syntax.Block:
		// Block { ... } shares environment with parent
		blockState := state
		for _, s := range c.Stmts {
			blockState = extractFromStmt(s, info, pipeToContext, pipeFromContext, blockState)
		}
		return blockState

	case *syntax.IfClause:
		// Conditions and branches don't predictably affect CWD
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		for _, s := range c.Then {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		if c.Else != nil {
			extractFromCmd(c.Else, info, pipeToContext, pipeFromContext, stmt, state)
		}
		return state

	case *syntax.WhileClause:
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		return state

	case *syntax.ForClause:
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		return state

	case *syntax.CaseClause:
		for _, item := range c.Items {
			for _, s := range item.Stmts {
				extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
			}
		}
		return state

	case *syntax.ArithmCmd, *syntax.TestClause, *syntax.DeclClause, *syntax.LetClause:
		// These don't contain executable commands we need to check
		return state

	case *syntax.CoprocClause:
		if c.Stmt != nil {
			// Coprocess runs in background, doesn't affect our CWD
			extractFromStmt(c.Stmt, info, pipeToContext, pipeFromContext, state)
		}
		return state

	case *syntax.TimeClause:
		if c.Stmt != nil {
			return extractFromStmt(c.Stmt, info, pipeToContext, pipeFromContext, state)
		}
		return state
	}
	return state
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
