package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	IsInput      bool   // true if input redirect (<), false if output (>, >>)
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

// defaultIFS is bash's word-splitting set when IFS is unset.
const defaultIFS = " \t\n"

// foldEnv is the resolution context threaded through word extraction: the
// statically-known variable values plus the current word-splitting (IFS) state.
type foldEnv struct {
	// vars holds variables whose value cc-allow can prove statically — assigned
	// a pure string literal (possibly built from other known vars) earlier in
	// the same command list. Variables assigned from command substitutions, other
	// dynamic sources, or via inline command env are deliberately absent.
	vars map[string]string
	// ifs is the active word-splitting character set for UNQUOTED expansions.
	ifs string
	// ifsKnown is false when IFS was set to a value cc-allow cannot prove; then
	// no unquoted fold is safe because the splitting behaviour is unknown.
	ifsKnown bool
}

// walkState tracks state during AST walking: the effective working directory
// after cd commands, statically-known variable values, the IFS state, and the
// set of user-defined function names (functions can rebind any variable).
type walkState struct {
	effectiveCwd string
	vars         map[string]string
	ifs          string
	ifsKnown     bool
	funcNames    map[string]bool
}

// newWalkState creates a new walkState initialized with the given working directory.
func newWalkState(cwd string) *walkState {
	return &walkState{effectiveCwd: cwd, vars: map[string]string{}, ifs: defaultIFS, ifsKnown: true}
}

// env returns the resolution context for word extraction.
func (s *walkState) env() *foldEnv {
	return &foldEnv{vars: s.vars, ifs: s.ifs, ifsKnown: s.ifsKnown}
}

func (s *walkState) copy(vars map[string]string) *walkState {
	return &walkState{effectiveCwd: s.effectiveCwd, vars: vars, ifs: s.ifs, ifsKnown: s.ifsKnown, funcNames: s.funcNames}
}

// withCwd returns a copy with the effective working directory updated.
func (s *walkState) withCwd(cwd string) *walkState {
	next := s.copy(s.vars)
	next.effectiveCwd = cwd
	return next
}

// withNoVars returns a copy with ALL folds forgotten and IFS marked unknown.
// Used after an arbitrary mutator — eval, source/. , or a user-function call —
// which can reassign any variable (including IFS) to any value. Conservative:
// only ever loses folds, never grants one.
func (s *walkState) withNoVars() *walkState {
	if len(s.vars) == 0 && !s.ifsKnown {
		return s
	}
	next := s.copy(map[string]string{})
	next.ifsKnown = false
	return next
}

// isArbitraryMutator reports whether a command can rebind arbitrary variables in
// the current shell: eval, source/. , or a call to a user-defined function.
func (s *walkState) isArbitraryMutator(name string) bool {
	switch name {
	case "eval", "source", ".":
		return true
	}
	return s.funcNames[name]
}

// withVar returns a copy of the walk state with an additional known variable.
// The vars map is copied so sibling branches of the walk never alias each other.
func (s *walkState) withVar(name, value string) *walkState {
	next := make(map[string]string, len(s.vars)+1)
	for k, v := range s.vars {
		next[k] = v
	}
	next[name] = value
	return s.copy(next)
}

// withoutVar returns a copy of the walk state with a variable forgotten. Used
// to INVALIDATE a previously-folded value whenever the walker can no longer
// prove the variable still holds its literal (reassigned to a non-provable
// value, appended to, unset, or written by a builtin/loop/branch the walker does
// not model). Forgetting only ever loses a fold — reverting the later $VAR to
// the safe dynamic-prompt path — and never grants one.
func (s *walkState) withoutVar(name string) *walkState {
	if _, ok := s.vars[name]; !ok {
		return s
	}
	next := make(map[string]string, len(s.vars))
	for k, v := range s.vars {
		if k != name {
			next[k] = v
		}
	}
	return s.copy(next)
}

// withIFS returns a copy of the walk state with the word-splitting state updated
// after an `IFS=...` assignment. value/known come from staticAssign: a provable
// literal sets the splitting set; an unprovable value makes folding unquoted
// expansions unsafe until IFS is set again.
func (s *walkState) withIFS(value string, known bool) *walkState {
	next := s.copy(s.vars)
	next.ifsKnown = known
	if known {
		next.ifs = value
	}
	return next
}

// identRe matches a plain shell variable name.
var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// nameTargetRe matches a read/mapfile NAME target, capturing the bare variable
// from a plain name or an array-element subscript (arr[0] writes scalar arr).
var nameTargetRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\[.*\])?$`)

// readFlagsWithArg are read/mapfile option flags that consume the NEXT token,
// which must not be mistaken for a target name (e.g. `read -d Z`).
var readFlagsWithArg = map[string]bool{
	"-u": true, "-t": true, "-p": true, "-n": true, "-d": true,
	"-N": true, "-i": true, "-c": true, "-C": true,
}

// unwrapBuiltinPrefix strips a leading run of `command`/`builtin` (and their
// option flags) from a command's args, returning the underlying command's name
// and args plus whether user functions still apply (they do NOT behind a
// command/builtin prefix). This is where wrappers like `builtin printf -v D` or
// `command read D` get unmasked so their variable writes are still seen.
func unwrapBuiltinPrefix(args []string) (name string, rest []string, allowFunc bool) {
	allowFunc = true
	i := 0
	for i < len(args) && (args[i] == "command" || args[i] == "builtin") {
		allowFunc = false
		i++
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			i++ // skip command/builtin's own flags (-p, -v, -V)
		}
	}
	if i >= len(args) {
		return "", nil, allowFunc
	}
	return args[i], args[i:], allowFunc
}

// builtinAssignTargets returns the variable names a known variable-writing
// builtin assigns, given the command's args (args[0] is the builtin name). It
// errs toward over-collection (an extra name only loses a fold). Returns nil for
// commands that don't write variables.
func builtinAssignTargets(name string, args []string) []string {
	switch name {
	case "read", "mapfile", "readarray":
		var t []string
		for i := 1; i < len(args); i++ {
			a := args[i]
			if a == "--" {
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				if readFlagsWithArg[a] {
					i++ // also skip the token this flag consumes
				}
				continue
			}
			if m := nameTargetRe.FindStringSubmatch(a); m != nil {
				t = append(t, m[1]) // bare name from NAME or NAME[subscript]
			}
		}
		if len(t) == 0 {
			if name == "read" {
				return []string{"REPLY"}
			}
			return []string{"MAPFILE"}
		}
		return t
	case "printf":
		for i := 1; i < len(args); i++ {
			var target string
			if args[i] == "-v" && i+1 < len(args) {
				target = args[i+1]
			} else if strings.HasPrefix(args[i], "-v") && len(args[i]) > 2 {
				target = args[i][2:]
			}
			if target != "" {
				if m := nameTargetRe.FindStringSubmatch(target); m != nil {
					return []string{m[1]} // bare name from NAME or NAME[subscript]
				}
				return nil
			}
		}
		return nil
	case "getopts":
		// getopts optstring NAME [args...]
		if len(args) >= 3 && identRe.MatchString(args[2]) {
			return []string{args[2], "OPTARG", "OPTIND"}
		}
		return []string{"OPTARG", "OPTIND"}
	}
	return nil
}

// trapInstallsHandler reports whether a `trap` invocation installs a non-trivial
// handler (which may rebind any variable). args[0] is "trap". It skips a leading
// run of option flags and a single `--` terminator before reading the handler;
// a reset (`trap -`, `trap ''`) or an options-only form installs nothing.
func trapInstallsHandler(args []string) bool {
	i := 1
	for i < len(args) {
		if args[i] == "--" {
			i++ // terminator: the next word is the handler, verbatim
			break
		}
		if strings.HasPrefix(args[i], "-") && args[i] != "-" {
			i++ // an option flag (-p, -l, ...)
			continue
		}
		break
	}
	if i >= len(args) {
		return false
	}
	act := args[i]
	return act != "" && act != "-"
}

// sliceWriteNames returns the variable names assigned as a side effect of a
// substring-slice expansion offset/length (`${v:D=2}`), plus opaque=true when a
// non-numeric slice expression may assign a variable the names can't be read
// from. mvdan stores the slice expression as raw literal text, so it is scanned
// rather than walked as arithmetic.
func sliceWriteNames(p *syntax.ParamExp) (names []string, opaque bool) {
	if p.Slice == nil {
		return nil, false
	}
	var text string
	for _, e := range []syntax.ArithmExpr{p.Slice.Offset, p.Slice.Length} {
		if e == nil {
			continue
		}
		syntax.Walk(e, func(n syntax.Node) bool {
			if lit, ok := n.(*syntax.Lit); ok {
				text += lit.Value + " "
			}
			return true
		})
	}
	for _, m := range sliceAssignRe.FindAllStringSubmatch(text, -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 && text != "" && !sliceNumericRe.MatchString(text) {
		opaque = true // a non-numeric slice expr that might assign — forget all
	}
	return names, opaque
}

// sliceAssignRe matches `NAME=` / `NAME+=` / ... / `NAME++` inside slice text,
// excluding the comparison `NAME==`.
var sliceAssignRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--|(?:[-+*/%&|^]|<<|>>)?=[^=])`)

// sliceNumericRe matches a purely numeric/operator slice expression (no names).
var sliceNumericRe = regexp.MustCompile(`^[0-9 +\-*/%()]*$`)

// declClauseIsNameref reports whether a declare/local/typeset clause has the -n
// (nameref) flag — the assigned name then aliases another variable, so its value
// cannot be tracked.
func declClauseIsNameref(d *syntax.DeclClause) bool {
	for _, as := range d.Args {
		if as.Naked && as.Value != nil {
			if v, _ := extractWord(as.Value, nil); strings.HasPrefix(v, "-") && strings.Contains(v, "n") {
				return true
			}
		}
	}
	return false
}

// arithmName returns the variable name of an arithmetic operand that is a bare
// identifier (the LHS of an arithmetic assignment/increment), or "".
func arithmName(e syntax.ArithmExpr) string {
	if w, ok := e.(*syntax.Word); ok {
		if s, dyn := extractWord(w, nil); !dyn && identRe.MatchString(s) {
			return s
		}
	}
	return ""
}

// isArithmAssign reports whether an arithmetic binary operator writes its LHS.
func isArithmAssign(op syntax.BinAritOperator) bool {
	switch op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn,
		syntax.QuoAssgn, syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn,
		syntax.XorAssgn, syntax.ShlAssgn, syntax.ShrAssgn:
		return true
	}
	return false
}

// isParamAssign reports whether a parameter expansion assigns its variable as a
// side effect: ${var=word} (AssignUnset) and ${var:=word} (AssignUnsetOrNull).
func isParamAssign(p *syntax.ParamExp) bool {
	return p.Param != nil && p.Exp != nil &&
		(p.Exp.Op == syntax.AssignUnset || p.Exp.Op == syntax.AssignUnsetOrNull)
}

// namesAssignedIn collects every variable name that may be written anywhere in
// node — covering ALL the ways bash mutates a variable: plain/declare
// assignments, loop iterators (for/select), arithmetic assignment and ++/--
// targets, the ${var:=} use-site assignment, and the variable-writing builtins
// (read, mapfile, printf -v, getopts, unset). It also returns wildcard=true when
// node contains an ARBITRARY mutator — eval, source/. , or a user-function call
// — which can rebind any variable. Subshell and process-substitution subtrees
// are pruned (their assignments cannot leak out). Inline-env assignments
// (`FOO=bar cmd`) are excluded — they don't persist. env resolves a command word
// that is itself a folded variable; funcNames identifies user functions.
func namesAssignedIn(node syntax.Node, env *foldEnv, funcNames map[string]bool) (map[string]struct{}, bool) {
	names := map[string]struct{}{}
	wildcard := false
	var walk func(n syntax.Node) bool
	walk = func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Subshell:
			return false // isolated environment — assignments don't leak out
		case *syntax.ProcSubst:
			return false // runs in a subshell
		case *syntax.CmdSubst:
			return false // $(...) runs in a subshell — assignments don't leak out
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				// Pure assignment statement — every assign persists.
				for _, as := range x.Assigns {
					if as.Name != nil {
						names[as.Name.Value] = struct{}{}
					}
				}
			} else {
				args := make([]string, len(x.Args))
				for i, a := range x.Args {
					args[i], _ = extractWord(a, env)
				}
				if oname, dyn := extractWord(x.Args[0], env); !dyn {
					// A user function (even one named command/builtin, which
					// shadows the builtin) can rebind anything.
					if funcNames[oname] {
						wildcard = true
					}
					// Unmask a command/builtin prefix so wrapped mutators are seen.
					nm, uargs, _ := unwrapBuiltinPrefix(args)
					if nm == "eval" || nm == "source" || nm == "." ||
						(nm == "trap" && trapInstallsHandler(uargs)) {
						wildcard = true
					}
					if nm == "unset" {
						for _, a := range uargs[1:] {
							if a != "" && !strings.HasPrefix(a, "-") {
								names[a] = struct{}{}
							}
						}
					}
					for _, t := range builtinAssignTargets(nm, uargs) {
						names[t] = struct{}{}
					}
				}
			}
		case *syntax.DeclClause:
			if declClauseIsNameref(x) {
				wildcard = true // nameref aliases an untrackable variable
			}
			for _, as := range x.Args {
				if as.Name != nil {
					names[as.Name.Value] = struct{}{}
				}
			}
		case *syntax.WordIter:
			if x.Name != nil {
				names[x.Name.Value] = struct{}{} // for X in ... / select X in ...
			}
		case *syntax.ParamExp:
			if isParamAssign(x) {
				if x.Excl {
					wildcard = true // ${!ref:=} assigns an indirectly-named var
				} else {
					names[x.Param.Value] = struct{}{} // ${var:=word}
				}
			}
			if sn, op := sliceWriteNames(x); op {
				wildcard = true // ${v:EXPR} writes an unreadable target
			} else {
				for _, n := range sn {
					names[n] = struct{}{} // ${v:D=2}
				}
			}
		case *syntax.BinaryArithm:
			if isArithmAssign(x.Op) {
				if nm := arithmName(x.X); nm != "" {
					names[nm] = struct{}{}
				}
			}
		case *syntax.UnaryArithm:
			if x.Op == syntax.Inc || x.Op == syntax.Dec {
				if nm := arithmName(x.X); nm != "" {
					names[nm] = struct{}{}
				}
			}
		}
		return true
	}
	syntax.Walk(node, walk)
	return names, wildcard
}

// invalidateAssignedNames returns a state copy with every variable that may be
// written anywhere inside node forgotten (all vars, if node holds an arbitrary
// mutator). Used for constructs whose runtime reachability the walker does not
// model (if/while/for/case bodies, the conditional operand of &&/||): in real
// bash an assignment there may leak to the enclosing shell, but only maybe, so
// the safe move is to forget the variable rather than trust a stale fold.
func invalidateAssignedNames(state *walkState, node syntax.Node) *walkState {
	if node == nil {
		return state
	}
	names, wildcard := namesAssignedIn(node, state.env(), state.funcNames)
	if wildcard {
		return state.withNoVars()
	}
	for nm := range names {
		state = state.withoutVar(nm)
		if nm == "IFS" {
			state = state.withIFS("", false) // a non-literal IFS write — splitting unknown
		}
	}
	return state
}

// usesiteAssignedNames collects only the assignments that happen as a side
// effect of EXPANDING a word — ${var:=word} and arithmetic ((var=...)) inside
// $((...)). These persist to later statements but are not handled by the command
// handlers (which see only top-level assignments/builtins), so the linear walk
// invalidates them after each statement. Subshell/process-sub subtrees pruned.
func usesiteAssignedNames(node syntax.Node) (map[string]struct{}, bool) {
	names := map[string]struct{}{}
	wildcard := false
	syntax.Walk(node, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Subshell, *syntax.ProcSubst, *syntax.CmdSubst:
			return false // run in a subshell — side effects don't leak out
		case *syntax.ParamExp:
			if isParamAssign(x) {
				if x.Excl {
					wildcard = true
				} else {
					names[x.Param.Value] = struct{}{}
				}
			}
			if sn, op := sliceWriteNames(x); op {
				wildcard = true
			} else {
				for _, nm := range sn {
					names[nm] = struct{}{}
				}
			}
		case *syntax.BinaryArithm:
			if isArithmAssign(x.Op) {
				if nm := arithmName(x.X); nm != "" {
					names[nm] = struct{}{}
				}
			}
		case *syntax.UnaryArithm:
			if x.Op == syntax.Inc || x.Op == syntax.Dec {
				if nm := arithmName(x.X); nm != "" {
					names[nm] = struct{}{}
				}
			}
		}
		return true
	})
	return names, wildcard
}

// arithmIsOpaque reports whether an arithmetic command/let contains an operand
// the static LHS extraction can't read (a quoted or substituted expression like
// `let "D=8"`), meaning it may assign a variable we cannot name — forget all.
func arithmIsOpaque(node syntax.Node) bool {
	opaque := false
	syntax.Walk(node, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.DblQuoted, *syntax.SglQuoted, *syntax.CmdSubst:
			opaque = true
		}
		return !opaque
	})
	return opaque
}

// applyAssigns records or invalidates each scalar assignment from a pure
// assignment statement or a declare/export/readonly/typeset clause, and keeps
// the IFS word-splitting state in sync.
func applyAssigns(state *walkState, assigns []*syntax.Assign) *walkState {
	for _, as := range assigns {
		if name, val, ok := staticAssign(as, state.env()); ok {
			state = state.withVar(name, val)
			if name == "IFS" {
				state = state.withIFS(val, true)
			}
		} else if as.Name != nil {
			state = state.withoutVar(as.Name.Value)
			if as.Name.Value == "IFS" {
				state = state.withIFS("", false)
			}
		}
	}
	return state
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
// cwd is the working directory used to resolve relative paths in cd commands.
func ExtractFromFile(f *syntax.File, cwd string) *ExtractedInfo {
	info := &ExtractedInfo{}
	state := newWalkState(cwd)

	// First pass: find function definitions. Their names are recorded on the
	// state so that calling a user function — which can rebind any variable —
	// forgets all folds.
	funcNames := map[string]bool{}
	syntax.Walk(f, func(node syntax.Node) bool {
		if fd, ok := node.(*syntax.FuncDecl); ok {
			info.Constructs.HasFunctionDefs = true
			info.Constructs.FuncDefs = append(info.Constructs.FuncDefs, FuncDef{
				Name: fd.Name.Value,
			})
			funcNames[fd.Name.Value] = true
		}
		return true
	})
	state.funcNames = funcNames

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

	// A use-site assignment (${var:=word}, $((var=...))) in this statement's
	// words takes effect DURING command-word expansion — before the redirect and
	// later words are expanded — so drop those folds before extracting any word
	// of THIS statement, and let the drop propagate to later statements too.
	stmtState := state
	if usenames, usewild := usesiteAssignedNames(stmt); usewild {
		stmtState = stmtState.withNoVars()
	} else {
		for nm := range usenames {
			stmtState = stmtState.withoutVar(nm)
			if nm == "IFS" {
				stmtState = stmtState.withIFS("", false) // splitting now unknown
			}
		}
	}

	// Extract redirects and heredocs from the statement
	for _, redir := range stmt.Redirs {
		// Check if this is a heredoc (<<, <<-)
		if redir.Hdoc != nil {
			info.Constructs.HasHeredocs = true
			delimiter, _ := extractWord(redir.Word, stmtState.env())
			body, isDynamic := extractWord(redir.Hdoc, stmtState.env())
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
			body, isDynamic := extractWord(redir.Word, stmtState.env())
			info.Heredocs = append(info.Heredocs, Heredoc{
				Body:         body,
				IsDynamic:    isDynamic,
				IsHereString: true,
			})
			continue
		}

		if redir.Word != nil {
			target, isDynamic := extractWord(redir.Word, stmtState.env())
			// Check if this is a file descriptor redirect (>&N or N>&M)
			isFdRedirect := redir.Op == syntax.DplOut || redir.Op == syntax.DplIn
			// Check if this is an input redirect (<)
			isInput := redir.Op == syntax.RdrIn || redir.Op == syntax.RdrInOut
			info.Redirects = append(info.Redirects, Redirect{
				Target:       target,
				Append:       redir.Op == syntax.AppOut, // >> only
				IsDynamic:    isDynamic,
				IsFdRedirect: isFdRedirect,
				IsInput:      isInput,
			})
		}
	}

	// Process the command using the per-statement state (use-site folds already
	// dropped, which also propagates to later statements via the return).
	if stmt.Cmd != nil {
		next := extractFromCmd(stmt.Cmd, info, pipeToContext, pipeFromContext, stmt, stmtState)
		if stmt.Background {
			// `cmd &` runs in a background subshell; its assignments and cd do
			// not affect the foreground shell, so keep the incoming state.
			return state
		}
		return next
	}
	return stmtState
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
			name, isDynamic := extractWord(c.Args[0], state.env())
			args := make([]string, len(c.Args))
			for i, arg := range c.Args {
				args[i], _ = extractWord(arg, state.env())
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

			// A user function (even one named command/builtin, which shadows the
			// builtin) can rebind any variable — forget every fold.
			if state.funcNames[name] {
				return state.withNoVars()
			}
			// Unmask a `command`/`builtin` prefix so a wrapped variable-writer or
			// mutator is still recognized. Functions are bypassed by the prefix.
			uname, uargs, _ := unwrapBuiltinPrefix(args)

			// eval / source / . / a trap that installs a handler can rebind any
			// variable (including IFS) — forget every fold.
			if uname == "eval" || uname == "source" || uname == "." ||
				(uname == "trap" && trapInstallsHandler(uargs)) {
				return state.withNoVars()
			}
			// Check if this is cd and update state for subsequent commands
			if uname == "cd" {
				newCwd := resolveCdTarget(uargs, state.effectiveCwd)
				// newCwd may be "" (undeterminable); eval falls back to os.Getwd.
				return state.withCwd(newCwd)
			}
			// `unset NAME...` removes variables — forget any folded values.
			if uname == "unset" {
				for _, a := range uargs[1:] {
					if a == "" || strings.HasPrefix(a, "-") {
						continue
					}
					state = state.withoutVar(a)
					if a == "IFS" {
						state = state.withIFS(defaultIFS, true)
					}
				}
				return state
			}
			// Variable-writing builtins (read, printf -v, mapfile, getopts) set a
			// variable from runtime input — forget any folded value for the target.
			// A non-literal write to IFS makes the word-splitting state unknown.
			for _, t := range builtinAssignTargets(uname, uargs) {
				state = state.withoutVar(t)
				if t == "IFS" {
					state = state.withIFS("", false)
				}
			}
			// Inline env assignments (FOO=bar cmd) apply only to this command's
			// environment and do not persist to later statements — ignore them.
			return state
		}
		// A pure assignment statement (e.g. SKILL=/path) has no command word.
		// Record statically-known literal values so later $VAR command names and
		// redirect targets can be constant-folded; INVALIDATE the variable on any
		// assignment whose value cannot be proven (command substitution, unknown
		// var, += append, tilde) so a stale fold can never survive a reassignment.
		state = applyAssigns(state, c.Assigns)
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
		}
		// && / || : the LEFT operand runs when this node is reached, so record
		// its assignments; the RIGHT operand is CONDITIONAL (runs only if the
		// left succeeds for &&, fails for ||), so extract its commands/redirects
		// for checking but forget any variable it assigns — folding a value that
		// may never be assigned is the false&&D=/safe bypass.
		newState := extractFromStmt(c.X, info, pipeToContext, pipeFromContext, state)
		extractFromStmt(c.Y, info, pipeToContext, pipeFromContext, newState)
		return invalidateAssignedNames(newState, c.Y)

	case *syntax.Subshell:
		// Subshell has an isolated environment: it can READ the parent's known
		// vars (so folds inside it work) but its assignments/cd do not leak out.
		// copy-on-write withVar/withoutVar protect the parent's map.
		subState := state.copy(state.vars)
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
		// Conditions and branches don't predictably affect CWD, and any variable
		// they reassign may or may not take effect at runtime — forget those so a
		// stale fold cannot survive (e.g. D=/safe; if c; then D=/etc; fi).
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		for _, s := range c.Then {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		if c.Else != nil {
			extractFromCmd(c.Else, info, pipeToContext, pipeFromContext, stmt, state)
		}
		return invalidateAssignedNames(state, c)

	case *syntax.WhileClause:
		for _, s := range c.Cond {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		return invalidateAssignedNames(state, c)

	case *syntax.ForClause:
		for _, s := range c.Do {
			extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
		}
		return invalidateAssignedNames(state, c)

	case *syntax.CaseClause:
		for _, item := range c.Items {
			for _, s := range item.Stmts {
				extractFromStmt(s, info, pipeToContext, pipeFromContext, state)
			}
		}
		return invalidateAssignedNames(state, c)

	case *syntax.DeclClause:
		// declare/export/readonly/typeset/local NAME=val persist a variable, so
		// record or invalidate the fold exactly like a pure assignment. A `-n`
		// nameref aliases an untrackable target, so forget everything.
		if declClauseIsNameref(c) {
			return state.withNoVars()
		}
		return applyAssigns(state, c.Args)

	case *syntax.ArithmCmd, *syntax.LetClause:
		// (( D=... )) and `let D=...` write their assignment targets — forget any
		// folded value so a numeric (or any) reassignment cannot leave a stale
		// fold. A quoted/substituted expression (let "D=8") is opaque to static
		// LHS extraction, so forget everything.
		if arithmIsOpaque(cmd) {
			return state.withNoVars()
		}
		return invalidateAssignedNames(state, cmd)

	case *syntax.TestClause:
		// [[ ... ]] evaluates conditions; no variables assigned, no commands to check.
		return state

	case *syntax.CoprocClause:
		if c.Stmt != nil {
			// Coprocess runs in background, doesn't affect our CWD
			extractFromStmt(c.Stmt, info, pipeToContext, pipeFromContext, state)
		}
		// `coproc NAME { ... }` binds NAME and NAME_PID; an unnamed coproc binds
		// COPROC and COPROC_PID. Forget those folds.
		base := "COPROC"
		if c.Name != nil {
			if nm, dyn := extractWord(c.Name, nil); !dyn && nm != "" {
				base = nm
			}
		}
		state = state.withoutVar(base).withoutVar(base + "_PID")
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
	if stmt.Cmd != nil {
		return extractCommandNamesFromCmd(stmt.Cmd)
	}
	return nil
}

// extractCommandNamesFromCmd extracts command names from any command type.
// This is needed for proper pipe context tracking across compound commands
// like subshells, blocks, if/while/for/case clauses, etc.
func extractCommandNamesFromCmd(cmd syntax.Command) []string {
	var names []string
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) > 0 {
			name, _ := extractWord(c.Args[0], nil)
			names = append(names, name)
		}
	case *syntax.BinaryCmd:
		names = append(names, extractCommandNames(c.X)...)
		names = append(names, extractCommandNames(c.Y)...)
	case *syntax.Subshell:
		for _, s := range c.Stmts {
			names = append(names, extractCommandNames(s)...)
		}
	case *syntax.Block:
		for _, s := range c.Stmts {
			names = append(names, extractCommandNames(s)...)
		}
	case *syntax.IfClause:
		// Only extract from then/else blocks, not conditions.
		// Condition commands don't produce output to the pipe.
		for _, s := range c.Then {
			names = append(names, extractCommandNames(s)...)
		}
		if c.Else != nil {
			names = append(names, extractCommandNamesFromCmd(c.Else)...)
		}
	case *syntax.WhileClause:
		// Only extract from do block, not condition.
		// Condition commands don't produce output to the pipe.
		for _, s := range c.Do {
			names = append(names, extractCommandNames(s)...)
		}
	case *syntax.ForClause:
		for _, s := range c.Do {
			names = append(names, extractCommandNames(s)...)
		}
	case *syntax.CaseClause:
		for _, item := range c.Items {
			for _, s := range item.Stmts {
				names = append(names, extractCommandNames(s)...)
			}
		}
	case *syntax.TimeClause:
		if c.Stmt != nil {
			names = append(names, extractCommandNames(c.Stmt)...)
		}
	case *syntax.CoprocClause:
		if c.Stmt != nil {
			names = append(names, extractCommandNames(c.Stmt)...)
		}
	}
	return names
}

// staticAssign returns the name and statically-resolved value of an assignment
// when it is a plain scalar assignment to a value cc-allow can prove (a literal,
// possibly built from already-known vars). It returns ok=false for array
// assignments, appends (+=), naked declarations, indexed assignments, values
// containing command substitutions or unknown variables, or values bash would
// tilde-expand (the parser keeps ~ literal, so the stored value would diverge).
func staticAssign(as *syntax.Assign, env *foldEnv) (string, string, bool) {
	if as == nil || as.Name == nil || as.Append || as.Naked || as.Index != nil || as.Array != nil {
		return "", "", false
	}
	if as.Value == nil {
		// Bare `FOO=` assigns the empty string.
		return as.Name.Value, "", true
	}
	val, isDynamic := extractWord(as.Value, env)
	if isDynamic || valueTildeExpands(as.Value, val) {
		return "", "", false
	}
	return as.Name.Value, val, true
}

// valueTildeExpands reports whether bash would tilde-expand this assignment
// value (so the parser's literal ~ would diverge from the runtime value): an
// UNQUOTED leading tilde, or an unquoted `:~` (PATH-style). A quoted "~..."
// keeps the tilde literal and is safe.
func valueTildeExpands(w *syntax.Word, val string) bool {
	if len(w.Parts) > 0 {
		if lit, ok := w.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(lit.Value, "~") {
			return true
		}
	}
	return strings.Contains(val, ":~")
}

// extractWord converts a Word to a string and indicates if it's dynamic.
// env supplies statically-known variable values and IFS state for constant
// folding; pass nil when no resolution context is available. Word parts here are
// in unquoted context (a DblQuoted part switches to quoted context internally).
func extractWord(word *syntax.Word, env *foldEnv) (string, bool) {
	var parts []string
	isDynamic := false

	for _, part := range word.Parts {
		s, dyn := extractWordPart(part, env, false)
		parts = append(parts, s)
		if dyn {
			isDynamic = true
		}
	}
	return strings.Join(parts, ""), isDynamic
}

// isPlainParam reports whether a parameter expansion is a simple $VAR / ${VAR}
// with no modifiers (no ${VAR:-x}, ${#VAR}, ${VAR[i]}, ${VAR/a/b}, etc.). Only
// plain expansions are safe to constant-fold to a known value.
func isPlainParam(p *syntax.ParamExp) bool {
	return p.Param != nil &&
		!p.Excl && !p.Length && !p.Width &&
		p.Index == nil && p.Slice == nil && p.Repl == nil &&
		p.Exp == nil && p.Names == 0
}

// foldableUnquoted reports whether a known value is safe to substitute for an
// UNQUOTED $VAR. Outside double quotes bash applies word-splitting (on the
// current IFS) and globbing to the expanded value, so folding it into one
// literal would diverge from what the shell actually runs. Refuse to fold when
// the value carries a current-IFS character or a glob metacharacter, or when IFS
// itself is unknown. Inside double quotes none of this applies, so quoted folds
// are always faithful. (Leading-tilde divergence is handled at assignment time.)
func foldableUnquoted(val string, env *foldEnv) bool {
	ifs := defaultIFS
	if env != nil {
		if !env.ifsKnown {
			return false
		}
		ifs = env.ifs
	}
	if ifs != "" && strings.ContainsAny(val, ifs) {
		return false
	}
	return !strings.ContainsAny(val, "*?[")
}

// decodeQuotedEscapes returns the effective string of a literal once bash's
// backslash handling is applied. Inside double quotes, a backslash is special
// only before $ ` " \ or newline (newline is a line continuation, removed);
// elsewhere it is literal. Unquoted, a backslash escapes any following character
// (newline removed). mvdan keeps these backslashes raw in Lit.Value, so a folded
// value would otherwise carry an extra backslash and miss a deny rule.
func decodeQuotedEscapes(s string, quoted bool) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '\n' {
				i++ // line continuation: drop backslash + newline
				continue
			}
			if !quoted || n == '$' || n == '`' || n == '"' || n == '\\' {
				b.WriteByte(n)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// extractWordPart handles individual word parts. quoted is true when the part
// is inside a double-quoted string (no word-splitting/globbing occurs).
func extractWordPart(part syntax.WordPart, env *foldEnv, quoted bool) (string, bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		return decodeQuotedEscapes(p.Value, quoted), false
	case *syntax.SglQuoted:
		// ANSI-C $'...' stores RAW source (e.g. \057); bash decodes escapes at
		// runtime, so the literal here is not the effective value — stay dynamic.
		if p.Dollar {
			return p.Value, true
		}
		return p.Value, false
	case *syntax.DblQuoted:
		s, dyn := extractDblQuoted(p, env)
		// $"..." is locale-translated at runtime; the source text may not be the
		// effective value, so treat it as dynamic.
		if p.Dollar {
			return s, true
		}
		return s, dyn
	case *syntax.ParamExp:
		if isPlainParam(p) && env != nil {
			if val, ok := env.vars[p.Param.Value]; ok && (quoted || foldableUnquoted(val, env)) {
				return val, false
			}
		}
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
		// @()/?()/*()/+()/!() — a pattern, not a literal; when extglob is active
		// bash expands it, so the source text is not the effective value. Dynamic.
		return fmt.Sprintf("%c(%s)", p.Op, p.Pattern.Value), true
	case *syntax.BraceExp:
		// Brace expansion like {a,b,c}
		var parts []string
		for _, elem := range p.Elems {
			s, _ := extractWord(elem, env)
			parts = append(parts, s)
		}
		return "{" + strings.Join(parts, ",") + "}", false
	default:
		return fmt.Sprintf("<%T>", p), true
	}
}

// extractDblQuoted handles double-quoted strings.
func extractDblQuoted(dq *syntax.DblQuoted, env *foldEnv) (string, bool) {
	var parts []string
	isDynamic := false

	for _, part := range dq.Parts {
		s, dyn := extractWordPart(part, env, true)
		parts = append(parts, s)
		if dyn {
			isDynamic = true
		}
	}
	return strings.Join(parts, ""), isDynamic
}
