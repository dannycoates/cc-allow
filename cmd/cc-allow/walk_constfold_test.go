package main

import (
	"os"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// extractBash is a small helper that parses a bash string and returns the
// extracted info using the current working directory.
func extractBash(t *testing.T, bash string) *ExtractedInfo {
	t.Helper()
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(bash), "test")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	cwd, _ := os.Getwd()
	return ExtractFromFile(f, cwd)
}

func findCommand(info *ExtractedInfo, name string) *Command {
	for i := range info.Commands {
		if info.Commands[i].Name == name {
			return &info.Commands[i]
		}
	}
	return nil
}

// TestConstFold_CommandName verifies that a command whose name is built from a
// variable assigned a static string literal earlier in the same command list is
// resolved to its literal value and is no longer classified dynamic.
func TestConstFold_CommandName(t *testing.T) {
	info := extractBash(t, `SKILL=/lit/path; "$SKILL/scripts/x" a b`)

	cmd := findCommand(info, "/lit/path/scripts/x")
	if cmd == nil {
		t.Fatalf("expected resolved command name %q, got commands: %+v", "/lit/path/scripts/x", info.Commands)
	}
	if cmd.IsDynamic {
		t.Errorf("expected IsDynamic=false for statically-resolved command name, got true")
	}
}

// TestConstFold_RedirectTarget verifies a redirect target built from a
// literal-assigned variable is resolved and no longer dynamic.
func TestConstFold_RedirectTarget(t *testing.T) {
	info := extractBash(t, `D=/tmp/x; echo y >> "$D/f"`)

	if len(info.Redirects) != 1 {
		t.Fatalf("expected 1 redirect, got %d: %+v", len(info.Redirects), info.Redirects)
	}
	r := info.Redirects[0]
	if r.Target != "/tmp/x/f" {
		t.Errorf("expected resolved target %q, got %q", "/tmp/x/f", r.Target)
	}
	if r.IsDynamic {
		t.Errorf("expected IsDynamic=false for statically-resolved redirect, got true")
	}
}

// TestConstFold_Chained verifies that an assignment referencing a previously
// folded literal also folds (A=/x; B=$A/y).
func TestConstFold_Chained(t *testing.T) {
	info := extractBash(t, `A=/x; B=$A/y; "$B/z" arg`)

	cmd := findCommand(info, "/x/y/z")
	if cmd == nil {
		t.Fatalf("expected resolved command name %q, got commands: %+v", "/x/y/z", info.Commands)
	}
	if cmd.IsDynamic {
		t.Errorf("expected IsDynamic=false for chained literal fold, got true")
	}
}

// TestConstFold_CmdSubstNotFolded verifies that a variable assigned from a
// command substitution is NOT folded — its value is not statically known.
func TestConstFold_CmdSubstNotFolded(t *testing.T) {
	info := extractBash(t, `SDD="$(git rev-parse --git-path sdd)"; echo y >> "$SDD/progress.md"`)

	if len(info.Redirects) != 1 {
		t.Fatalf("expected 1 redirect, got %d: %+v", len(info.Redirects), info.Redirects)
	}
	if !info.Redirects[0].IsDynamic {
		t.Errorf("expected IsDynamic=true for command-substitution-assigned redirect, got false")
	}
}

// TestConstFold_UnknownVarNotFolded verifies an unassigned variable stays dynamic.
func TestConstFold_UnknownVarNotFolded(t *testing.T) {
	info := extractBash(t, `"$UNKNOWN/x" a`)

	for _, c := range info.Commands {
		if !c.IsDynamic {
			t.Errorf("expected IsDynamic=true for unknown variable, got false (cmd %q)", c.Name)
		}
	}
}

// TestConstFold_ModifierNotFolded verifies that parameter expansions with
// modifiers (e.g. ${VAR:-default}) are NOT folded — only plain $VAR / ${VAR}.
func TestConstFold_ModifierNotFolded(t *testing.T) {
	info := extractBash(t, `SKILL=/p; "${SKILL:-/other}/x" a`)

	cmd := lastCommand(info)
	if cmd == nil {
		t.Fatalf("expected a command, got none")
	}
	if !cmd.IsDynamic {
		t.Errorf("modifier expansion ${SKILL:-/other} must stay dynamic, got IsDynamic=false name=%q", cmd.Name)
	}
}

// --- helpers for the security-load-bearing regression tests below ---

// lastCommand returns the last extracted command (the one that uses the var in
// these single-use scenarios).
func lastCommand(info *ExtractedInfo) *Command {
	if len(info.Commands) == 0 {
		return nil
	}
	return &info.Commands[len(info.Commands)-1]
}

// hasResolvedCommand reports whether any command was statically resolved
// (IsDynamic=false) to exactly name — i.e. folded to that literal.
func hasResolvedCommand(info *ExtractedInfo, name string) bool {
	for _, c := range info.Commands {
		if !c.IsDynamic && c.Name == name {
			return true
		}
	}
	return false
}

// hasResolvedRedirect reports whether any redirect was statically resolved
// (IsDynamic=false) to exactly target.
func hasResolvedRedirect(info *ExtractedInfo, target string) bool {
	for _, r := range info.Redirects {
		if !r.IsDynamic && r.Target == target {
			return true
		}
	}
	return false
}

// Bypass class 1: stale value must be invalidated on non-provable reassignment.
func TestConstFold_ReassignToCmdSubst_NotFolded(t *testing.T) {
	info := extractBash(t, `A=/lit; A=$(echo y); "$A/x" a`)
	if hasResolvedCommand(info, "/lit/x") {
		t.Errorf("stale value survived reassignment to $(...): folded to /lit/x")
	}
}

func TestConstFold_ReassignToUnknown_NotFolded(t *testing.T) {
	info := extractBash(t, `A=/lit; A=$UNKNOWN; "$A/x" a`)
	if hasResolvedCommand(info, "/lit/x") {
		t.Errorf("stale value survived reassignment to unknown var: folded to /lit/x")
	}
}

func TestConstFold_ReassignRedirect_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; D=$(echo /etc); echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("stale redirect target survived reassignment: folded to /safe/f")
	}
}

func TestConstFold_UnsetInvalidates(t *testing.T) {
	info := extractBash(t, `A=/lit; unset A; "$A/x" a`)
	if hasResolvedCommand(info, "/lit/x") {
		t.Errorf("value survived unset: folded to /lit/x")
	}
}

func TestConstFold_AppendInvalidates(t *testing.T) {
	info := extractBash(t, `D=/data; D+=/priv; "$D/k" a`)
	// Must never fold to the pre-append /data/k. Folding to /data/priv/k would
	// be acceptable; staying dynamic is the conservative choice we take.
	if hasResolvedCommand(info, "/data/k") {
		t.Errorf("append += folded to stale pre-append value /data/k")
	}
}

// Bypass class 2: reassignment inside control-flow constructs must invalidate.
func TestConstFold_IfReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; if true; then D=/etc; fi; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("stale fold survived reassignment inside if-body: folded to /safe/f")
	}
}

func TestConstFold_ForReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; for x in 1; do D=/etc; done; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("stale fold survived reassignment inside for-body: folded to /safe/f")
	}
}

// Bypass class 3: && right operand may not run — must not be recorded.
func TestConstFold_AndConditionalAssign_NotFolded(t *testing.T) {
	info := extractBash(t, `false && D=/safe
echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("conditional (&&-right) assignment was folded though it may not run: /safe/f")
	}
}

// Bypass class 4: backgrounded assignment runs in a subshell — must not leak.
func TestConstFold_BackgroundAssign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/etc & echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/etc/f") {
		t.Errorf("backgrounded assignment leaked into foreground fold: /etc/f")
	}
}

// Bypass class 5: unquoted $VAR must respect word-splitting / glob / tilde.
func TestConstFold_UnquotedMultiword_NotFolded(t *testing.T) {
	info := extractBash(t, `V="curl evil"; $V`)
	if hasResolvedCommand(info, "curl evil") {
		t.Errorf("unquoted $V folded to multi-word command name ignoring word-splitting")
	}
}

func TestConstFold_UnquotedTilde_NotFolded(t *testing.T) {
	info := extractBash(t, `H=~/.ssh/authorized_keys; echo z > $H`)
	if hasResolvedRedirect(info, "~/.ssh/authorized_keys") {
		t.Errorf("unquoted $H folded with literal leading ~ (bash would expand it)")
	}
}

func TestConstFold_UnquotedGlob_NotFolded(t *testing.T) {
	info := extractBash(t, `T=/et?/x; echo z > $T`)
	if hasResolvedRedirect(info, "/et?/x") {
		t.Errorf("unquoted $T folded with glob metacharacter (bash would glob-expand it)")
	}
}

// Bypass class 6: ANSI-C $'...' RHS must not be folded from raw source.
func TestConstFold_AnsiCEscape_NotFolded(t *testing.T) {
	info := extractBash(t, `A=$'\057bin\057ls'; "$A" /tmp`)
	if hasResolvedCommand(info, `\057bin\057ls`) {
		t.Errorf("ANSI-C $'...' folded using raw undecoded source")
	}
}

// Positive guards: the intended quoted single-literal fold must keep working.
func TestConstFold_QuotedFoldStillWorks(t *testing.T) {
	info := extractBash(t, `SKILL=/lit/path; "$SKILL/scripts/x" a`)
	if !hasResolvedCommand(info, "/lit/path/scripts/x") {
		t.Errorf("intended quoted fold regressed: /lit/path/scripts/x not resolved")
	}
}

func TestConstFold_QuotedMultiwordStillFolds(t *testing.T) {
	// Inside double quotes bash does NOT word-split, so this fold is faithful.
	info := extractBash(t, `V="a b"; "$V/x" arg`)
	if !hasResolvedCommand(info, "a b/x") {
		t.Errorf("quoted fold of a spaced value should stay faithful, got commands %+v", info.Commands)
	}
}

// ---- Round 2: variable mutations that are NOT *syntax.Assign nodes ----

func TestConstFold_ForLoopVar_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; for D in /etc; do echo hi; done; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("for-loop variable rebinding left a stale fold: /safe/f")
	}
}

func TestConstFold_DeclareReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; declare D=/etc; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("declare reassignment left a stale fold: /safe/f")
	}
}

func TestConstFold_ExportReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; export D=$(echo /etc); echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("export reassignment to a substitution left a stale fold: /safe/f")
	}
}

func TestConstFold_ReadBuiltin_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; read D <<< /etc; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("read builtin left a stale fold: /safe/f")
	}
}

func TestConstFold_PrintfV_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; printf -v D /etc; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("printf -v left a stale fold: /safe/f")
	}
}

func TestConstFold_ArithmeticReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; (( D = 3 )); echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("arithmetic ((D=...)) left a stale fold: /safe/f")
	}
}

func TestConstFold_LetReassign_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; let D=3; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("let reassignment left a stale fold: /safe/f")
	}
}

// Custom IFS: unquoted value splits on a custom separator the guard ignores.
func TestConstFold_CustomIFS_NotFolded(t *testing.T) {
	info := extractBash(t, `IFS=/; C="deploy/prod"; $C`)
	if hasResolvedCommand(info, "deploy/prod") {
		t.Errorf("unquoted $C folded to one word though IFS=/ would split it")
	}
}

// Double-quote backslash decoding: folded value must equal bash's stripped form.
func TestConstFold_DQBackslashEscape_Decoded(t *testing.T) {
	info := extractBash(t, `goodcmd > "/tmp/d\$x"`)
	if hasResolvedRedirect(info, `/tmp/d\$x`) {
		t.Errorf("double-quote escape kept raw backslash; bash strips it to /tmp/d$x")
	}
}

// Quoted tilde: H=~/x stores ~/x but bash expands ~ at assignment; must not fold.
func TestConstFold_QuotedTilde_NotFolded(t *testing.T) {
	info := extractBash(t, `H=~/x; "$H/y" a`)
	if hasResolvedCommand(info, "~/y") || hasResolvedCommand(info, "~/x/y") {
		t.Errorf("tilde value folded though bash expands ~ at assignment time")
	}
}

// ---- Round 2: over-invalidation must NOT drop legitimate folds ----

func TestConstFold_UnrelatedIfKeepsFold(t *testing.T) {
	info := extractBash(t, `SKILL=/lit/path; if true; then echo hi; fi; "$SKILL/scripts/x" a`)
	if !hasResolvedCommand(info, "/lit/path/scripts/x") {
		t.Errorf("an if-body that doesn't touch SKILL wrongly dropped the fold")
	}
}

func TestConstFold_UnrelatedForLoopKeepsFold(t *testing.T) {
	info := extractBash(t, `SKILL=/lit/path; for f in 1 2; do echo $f; done; "$SKILL/scripts/x" a`)
	if !hasResolvedCommand(info, "/lit/path/scripts/x") {
		t.Errorf("a for-loop over an unrelated var wrongly dropped the SKILL fold")
	}
}

func TestConstFold_InlineEnvInIfKeepsFold(t *testing.T) {
	// FOO=bar inside the if is inline-env (does not persist); it must not cause
	// SKILL to be forgotten.
	info := extractBash(t, `SKILL=/lit/path; if true; then FOO=bar echo hi; fi; "$SKILL/scripts/x" a`)
	if !hasResolvedCommand(info, "/lit/path/scripts/x") {
		t.Errorf("inline-env assignment inside if wrongly dropped the SKILL fold")
	}
}

// ---- Round 3: use-site assignments, arbitrary mutators, IFS-via-builtin ----

func TestConstFold_ParamAssignDefault_NotFolded(t *testing.T) {
	// ${D:=/etc} assigns D when null; the empty fold must not survive.
	info := extractBash(t, `D=; : "${D:=/etc}"; echo z > "$D/passwd"`)
	if hasResolvedRedirect(info, "/passwd") {
		t.Errorf("${D:=/etc} use-site assignment left a stale empty fold: /passwd")
	}
}

func TestConstFold_Eval_NotFolded(t *testing.T) {
	info := extractBash(t, `P=/bin/echo; eval "P=/bin/ls"; "$P" x`)
	if hasResolvedCommand(info, "/bin/echo") {
		t.Errorf("eval reassignment left a stale fold: /bin/echo")
	}
}

func TestConstFold_Source_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; source /tmp/x.sh; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("source left a stale fold: /safe/f")
	}
}

func TestConstFold_Dot_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; . /tmp/x.sh; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf(". (dot/source) left a stale fold: /safe/f")
	}
}

func TestConstFold_FunctionCall_NotFolded(t *testing.T) {
	info := extractBash(t, `foo() { D=/etc; }; D=/safe; foo; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("function call that reassigns D left a stale fold: /safe/f")
	}
}

func TestConstFold_NilEnvBuiltinInIf_NotFolded(t *testing.T) {
	// $C resolves to `read` only with the live env; the if-body must invalidate D.
	info := extractBash(t, `D=/safe; C=read; if true; then $C D; fi; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("builtin invoked via folded name inside if left a stale fold: /safe/f")
	}
}

func TestConstFold_ArithmeticUseSite_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; : $(( D = 5 )); echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("use-site arithmetic $((D=5)) left a stale fold: /safe/f")
	}
}

func TestConstFold_LetQuoted_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; let "D=8"; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("let \"D=8\" left a stale fold: /safe/f")
	}
}

// ---- Round 4: wrapper prefixes, trap, read parsing, same-statement ordering ----

func TestConstFold_BuiltinPrefix_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; builtin printf -v D /etc; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("`builtin printf -v D` hidden behind prefix left a stale fold: /safe/f")
	}
}

func TestConstFold_CommandPrefixRead_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; command read D <<< /etc; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("`command read D` hidden behind prefix left a stale fold: /safe/f")
	}
}

func TestConstFold_CommandPrefixEval_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; command eval "D=/etc"; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("`command eval` hidden behind prefix left a stale fold: /safe/f")
	}
}

func TestConstFold_Trap_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; trap "D=/etc" DEBUG; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("trap handler that rebinds D left a stale fold: /safe/f")
	}
}

func TestConstFold_ReadOptionArg_NotFolded(t *testing.T) {
	// -d Z consumes Z as the delimiter; REPLY (the real target) must be forgotten.
	info := extractBash(t, `REPLY=/safe; read -d Z; echo z > "$REPLY/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("read -d Z: REPLY target not invalidated, stale fold: /safe/f")
	}
}

func TestConstFold_ReadArraySubscript_NotFolded(t *testing.T) {
	info := extractBash(t, `arr=/safe; read "arr[0]"; echo z > "$arr/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("read arr[0]: scalar arr not invalidated, stale fold: /safe/f")
	}
}

func TestConstFold_UseSiteArithSameStmt_NotFolded(t *testing.T) {
	// The $((D=5)) side effect runs during command-word expansion, before the
	// redirect word — so the redirect on THIS statement must not fold the old D.
	info := extractBash(t, `D=/safe; echo $(( D = 5 )) > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("same-statement use-site arithmetic left a stale redirect fold: /safe/f")
	}
}

func TestConstFold_DeclareNameref_NotFolded(t *testing.T) {
	// declare -n makes D a nameref; a later read of $D is indirect — don't fold.
	info := extractBash(t, `D=/safe; declare -n D=other; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("declare -n nameref left a stale fold: /safe/f")
	}
}

// Positive: a benign `command`/`builtin`-wrapped NON-mutator must keep the fold.
func TestConstFold_CommandWrappedNonMutatorKeepsFold(t *testing.T) {
	info := extractBash(t, `SKILL=/lit/path; command echo hi; "$SKILL/scripts/x" a`)
	if !hasResolvedCommand(info, "/lit/path/scripts/x") {
		t.Errorf("`command echo` (non-mutator) wrongly dropped the SKILL fold")
	}
}

// ---- Round 5: deep edges ----

func TestConstFold_TrapDoubleDash_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; trap -- "D=/etc" DEBUG; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("`trap -- HANDLER` evaded handler detection, stale fold: /safe/f")
	}
}

func TestConstFold_FunctionNamedCommand_NotFolded(t *testing.T) {
	// A user function named `command` shadows the builtin; calling it can mutate.
	info := extractBash(t, `command() { D=/etc; }; D=/safe; command read X; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("function named `command` was stripped as a prefix, stale fold: /safe/f")
	}
}

func TestConstFold_SliceArith_NotFolded(t *testing.T) {
	info := extractBash(t, `D=/safe; v=abcdefgh; : "${v:D=2}"; echo z > "$D/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("slice-offset arithmetic ${v:D=2} write missed, stale fold: /safe/f")
	}
}

func TestConstFold_UseSiteIFSArith_NotFolded(t *testing.T) {
	// $((IFS=5)) makes splitting unknown; an unquoted $V must then stay dynamic.
	info := extractBash(t, `V=a5b; : $(( IFS = 5 )); $V`)
	if hasResolvedCommand(info, "a5b") {
		t.Errorf("use-site $((IFS=5)) left splitting state stale; $V wrongly folded")
	}
}

func TestConstFold_PrintfVSubscript_NotFolded(t *testing.T) {
	info := extractBash(t, `arr=/safe; printf -v "arr[0]" /etc; echo z > "$arr/f"`)
	if hasResolvedRedirect(info, "/safe/f") {
		t.Errorf("printf -v arr[0] subscript target missed, stale fold: /safe/f")
	}
}

func TestConstFold_ExtGlobRedirect_Dynamic(t *testing.T) {
	// Extglob in a target must not fold to a byte-corrupted literal.
	info := extractBash(t, `echo z > /e@(t)c`)
	if len(info.Redirects) != 1 || !info.Redirects[0].IsDynamic {
		t.Errorf("extglob redirect target should be dynamic, got %+v", info.Redirects)
	}
}

// TestConstFold_InlineEnvDoesNotPersist verifies that an inline environment
// assignment (FOO=bar cmd) does not leak into subsequent statements.
func TestConstFold_InlineEnvDoesNotPersist(t *testing.T) {
	info := extractBash(t, `FOO=/bar echo hi; "$FOO/x" a`)

	if findCommand(info, "/bar/x") != nil {
		t.Errorf("inline env assignment FOO=/bar must not persist to later commands")
	}
}
