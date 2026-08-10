package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cc-allow/pkg/pathutil"
)

const (
	gateDocBody = "GATED-DOC-BODY-MARKER\nrun acli with --key, not REST.\n"
	acliCmd     = "acli jira workitem transition --key MAC-1 --status Done --yes"
	jiraBash    = `re:\bacli\b|atlassian\.|/rest/(api|agile)`
)

// gateDoc writes a doc file into dir and returns its path.
func gateDoc(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "gatedoc.md")
	if err := os.WriteFile(p, []byte(gateDocBody), 0644); err != nil {
		t.Fatalf("write doc: %v", err)
	}
	return p
}

// gateMerged builds a merged config holding a single gate via the real parse +
// merge path, so tests exercise [[gate]] parsing, not a hand-built struct.
func gateMerged(t *testing.T, doc, bash string, window int) *MergedConfig {
	t.Helper()
	tmpl := "[[gate]]\ndoc = %q\nbash = '%s'\nwindow = %d\n"
	cfg, err := parseConfigInternal(fmt.Sprintf(tmpl, doc, bash, window))
	if err != nil {
		t.Fatalf("parse gate config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate gate config: %v", err)
	}
	cfg.Path = "test.toml"
	return MergeConfigs([]*Config{cfg})
}

// asstToolUse renders an assistant tool_use transcript line.
func asstToolUse(t *testing.T, name string, input map[string]any) string {
	t.Helper()
	entry := map[string]any{
		"type": "assistant",
		"message": map[string]any{
			"role":    "assistant",
			"content": []any{map[string]any{"type": "tool_use", "name": name, "input": input}},
		},
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal tool_use: %v", err)
	}
	return string(b)
}

// userToolResult renders a user tool_result transcript line.
func userToolResult(t *testing.T, content string, isErr bool) string {
	t.Helper()
	entry := map[string]any{
		"type": "user",
		"message": map[string]any{
			"role":    "user",
			"content": []any{map[string]any{"type": "tool_result", "is_error": isErr, "content": content}},
		},
	}
	b, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal tool_result: %v", err)
	}
	return string(b)
}

// writeTranscript writes JSONL lines and returns the file path.
func writeTranscript(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	p := filepath.Join(dir, "transcript.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	return p
}

// bashInput builds a Bash hook input pointed at a transcript.
func bashInput(cmd, transcriptPath string) HookInput {
	var in HookInput
	in.ToolName = ToolBash
	in.ToolInput.Command = cmd
	in.TranscriptPath = transcriptPath
	return in
}

// allow is the pre-gate result for the common case.
func allow() Result { return Result{Action: ActionAllow, Source: "test-allow"} }

// canonicalDoc resolves a raw doc path the way the gate does, so tests can
// predict the sentinel string.
func canonicalDoc(doc string) string {
	return canonPath(doc, pathutil.NewPathVars(findProjectRoot()))
}

func TestDocGateStaleDenies(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	tr := writeTranscript(t, dir,
		asstToolUse(t, "Bash", map[string]any{"command": "ls -la"}),
		asstToolUse(t, "Bash", map[string]any{"command": "git status"}),
	)

	got := applyDocGates(bashInput(acliCmd, tr), merged, allow())
	if got.Action != ActionDeny {
		t.Fatalf("expected deny on stale doc, got %s", got.Action)
	}
	if !strings.Contains(got.Message, gateSentinel(canonicalDoc(doc))) {
		t.Errorf("deny message missing sentinel:\n%s", got.Message)
	}
	if !strings.Contains(got.Message, "GATED-DOC-BODY-MARKER") {
		t.Errorf("deny message missing doc body:\n%s", got.Message)
	}
}

func TestDocGateFreshReadAllows(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	tr := writeTranscript(t, dir,
		asstToolUse(t, "Read", map[string]any{"file_path": doc}),
		asstToolUse(t, "Bash", map[string]any{"command": acliCmd}), // the self call
	)

	got := applyDocGates(bashInput(acliCmd, tr), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("expected allow after recent Read, got %s (%s)", got.Action, got.Message)
	}
}

func TestDocGateFreshBashReadAllows(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	tr := writeTranscript(t, dir,
		asstToolUse(t, "Bash", map[string]any{"command": "cat " + doc}),
		asstToolUse(t, "Bash", map[string]any{"command": acliCmd}),
	)

	got := applyDocGates(bashInput(acliCmd, tr), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("expected allow after `cat doc`, got %s (%s)", got.Action, got.Message)
	}
}

// TestDocGateInjectionLoopProtection is the load-bearing test: a stale deny
// injects the doc, the retry sees the injection sentinel in a recent
// tool_result, and is allowed — exactly one injection, never a loop.
func TestDocGateInjectionLoopProtection(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	stale := writeTranscript(t, dir,
		asstToolUse(t, "Bash", map[string]any{"command": "ls"}),
	)
	denied := applyDocGates(bashInput(acliCmd, stale), merged, allow())
	if denied.Action != ActionDeny {
		t.Fatalf("setup: expected initial deny, got %s", denied.Action)
	}

	// The retry transcript: the original attempt, the injected deny as a
	// tool_result, then the identical retry (the self call).
	retry := writeTranscript(t, dir,
		asstToolUse(t, "Bash", map[string]any{"command": acliCmd}),
		userToolResult(t, denied.Message, true),
		asstToolUse(t, "Bash", map[string]any{"command": acliCmd}),
	)
	got := applyDocGates(bashInput(acliCmd, retry), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("expected allow on retry (injection fresh), got %s (%s)", got.Action, got.Message)
	}
}

// TestDocGateSurvivesTranscriptLag covers the race the sentinel alone cannot.
//
// The transcript is written asynchronously, so an immediate retry's hook can
// fire before the injection's tool_result has been flushed. The transcript then
// shows only the first attempt, whose command is byte-identical, so isSelfCall
// consumes it and the window is left empty with no sentinel in sight - and the
// gate injects the whole doc a second time. Observed live: one command produced
// two full injections of the same doc, one transcript line apart.
func TestDocGateSurvivesTranscriptLag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(gateMarkerDirEnv, filepath.Join(dir, "markers"))
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))
	first := bashInput(acliCmd, stale)
	first.SessionID = "sess-lag"
	if got := applyDocGates(first, merged, allow()); got.Action != ActionDeny {
		t.Fatalf("setup: expected initial deny, got %s", got.Action)
	}

	// The retry, with the injection's tool_result not yet on disk.
	lagged := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": acliCmd}))
	retry := bashInput(acliCmd, lagged)
	retry.SessionID = "sess-lag"
	if got := applyDocGates(retry, merged, allow()); got.Action != ActionAllow {
		t.Fatalf("re-injected despite an injection recorded moments earlier: %s", got.Action)
	}
}

// TestDocGateMarkerIsSessionScoped: one session's injection must not satisfy
// another's, or a fresh session would silently skip its required reading.
func TestDocGateMarkerIsSessionScoped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(gateMarkerDirEnv, filepath.Join(dir, "markers"))
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))
	a := bashInput(acliCmd, stale)
	a.SessionID = "sess-a"
	if got := applyDocGates(a, merged, allow()); got.Action != ActionDeny {
		t.Fatalf("setup: expected deny for session a, got %s", got.Action)
	}

	b := bashInput(acliCmd, stale)
	b.SessionID = "sess-b"
	if got := applyDocGates(b, merged, allow()); got.Action != ActionDeny {
		t.Fatalf("session b rode session a's marker: %s", got.Action)
	}
}

// TestDocGateMarkerExpires: the marker bridges a flush lag, it does not grant
// permanent freshness. Past the grace period the transcript is authoritative
// again.
func TestDocGateMarkerExpires(t *testing.T) {
	dir := t.TempDir()
	markers := filepath.Join(dir, "markers")
	t.Setenv(gateMarkerDirEnv, markers)
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))
	in := bashInput(acliCmd, stale)
	in.SessionID = "sess-exp"
	if got := applyDocGates(in, merged, allow()); got.Action != ActionDeny {
		t.Fatalf("setup: expected deny, got %s", got.Action)
	}

	p, err := gateMarkerPath("sess-exp", canonicalDoc(doc))
	if err != nil {
		t.Fatalf("marker path: %v", err)
	}
	old := time.Now().Add(-2 * gateInjectionGrace)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("age marker: %v", err)
	}

	if got := applyDocGates(in, merged, allow()); got.Action != ActionDeny {
		t.Fatalf("expired marker still counted as fresh: %s", got.Action)
	}
}

// TestDocGateReadOlderThanWindow proves freshness is recency, not ever-read:
// a read beyond the window re-denies.
func TestDocGateReadOlderThanWindow(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 3)

	// Oldest first: a read, then 4 unrelated tool_uses, then the self call.
	tr := writeTranscript(t, dir,
		asstToolUse(t, "Read", map[string]any{"file_path": doc}),
		asstToolUse(t, "Bash", map[string]any{"command": "ls 1"}),
		asstToolUse(t, "Bash", map[string]any{"command": "ls 2"}),
		asstToolUse(t, "Bash", map[string]any{"command": "ls 3"}),
		asstToolUse(t, "Bash", map[string]any{"command": "ls 4"}),
		asstToolUse(t, "Bash", map[string]any{"command": acliCmd}),
	)

	got := applyDocGates(bashInput(acliCmd, tr), merged, allow())
	if got.Action != ActionDeny {
		t.Fatalf("expected deny when read is beyond window, got %s", got.Action)
	}
}

// TestDocGateNeverGatesTheReadItself covers both the doc read as the current
// call (isReadOfDoc) and a matching non-read control that still denies.
func TestDocGateNeverGatesTheReadItself(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	// Pattern matches the doc name so the read command itself matches the gate.
	merged := gateMerged(t, doc, "re:gatedoc", 10)
	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))

	// `cat <doc>` matches the pattern but is a read of the doc → allow.
	catInput := bashInput("cat "+doc, stale)
	if got := applyDocGates(catInput, merged, allow()); got.Action != ActionAllow {
		t.Errorf("`cat doc` should never be gated, got %s (%s)", got.Action, got.Message)
	}

	// A Read tool call of the doc → bash-only gate does not match it → allow.
	var readInput HookInput
	readInput.ToolName = ToolRead
	readInput.ToolInput.FilePath = doc
	readInput.TranscriptPath = stale
	if got := applyDocGates(readInput, gateMerged(t, doc, jiraBash, 10), allow()); got.Action != ActionAllow {
		t.Errorf("Read of doc should never be gated, got %s", got.Action)
	}

	// Control: a matching non-read command with the same pattern → deny.
	echoInput := bashInput("echo gatedoc reminder", stale)
	if got := applyDocGates(echoInput, merged, allow()); got.Action != ActionDeny {
		t.Errorf("matching non-read command should deny, got %s", got.Action)
	}
}

func TestDocGateNonMatchingCommand(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)
	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "pwd"}))

	got := applyDocGates(bashInput("ls -la", stale), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("non-matching command should be unchanged, got %s", got.Action)
	}
}

func TestDocGateNoTranscriptFailsOpen(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)

	got := applyDocGates(bashInput(acliCmd, ""), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("empty transcript_path should fail open, got %s", got.Action)
	}
}

func TestDocGateMissingDocFailsOpen(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.md")
	merged := gateMerged(t, missing, jiraBash, 10)
	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))

	got := applyDocGates(bashInput(acliCmd, stale), merged, allow())
	if got.Action != ActionAllow {
		t.Fatalf("missing doc should fail open, got %s (%s)", got.Action, got.Message)
	}
}

func TestDocGateExistingDenyUntouched(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)
	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))

	pre := Result{Action: ActionDeny, Message: "original deny", Source: "rule"}
	got := applyDocGates(bashInput(acliCmd, stale), merged, pre)
	if got.Action != ActionDeny || got.Message != "original deny" {
		t.Fatalf("existing deny must be returned untouched, got %s (%s)", got.Action, got.Message)
	}
}

// TestDocGateCurlRestMatches confirms the /rest/(api|agile) branch catches the
// curl form that hits api.atlassian.com (not atlassian.net).
func TestDocGateCurlRestMatches(t *testing.T) {
	dir := t.TempDir()
	doc := gateDoc(t, dir)
	merged := gateMerged(t, doc, jiraBash, 10)
	stale := writeTranscript(t, dir, asstToolUse(t, "Bash", map[string]any{"command": "ls"}))

	curl := `curl -s https://api.atlassian.com/ex/jira/abc/rest/api/3/issue/MAC-1/remotelink`
	got := applyDocGates(bashInput(curl, stale), merged, allow())
	if got.Action != ActionDeny {
		t.Fatalf("curl to /rest/api should be gated, got %s", got.Action)
	}
}

func TestGateValidation(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr bool
	}{
		{"valid bash", "[[gate]]\ndoc = \"/x\"\nbash = 're:acli'\n", false},
		{"valid webfetch", "[[gate]]\ndoc = \"/x\"\nwebfetch = 're:atlassian'\n", false},
		{"missing doc", "[[gate]]\nbash = 're:acli'\n", true},
		{"no matcher", "[[gate]]\ndoc = \"/x\"\n", true},
		{"bad regex", "[[gate]]\ndoc = \"/x\"\nbash = 're:('\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfigInternal(tc.toml)
			if err == nil {
				err = cfg.Validate()
			}
			if tc.wantErr && err == nil {
				t.Errorf("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGateWindowDefault(t *testing.T) {
	if got := gateWindow(DocGate{}); got != defaultGateWindow {
		t.Errorf("unset window = %d, want %d", got, defaultGateWindow)
	}
	if got := gateWindow(DocGate{Window: 5}); got != 5 {
		t.Errorf("explicit window = %d, want 5", got)
	}
}
