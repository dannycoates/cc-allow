package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cc-allow/pkg/pathutil"
)

// Doc-read gates: a state-aware overlay that runs as a post-pass after the
// normal permission decision. On a tool call that matches a gate's pattern, the
// gate checks this agent's transcript (see agentTranscriptPath) for whether the
// gate's doc was read or injected within a small window of recent tool-call
// events. If fresh, the call
// proceeds untouched. If stale, the gate denies and injects the doc's full
// contents into the deny reason, so the content enters fresh context with no
// reliance on the model choosing to read it; the immediate retry then sees the
// injection sentinel as fresh and proceeds.
//
// The gate only ever escalates an allow/ask result to deny and early-returns on
// an existing deny, so it cannot weaken any existing rule and never participates
// in specificity scoring.

// defaultGateWindow is the freshness window (in tool-call events) when a gate
// does not set one. Small by design: retention degrades sharply as intervening
// tool-call volume grows, and the gate re-fires cheaply whenever it goes stale.
const defaultGateWindow = 10

// gateTailBytes bounds the transcript tail read. 512 KB covers a full freshness
// window in all but the densest sessions: across the 30 largest local
// transcripts, 256 KB left 5 short of window+2 tool-uses and 512 KB left 2. A
// genuine read beyond the tail causes only one spurious re-injection — the
// retry's injection is the newest tool_result, so the gate never loops — an
// accepted trade for a fixed, single-read tail (no fixed size beats a
// multi-MB tool_result; an expanding read was considered and declined).
const gateTailBytes = 512 * 1024

// gateWindow returns the effective freshness window for a gate.
func gateWindow(g DocGate) int {
	if g.Window <= 0 {
		return defaultGateWindow
	}
	return g.Window
}

// gateInjectionGrace bounds how long a recorded injection stands in for the
// transcript.
//
// It exists for one reason: the transcript is written asynchronously, so on an
// immediate retry the hook can fire before the previous injection's tool_result
// has been flushed to the JSONL. The gate then finds no sentinel and injects the
// whole doc a second time - the exact inject loop the sentinel was meant to
// prevent. Worse, the newest tool_use at that moment is the *previous* attempt,
// whose command is byte-identical, so isSelfCall skips it and the window is left
// empty. That makes the failure specific to identical retries, which is the case
// the guarantee is supposed to cover.
//
// The transcript stays the authority for the real freshness window. This marker
// only covers evidence that has not landed on disk yet, so it is deliberately
// short: long enough to absorb a loaded host, far shorter than any window.
const gateInjectionGrace = 60 * time.Second

// gateMarkerDirEnv lets tests point the marker directory somewhere disposable.
// os.UserCacheDir honours XDG_CACHE_HOME only on some platforms, so an explicit
// seam keeps the test portable.
const gateMarkerDirEnv = "CC_ALLOW_GATE_DIR"

// gateMarkerPath is the marker for one (agent, doc) pair, where key identifies
// the agent (see gateMarkerKey). Hashing both keeps two agents, or two gates in
// one agent, from satisfying each other, and keeps arbitrary doc paths out of a
// filename.
func gateMarkerPath(key, docPath string) (string, error) {
	dir := os.Getenv(gateMarkerDirEnv)
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "cc-allow", "gate")
	}
	sum := sha256.Sum256([]byte(key + "\x00" + docPath))
	return filepath.Join(dir, hex.EncodeToString(sum[:16])), nil
}

// gateMarkerKey identifies whose injection a marker records. A sidechain tool
// call carries the *parent's* session id, so keying on the session alone would
// let a parent's injection satisfy a subagent's gate for the whole grace period.
// The subagent would then run the gated command having never seen the doc -
// exactly what the gate exists to prevent. agent_id is present only inside a
// subagent, so it takes precedence wherever it is set.
func gateMarkerKey(input HookInput) string {
	if input.AgentID != "" {
		return input.AgentID
	}
	return input.SessionID
}

// recordGateInjection notes that this doc was just injected for this agent.
// Best effort throughout: a failure here costs at most one extra injection, and
// must never interfere with the deny that carries the doc.
func recordGateInjection(key, docPath string) {
	if key == "" {
		return // nothing to key on; transcript detection is the only path
	}
	p, err := gateMarkerPath(key, docPath)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		return
	}
	sweepGateMarkers(filepath.Dir(p))
}

// gateInjectedRecently reports whether this agent had this doc injected within
// the grace period.
func gateInjectedRecently(key, docPath string) bool {
	if key == "" {
		return false
	}
	p, err := gateMarkerPath(key, docPath)
	if err != nil {
		return false
	}
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < gateInjectionGrace
}

// sweepGateMarkers drops markers long past their grace period, so the directory
// cannot grow without bound as sessions come and go. Cheap: it holds one empty
// file per (agent, doc) that was actually gated.
func sweepGateMarkers(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil || fi.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

// agentTranscriptPath returns the transcript that records this call.
//
// Claude Code derives transcript_path from the session id alone, and a subagent
// shares its parent's session id - so a sidechain tool call is handed the PARENT
// transcript, which never contains the subagent's own reads or injections. Left
// unresolved, a gate reading it denies every retry forever. agent_id is in the
// payload for exactly this purpose, and the agent's transcript is named after it.
func agentTranscriptPath(input HookInput) string {
	if input.AgentID == "" {
		return input.TranscriptPath // main thread
	}
	base := strings.TrimSuffix(input.TranscriptPath, ".jsonl") // <projects>/<session>
	dir := filepath.Join(base, "subagents")
	p := filepath.Join(dir, "agent-"+input.AgentID+".jsonl")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Nested agents get one extra path segment; the id still names the file.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			q := filepath.Join(dir, e.Name(), "agent-"+input.AgentID+".jsonl")
			if _, err := os.Stat(q); err == nil {
				return q
			}
		}
	}
	// Not flushed yet. Returning the derived path (never input.TranscriptPath,
	// which is the parent's) makes the tail read fail open, so a subagent's very
	// first gated call is allowed rather than judged against the wrong file.
	return p
}

// gateSentinel is the machine-detectable marker that leads an injected deny
// reason. It encodes the resolved doc path so distinct gates cannot
// cross-satisfy each other, and docFreshInTranscript finds it in a recent
// tool_result on the retry (the loop-protection case).
//
// A synthetic sentinel is used rather than detecting the doc's own content in
// the transcript: a denied tool_result carries no structured cc-allow marker
// (only content/is_error/tool_use_id/type), and matching doc content is fragile —
// Read results prefix every line with "<n>\t" (so only single-line fingerprints
// survive) and a single line risks a false "fresh" that would silently disable
// the gate. The sentinel is exact, gate-only, and path-scoped.
func gateSentinel(docPath string) string {
	return "⟦cc-allow:doc-gate:" + docPath + "⟧"
}

// applyDocGates is the post-pass. It returns result unchanged unless a gate
// matches, its doc is stale, and the doc is readable — in which case it returns
// a deny carrying the injected doc contents.
func applyDocGates(input HookInput, merged *MergedConfig, result Result) Result {
	if merged == nil || len(merged.Gates) == 0 {
		return result
	}
	if result.Action == ActionDeny {
		return result // already blocked; nothing to add
	}
	if input.TranscriptPath == "" {
		return result // pipe mode / no transcript → fail-open
	}

	pv := pathutil.NewPathVars(findProjectRoot())
	if input.Cwd != "" {
		pv.Cwd = input.Cwd
	}
	ctx := &MatchContext{PathVars: pv, Merged: merged}
	transcriptPath := agentTranscriptPath(input)
	markerKey := gateMarkerKey(input)

	for _, g := range merged.Gates {
		if !gateMatches(g, input, ctx) {
			continue
		}
		docPath := canonPath(g.Doc, pv)
		if isReadOfDoc(input, docPath, pv) {
			continue // never gate the doc read itself
		}
		// Checked before the transcript because it is both cheaper (one stat
		// versus a 512 KB tail read) and more reliable: it records the
		// injection at the instant it happens, rather than waiting for the
		// transcript to be flushed. See gateInjectionGrace.
		if gateInjectedRecently(markerKey, docPath) {
			continue
		}
		if docFreshInTranscript(transcriptPath, docPath, gateWindow(g), input, pv) {
			continue
		}
		contents, err := os.ReadFile(docPath)
		if err != nil {
			return result // misconfig (e.g. host-specific doc absent) → fail-open
		}
		recordGateInjection(markerKey, docPath)
		return Result{
			Action:  ActionDeny,
			Message: buildInjection(docPath, string(contents), g.Message, gateWindow(g)),
			Source:  "doc-gate: " + g.Doc,
		}
	}
	return result
}

// gateMatches reports whether the gate's matcher applies to this tool call.
func gateMatches(g DocGate, input HookInput, ctx *MatchContext) bool {
	if g.Bash != "" && (input.ToolName == ToolBash || input.ToolName == "") {
		return matchOne(g.Bash, input.ToolInput.Command, ctx)
	}
	if g.WebFetch != "" && input.ToolName == ToolWebFetch {
		return matchOne(g.WebFetch, input.ToolInput.URL, ctx)
	}
	return false
}

// canonPath expands $HOME / $PROJECT_ROOT and ~, then resolves to a cleaned
// absolute path (resolving symlinks when the path exists). Used to canonicalize
// both the gate's doc and path tokens so they compare exactly.
func canonPath(p string, pv *pathutil.PathVars) string {
	if p == "" {
		return ""
	}
	return pathutil.ResolvePath(pv.ExpandPattern(p), pv.Cwd, pv.Home)
}

// isReadOfDoc reports whether the current tool call is itself a read of the doc,
// so the gate never blocks the very action that would make the doc fresh.
func isReadOfDoc(input HookInput, docPath string, pv *pathutil.PathVars) bool {
	switch input.ToolName {
	case ToolRead:
		return canonPath(input.ToolInput.FilePath, pv) == docPath
	case ToolBash, "":
		return commandReadsDoc(input.ToolInput.Command, docPath, pv)
	}
	return false
}

// docReadVerbs are commands that read a file's contents to stdout/pager.
var docReadVerbs = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true,
	"bat": true, "grep": true, "rg": true, "view": true,
}

// commandReadsDoc reports whether a bash command reads the doc: it must contain
// a read verb and reference the doc, either as a literal substring of the
// resolved path or as a path-like token that resolves to it.
func commandReadsDoc(command, docPath string, pv *pathutil.PathVars) bool {
	if command == "" || docPath == "" {
		return false
	}
	fields := strings.Fields(command)
	hasVerb := false
	for _, f := range fields {
		if docReadVerbs[f] {
			hasVerb = true
			break
		}
	}
	if !hasVerb {
		return false
	}
	if strings.Contains(command, docPath) {
		return true
	}
	for _, tok := range fields {
		tok = strings.Trim(tok, "'\"")
		if tok == "" || strings.HasPrefix(tok, "-") {
			continue
		}
		if pathutil.IsPathLike(tok) || pathutil.HasFileExtension(tok) {
			if canonPath(tok, pv) == docPath {
				return true
			}
		}
	}
	return false
}

// transcriptLine is one JSONL entry. Only assistant/user entries carry the
// content blocks the gate cares about; everything else is skipped.
type transcriptLine struct {
	Type    string          `json:"type"`
	Message json.RawMessage `json:"message"`
}

// transcriptMessage is the message object. Content is a string (plain user text)
// or an array of content blocks; it is decoded as RawMessage and handled by type.
type transcriptMessage struct {
	Content json.RawMessage `json:"content"`
}

// transcriptBlock is one content block: a tool_use (assistant) or tool_result
// (user). Unused fields per type stay zero.
type transcriptBlock struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`    // tool_use: tool name
	Input   transcriptInput `json:"input"`   // tool_use: tool input
	Content json.RawMessage `json:"content"` // tool_result: string or array of parts
}

// transcriptInput holds the tool-input fields the gate inspects.
type transcriptInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
	URL      string `json:"url"`
}

// docFreshInTranscript walks the transcript tail newest→oldest and reports
// whether the doc was read or injected within the last `window` tool-call
// events. A genuine read error fails open (returns true) so an undeterminable
// transcript can never trap the gate in an inject loop.
func docFreshInTranscript(transcriptPath, docPath string, window int, input HookInput, pv *pathutil.PathVars) bool {
	lines, err := readTranscriptTail(transcriptPath, gateTailBytes)
	if err != nil {
		return true // cannot determine freshness → do not gate (avoids inject loop)
	}

	sentinel := gateSentinel(docPath)
	toolUseCount := 0
	skippedSelf := false

	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var entry transcriptLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.Type != "assistant" && entry.Type != "user" {
			continue
		}
		blocks := decodeContentBlocks(entry.Message)

		if entry.Type == "assistant" {
			for _, b := range blocks {
				if b.Type != "tool_use" {
					continue
				}
				// Skip the single newest tool_use that equals the current call
				// (the gated action itself, which is appended before the hook
				// fires). This keeps the window count exact.
				if !skippedSelf && isSelfCall(b, input) {
					skippedSelf = true
					continue
				}
				toolUseCount++
				if toolUseCount > window {
					return false // walked past the window without a fresh hit → stale
				}
				if isDocReadBlock(b, docPath, pv) {
					return true // recent read
				}
			}
			continue
		}

		// user entry: look for a prior injection sentinel in a tool_result.
		for _, b := range blocks {
			if b.Type != "tool_result" {
				continue
			}
			if strings.Contains(toolResultText(b.Content), sentinel) {
				return true // recent injection (loop protection)
			}
		}
	}
	return false
}

// isSelfCall reports whether a transcript tool_use is the current gated call.
func isSelfCall(b transcriptBlock, input HookInput) bool {
	switch input.ToolName {
	case ToolBash, "":
		return b.Name == string(ToolBash) && b.Input.Command == input.ToolInput.Command
	case ToolWebFetch:
		return b.Name == string(ToolWebFetch) && b.Input.URL == input.ToolInput.URL
	}
	return false
}

// isDocReadBlock reports whether a transcript tool_use reads the doc.
func isDocReadBlock(b transcriptBlock, docPath string, pv *pathutil.PathVars) bool {
	switch b.Name {
	case string(ToolRead):
		return canonPath(b.Input.FilePath, pv) == docPath
	case string(ToolBash):
		return commandReadsDoc(b.Input.Command, docPath, pv)
	}
	return false
}

// decodeContentBlocks extracts the content blocks from an entry's message.
// Returns nil when the message is absent or its content is a plain string.
func decodeContentBlocks(raw json.RawMessage) []transcriptBlock {
	if len(raw) == 0 {
		return nil
	}
	var msg transcriptMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil
	}
	if len(msg.Content) == 0 {
		return nil
	}
	var blocks []transcriptBlock
	if err := json.Unmarshal(msg.Content, &blocks); err != nil {
		return nil // content is a plain string, not an array of blocks
	}
	return blocks
}

// toolResultText flattens a tool_result content field (string or array of text
// parts) to a single string for sentinel detection.
func toolResultText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// readTranscriptTail reads up to maxBytes from the end of the transcript and
// returns its lines, dropping the first (partial) line when the file was longer
// than the tail. An existing but empty file yields no lines and no error.
func readTranscriptTail(path string, maxBytes int64) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if fi.Size() > maxBytes {
		start = fi.Size() - maxBytes
	}
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // drop the partial first line
	}
	return lines, nil
}

// buildInjection composes the deny reason: the sentinel line, a preamble (the
// gate's message override or the default STOP instruction), then the doc
// contents fenced by BEGIN/END markers.
func buildInjection(docPath, contents, message string, window int) string {
	preamble := message
	if strings.TrimSpace(preamble) == "" {
		preamble = fmt.Sprintf(
			"STOP. This action is gated on required reading that is not currently fresh in your context.\n"+
				"The full contents of %s are included below. Read them now, then re-issue the exact command\n"+
				"you just attempted — it will be permitted because this doc will count as fresh for the next\n"+
				"%d tool calls.",
			docPath, window)
	}

	var b strings.Builder
	b.WriteString(gateSentinel(docPath))
	b.WriteString("\n")
	b.WriteString(preamble)
	b.WriteString("\n\n")
	b.WriteString("----- BEGIN " + docPath + " -----\n")
	b.WriteString(contents)
	if !strings.HasSuffix(contents, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("----- END " + docPath + " -----\n")
	return b.String()
}
