package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"cc-allow/pkg/pathutil"
)

// Doc-read gates: a state-aware overlay that runs as a post-pass after the
// normal permission decision. On a tool call that matches a gate's pattern, the
// gate checks the session transcript for whether the gate's doc was read or
// injected within a small window of recent tool-call events. If fresh, the call
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

// gateTailBytes bounds the transcript tail read. Transcripts can reach a few MB,
// but the window is single digits, so a fixed tail always covers it.
const gateTailBytes = 256 * 1024

// gateWindow returns the effective freshness window for a gate.
func gateWindow(g DocGate) int {
	if g.Window <= 0 {
		return defaultGateWindow
	}
	return g.Window
}

// gateSentinel is the machine-detectable marker that leads an injected deny
// reason. It encodes the resolved doc path so distinct gates cannot
// cross-satisfy each other, and docFreshInTranscript finds it in a recent
// tool_result on the retry (the loop-protection case).
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

	for _, g := range merged.Gates {
		if !gateMatches(g, input, ctx) {
			continue
		}
		docPath := canonPath(g.Doc, pv)
		if isReadOfDoc(input, docPath, pv) {
			continue // never gate the doc read itself
		}
		if docFreshInTranscript(input.TranscriptPath, docPath, gateWindow(g), input, pv) {
			continue
		}
		contents, err := os.ReadFile(docPath)
		if err != nil {
			return result // misconfig (e.g. host-specific doc absent) → fail-open
		}
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
		if p, err := ParsePattern(g.Bash); err == nil && p.MatchWithContext(input.ToolInput.Command, ctx) {
			return true
		}
	}
	if g.WebFetch != "" && input.ToolName == ToolWebFetch {
		if p, err := ParsePattern(g.WebFetch); err == nil && p.MatchWithContext(input.ToolInput.URL, ctx) {
			return true
		}
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
