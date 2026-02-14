package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSessionConfig(t *testing.T, sessionsDir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(sessionsDir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func setupTestSessionsDir(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	sessionsDir := filepath.Join(tmpDir, ".config", "cc-allow", "sessions")
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	return tmpDir, sessionsDir
}

func TestCountSessionMatches(t *testing.T) {
	t.Run("finds matches across sessions", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "session1.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)
		writeSessionConfig(t, sessionsDir, "session2.toml", `
version = "2.0"
[bash.allow]
commands = ["go", "npm"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test ./..."

		count := countSessionMatches(tmpDir, "current", input)
		if count != 2 {
			t.Errorf("expected 2 matches, got %d", count)
		}
	})

	t.Run("excludes current session", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "current.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)
		writeSessionConfig(t, sessionsDir, "other.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test ./..."

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 match (excluding current), got %d", count)
		}
	})

	t.Run("no sessions dir returns 0", func(t *testing.T) {
		tmpDir := t.TempDir()
		input := HookInput{ToolName: ToolBash}
		input.ToolInput.Command = "go test"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}
	})

	t.Run("single session returns 0", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "only.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 (the only.toml session), got %d", count)
		}
	})

	t.Run("no matching sessions returns 0", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "session1.toml", `
version = "2.0"
[bash.allow]
commands = ["npm"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}
	})

	t.Run("skips malformed configs", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "good.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)
		writeSessionConfig(t, sessionsDir, "bad.toml", `this is not valid toml {{{{`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 (skipping bad config), got %d", count)
		}
	})

	t.Run("empty project root returns 0", func(t *testing.T) {
		input := HookInput{ToolName: ToolBash}
		input.ToolInput.Command = "go test"

		count := countSessionMatches("", "current", input)
		if count != 0 {
			t.Errorf("expected 0, got %d", count)
		}
	})

	t.Run("file tool matches", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "session1.toml", `
version = "2.0"
[read.allow]
paths = ["path:`+tmpDir+`/**"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolRead,
		}
		input.ToolInput.FilePath = filepath.Join(tmpDir, "src", "main.go")

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 match for read path, got %d", count)
		}
	})

	t.Run("webfetch matches", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "session1.toml", `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://example\\.com/"]
`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolWebFetch,
		}
		input.ToolInput.URL = "https://example.com/api/data"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 match for webfetch, got %d", count)
		}
	})

	t.Run("skips non-toml files", func(t *testing.T) {
		tmpDir, sessionsDir := setupTestSessionsDir(t)

		writeSessionConfig(t, sessionsDir, "session1.toml", `
version = "2.0"
[bash.allow]
commands = ["go"]
`)
		writeSessionConfig(t, sessionsDir, ".gitignore", `*
!.gitignore
`)
		writeSessionConfig(t, sessionsDir, "notes.txt", `some notes`)

		input := HookInput{
			SessionID: "current",
			ToolName:  ToolBash,
		}
		input.ToolInput.Command = "go test"

		count := countSessionMatches(tmpDir, "current", input)
		if count != 1 {
			t.Errorf("expected 1 (only .toml files), got %d", count)
		}
	})
}

func TestBuildSessionMatchContext(t *testing.T) {
	msg := buildSessionMatchContext(3, ToolBash, "command: `go test`")

	if !strings.Contains(msg, "3 other session(s)") {
		t.Error("message should contain session count")
	}
	if !strings.Contains(msg, "Bash") {
		t.Error("message should contain tool name")
	}
	if !strings.Contains(msg, "go test") {
		t.Error("message should contain input description")
	}
	if !strings.Contains(msg, ".config/cc-allow.toml") {
		t.Error("message should reference project config path")
	}
	if !strings.Contains(msg, "MUST use AskUserQuestion") {
		t.Error("message should require AskUserQuestion")
	}
	if !strings.Contains(msg, "<system-reminder>") {
		t.Error("message should be wrapped in system-reminder tags")
	}
}

func TestDescribeToolInput(t *testing.T) {
	tests := []struct {
		name     string
		input    HookInput
		expected string
	}{
		{
			name: "bash command",
			input: func() HookInput {
				i := HookInput{ToolName: ToolBash}
				i.ToolInput.Command = "go test ./..."
				return i
			}(),
			expected: "command: `go test ./...`",
		},
		{
			name: "read file",
			input: func() HookInput {
				i := HookInput{ToolName: ToolRead}
				i.ToolInput.FilePath = "/project/main.go"
				return i
			}(),
			expected: "file: `/project/main.go`",
		},
		{
			name: "write file",
			input: func() HookInput {
				i := HookInput{ToolName: ToolWrite}
				i.ToolInput.FilePath = "/project/out.txt"
				return i
			}(),
			expected: "file: `/project/out.txt`",
		},
		{
			name: "edit file",
			input: func() HookInput {
				i := HookInput{ToolName: ToolEdit}
				i.ToolInput.FilePath = "/project/config.yaml"
				return i
			}(),
			expected: "file: `/project/config.yaml`",
		},
		{
			name: "webfetch",
			input: func() HookInput {
				i := HookInput{ToolName: ToolWebFetch}
				i.ToolInput.URL = "https://example.com/api"
				return i
			}(),
			expected: "URL: `https://example.com/api`",
		},
		{
			name: "glob with path",
			input: func() HookInput {
				i := HookInput{ToolName: ToolGlob}
				i.ToolInput.Pattern = "**/*.go"
				i.ToolInput.Path = "/project"
				return i
			}(),
			expected: "pattern='**/*.go' path='/project'",
		},
		{
			name: "grep without path",
			input: func() HookInput {
				i := HookInput{ToolName: ToolGrep}
				i.ToolInput.Pattern = "TODO"
				return i
			}(),
			expected: "pattern='TODO'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := describeToolInput(tt.input)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
