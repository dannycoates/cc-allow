package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatternForDir(t *testing.T) {
	home := "/home/heron"
	// Deliberately outside $HOME: $HOME is checked first, so a project root
	// nested under $HOME would always resolve to $HOME instead.
	projectRoot := "/opt/projects/cc-allow"

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{"home-relative", "/home/heron/Downloads", "path:$HOME/Downloads/**"},
		{"home-relative-nested", "/home/heron/.config/foo/bar", "path:$HOME/.config/foo/bar/**"},
		{"project-relative", "/opt/projects/cc-allow/cmd/cc-allow", "path:$PROJECT_ROOT/cmd/cc-allow/**"},
		{"literal-absolute-mnt-memes", "/mnt/d/Human Documents/digital-presence/memes", "path:/mnt/d/Human Documents/digital-presence/memes/**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := patternForDir(tt.dir, home, projectRoot)
			if got != tt.want {
				t.Errorf("patternForDir(%q) = %q, want %q", tt.dir, got, tt.want)
			}
		})
	}
}

func TestPatternForDirNoProjectRoot(t *testing.T) {
	// A directory under neither $HOME nor a resolved project root (project
	// root outside $HOME, unrelated tree) falls back to a literal pattern.
	got := patternForDir("/mnt/d/Human Documents/digital-presence/memes", "/home/heron", "")
	want := "path:/mnt/d/Human Documents/digital-presence/memes/**"
	if got != want {
		t.Errorf("patternForDir() = %q, want %q", got, want)
	}
}

func TestTooBroadDir(t *testing.T) {
	home := "/home/heron"

	tests := []struct {
		name     string
		dir      string
		tooBroad bool
	}{
		{"home-itself", "/home/heron", true},
		{"filesystem-root", "/", true},
		{"one-above-home", "/home", true},
		{"bare-mnt-drive-root", "/mnt/d", true},
		{"another-bare-mnt-drive-root", "/mnt/c", true},
		{"memes-dir-is-fine", "/mnt/d/Human Documents/digital-presence/memes", false},
		{"home-subdir-is-fine", "/home/heron/Downloads", false},
		{"mnt-with-subdir-is-fine", "/mnt/d/some/dir", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tooBroadDir(tt.dir, home)
			if got != tt.tooBroad {
				t.Errorf("tooBroadDir(%q) = %v, want %v", tt.dir, got, tt.tooBroad)
			}
		})
	}
}

func TestPatternForURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{"basic-https", "https://example.com/foo/bar", "re:^https://example\\.com/", false},
		{"with-port", "http://localhost:8080/api", "re:^http://localhost:8080/", false},
		{"no-scheme", "example.com/foo", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := patternForURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("patternForURL(%q) expected error, got %q", tt.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("patternForURL(%q) unexpected error: %v", tt.url, err)
			}
			if got != tt.want {
				t.Errorf("patternForURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
			// The generated pattern must actually match the URL it was derived from.
			p, err := ParsePattern(got)
			if err != nil {
				t.Fatalf("ParsePattern(%q) error: %v", got, err)
			}
			if !p.Match(tt.url) {
				t.Errorf("pattern %q does not match its source URL %q", got, tt.url)
			}
		})
	}
}

func TestMergeSessionRuleCreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.toml")

	changed, err := mergeSessionRule(path, "read", "path:$HOME/Downloads/**")
	if err != nil {
		t.Fatalf("mergeSessionRule error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true for new file")
	}

	content := readFile(t, path)
	if !strings.Contains(content, "version = \"2.0\"") {
		t.Errorf("missing version header: %s", content)
	}
	if !strings.Contains(content, "[read.allow]") {
		t.Errorf("missing [read.allow] section: %s", content)
	}
	if !strings.Contains(content, `"path:$HOME/Downloads/**"`) {
		t.Errorf("missing new pattern: %s", content)
	}

	assertConfigParses(t, path)
}

func TestMergeSessionRuleAppendsNewSectionLeavesBashBlockUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.toml")
	original := "version = \"2.0\"\n\n[[bash.allow.git.push]]\nargs.all = [\"origin\"]\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := mergeSessionRule(path, "read", "path:$HOME/Downloads/**")
	if err != nil {
		t.Fatalf("mergeSessionRule error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}

	content := readFile(t, path)
	if !strings.Contains(content, original) {
		t.Errorf("existing bash block was modified:\n%s", content)
	}
	if !strings.Contains(content, "[read.allow]") {
		t.Errorf("missing [read.allow] section: %s", content)
	}
	if !strings.Contains(content, `"path:$HOME/Downloads/**"`) {
		t.Errorf("missing new pattern: %s", content)
	}

	assertConfigParses(t, path)
}

func TestMergeSessionRuleInsertsIntoExistingPathsArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.toml")
	original := "version = \"2.0\"\n\n[read.allow]\npaths = [\"path:$HOME/Documents/**\"]\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := mergeSessionRule(path, "read", "path:$HOME/Downloads/**")
	if err != nil {
		t.Fatalf("mergeSessionRule error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}

	content := readFile(t, path)
	if !strings.Contains(content, `"path:$HOME/Documents/**"`) {
		t.Errorf("existing pattern was lost: %s", content)
	}
	if !strings.Contains(content, `"path:$HOME/Downloads/**"`) {
		t.Errorf("missing new pattern: %s", content)
	}
	// Exactly one [read.allow] header -- inserted into the existing section,
	// not appended as a duplicate.
	if strings.Count(content, "[read.allow]") != 1 {
		t.Errorf("expected exactly one [read.allow] header: %s", content)
	}

	assertConfigParses(t, path)
}

func TestMergeSessionRuleSkipsWhenAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.toml")
	original := "version = \"2.0\"\n\n[read.allow]\npaths = [\"path:$HOME/Downloads/**\"]\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := mergeSessionRule(path, "read", "path:$HOME/Downloads/**")
	if err != nil {
		t.Fatalf("mergeSessionRule error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false when pattern already present")
	}

	content := readFile(t, path)
	if content != original {
		t.Errorf("file should be unchanged:\ngot:  %q\nwant: %q", content, original)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

// assertConfigParses confirms mergeSessionRule always leaves behind valid,
// parseable TOML.
func assertConfigParses(t *testing.T, path string) {
	t.Helper()
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("session config at %s failed to parse: %v", path, err)
	}
}
