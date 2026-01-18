package main

import (
	"cc-allow/pkg/pathutil"
	"testing"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		input    string
		wantType PatternType
	}{
		{"hello", PatternLiteral},
		{"*.txt", PatternGlob},
		{"glob:*.txt", PatternGlob},
		{"re:^foo$", PatternRegex},
		{"file.txt", PatternLiteral},
		{"dir/file", PatternLiteral},
		{"dir/*", PatternGlob},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := ParsePattern(tt.input)
			if err != nil {
				t.Fatalf("ParsePattern error: %v", err)
			}
			if p.Type != tt.wantType {
				t.Errorf("expected type %v, got %v", tt.wantType, p.Type)
			}
		})
	}
}

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		want    bool
	}{
		// Literal
		{"hello", "hello", true},
		{"hello", "world", false},
		{"hello", "hello!", false},

		// Glob
		{"*.txt", "file.txt", true},
		{"*.txt", "file.log", false},
		{"glob:test.*", "test.go", true},
		{"glob:test.*", "test", false},

		// Regex
		{"re:^foo$", "foo", true},
		{"re:^foo$", "foobar", false},
		{"re:^[0-7]{3}$", "755", true},
		{"re:^[0-7]{3}$", "888", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.input, func(t *testing.T) {
			p, err := ParsePattern(tt.pattern)
			if err != nil {
				t.Fatalf("ParsePattern error: %v", err)
			}
			got := p.Match(tt.input)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatcherAnyMatch(t *testing.T) {
	m, err := NewMatcher([]string{"*.txt", "*.log"})
	if err != nil {
		t.Fatalf("NewMatcher error: %v", err)
	}

	if !m.AnyMatch([]string{"file.txt", "other.go"}) {
		t.Error("expected match for file.txt")
	}

	if m.AnyMatch([]string{"file.go", "other.rs"}) {
		t.Error("expected no match")
	}
}

func TestMatcherAllMatch(t *testing.T) {
	m, err := NewMatcher([]string{"-f", "*.tmp"})
	if err != nil {
		t.Fatalf("NewMatcher error: %v", err)
	}

	if !m.AllMatch([]string{"-f", "file.tmp"}) {
		t.Error("expected all match")
	}

	if m.AllMatch([]string{"-f", "file.txt"}) {
		t.Error("expected no all match (*.tmp not found)")
	}

	if m.AllMatch([]string{"-r", "file.tmp"}) {
		t.Error("expected no all match (-f not found)")
	}
}

func TestContains(t *testing.T) {
	if !Contains([]string{"--force", "-rf"}, []string{"rf"}) {
		t.Error("expected to find 'rf' in '-rf'")
	}

	if Contains([]string{"--verbose"}, []string{"force"}) {
		t.Error("expected not to find 'force'")
	}
}

func TestContainsExact(t *testing.T) {
	if !ContainsExact([]string{"echo", "ls"}, []string{"echo"}) {
		t.Error("expected to find 'echo'")
	}

	if ContainsExact([]string{"echo", "ls"}, []string{"ech"}) {
		t.Error("expected not to find 'ech'")
	}
}

func TestMatchPosition(t *testing.T) {
	args := []string{"-f", "file.txt", "output.log"}

	if !MatchPosition(args, 0, "-f") {
		t.Error("expected position 0 to match -f")
	}

	if !MatchPosition(args, 1, "*.txt") {
		t.Error("expected position 1 to match *.txt")
	}

	if MatchPosition(args, 5, "anything") {
		t.Error("expected out of bounds to not match")
	}
}

func TestParsePatternPath(t *testing.T) {
	p, err := ParsePattern("path:$PROJECT_ROOT/**")
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}
	if p.Type != PatternPath {
		t.Errorf("expected PatternPath, got %v", p.Type)
	}
	if p.PathPattern != "$PROJECT_ROOT/**" {
		t.Errorf("expected PathPattern '$PROJECT_ROOT/**', got %q", p.PathPattern)
	}
}

func TestPathPatternWithContext(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		input       string
		projectRoot string
		home        string
		cwd         string
		want        bool
	}{
		{
			name:        "match under project root",
			pattern:     "path:$PROJECT_ROOT/**",
			input:       "./subdir/file.txt",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        true,
		},
		{
			name:        "match exact project root",
			pattern:     "path:$PROJECT_ROOT",
			input:       ".",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        true,
		},
		{
			name:        "no match outside project root",
			pattern:     "path:$PROJECT_ROOT/**",
			input:       "/etc/passwd",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        false,
		},
		{
			name:        "match under home",
			pattern:     "path:$HOME/.config/**",
			input:       "~/.config/app/settings.json",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        true,
		},
		{
			name:        "absolute path under project root",
			pattern:     "path:$PROJECT_ROOT/**",
			input:       "/home/user/project/src/main.go",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        true,
		},
		{
			name:        "relative path resolves correctly",
			pattern:     "path:$PROJECT_ROOT/**",
			input:       "../project/file.txt",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/other",
			want:        true,
		},
		{
			name:        "non-path-like string doesn't match",
			pattern:     "path:$PROJECT_ROOT/**",
			input:       "--flag",
			projectRoot: "/home/user/project",
			home:        "/home/user",
			cwd:         "/home/user/project",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePattern(tt.pattern)
			if err != nil {
				t.Fatalf("ParsePattern error: %v", err)
			}

			ctx := &MatchContext{
				PathVars: &pathutil.PathVars{
					ProjectRoot: tt.projectRoot,
					Home:        tt.home,
					Cwd:         tt.cwd,
				},
			}

			got := p.MatchWithContext(tt.input, ctx)
			if got != tt.want {
				t.Errorf("MatchWithContext(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestPathPatternWithoutContext(t *testing.T) {
	p, err := ParsePattern("path:$PROJECT_ROOT/**")
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}

	// Path patterns should return false without context
	if p.Match("./file.txt") {
		t.Error("path pattern should return false without context")
	}
}

func TestDoublestarGlobbing(t *testing.T) {
	// Test that ** works for recursive matching (via doublestar library)
	p, err := ParsePattern("src/**/*.go")
	if err != nil {
		t.Fatalf("ParsePattern error: %v", err)
	}

	if !p.Match("src/main.go") {
		t.Error("expected src/main.go to match")
	}

	if !p.Match("src/pkg/util.go") {
		t.Error("expected src/pkg/util.go to match")
	}

	if p.Match("test/main.go") {
		t.Error("expected test/main.go not to match")
	}
}
