package main

import (
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
