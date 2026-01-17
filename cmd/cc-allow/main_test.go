package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func extractCommands(f *syntax.File) []string {
	var commands []string
	syntax.Walk(f, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			if len(call.Args) > 0 {
				cmd := wordToString(call.Args[0])
				commands = append(commands, cmd)
			}
		}
		return true
	})
	return commands
}

func parseFile(path string) (*syntax.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	return parser.Parse(f, path)
}

func TestSimple(t *testing.T) {
	f, err := parseFile("testdata/simple.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"echo", "ls"}
	assertCommands(t, expected, commands)
}

func TestPipeline(t *testing.T) {
	f, err := parseFile("testdata/pipeline.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"cat", "grep", "sort", "uniq"}
	assertCommands(t, expected, commands)
}

func TestConditionals(t *testing.T) {
	f, err := parseFile("testdata/conditionals.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"echo", "ls", "pwd", "true", "cat"}
	assertCommands(t, expected, commands)
}

func TestLoops(t *testing.T) {
	f, err := parseFile("testdata/loops.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"echo", "sleep", "true", "date", "break"}
	assertCommands(t, expected, commands)
}

func TestSubshell(t *testing.T) {
	f, err := parseFile("testdata/subshell.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"cat", "grep", "cd", "ls"}
	assertCommands(t, expected, commands)
}

func TestVariables(t *testing.T) {
	f, err := parseFile("testdata/variables.bash")
	if err != nil {
		t.Fatal(err)
	}
	commands := extractCommands(f)
	expected := []string{"$CMD", "$PROGRAM", "$SHELL"}
	assertCommands(t, expected, commands)
}

func TestAllFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/*.bash")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no test fixtures found")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			f, err := parseFile(file)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", file, err)
			}
			commands := extractCommands(f)
			if len(commands) == 0 {
				t.Errorf("no commands extracted from %s", file)
			}
			t.Logf("commands: %v", commands)
		})
	}
}

func assertCommands(t *testing.T, expected, actual []string) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Errorf("expected %d commands %v, got %d commands %v",
			len(expected), expected, len(actual), actual)
		return
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("command %d: expected %q, got %q", i, expected[i], actual[i])
		}
	}
}

func TestWordToString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"echo", "echo"},
		{"$VAR", "$VAR"},
		{"'literal'", "literal"},
		{`"quoted"`, "quoted"},
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			f, err := parser.Parse(strings.NewReader(tt.input+" arg"), "test")
			if err != nil {
				t.Fatal(err)
			}
			commands := extractCommands(f)
			if len(commands) != 1 {
				t.Fatalf("expected 1 command, got %d", len(commands))
			}
			if commands[0] != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, commands[0])
			}
		})
	}
}
