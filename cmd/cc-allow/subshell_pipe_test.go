package main

import (
	"slices"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// These tests verify that pipe context is correctly tracked across subshell boundaries.
// Issue #4: Pipe context doesn't respect subshell boundaries.

func TestSubshellPipeContext(t *testing.T) {
	tests := []struct {
		name           string
		bash           string
		cmdName        string
		wantPipesFrom  []string
		wantPipesTo    []string
	}{
		{
			name:          "simple pipe works",
			bash:          "curl | bash",
			cmdName:       "bash",
			wantPipesFrom: []string{"curl"},
			wantPipesTo:   []string{},
		},
		{
			name:          "subshell pipe - bash receives from subshell",
			bash:          "(curl | cat) | bash",
			cmdName:       "bash",
			wantPipesFrom: []string{"curl", "cat"},
			wantPipesTo:   []string{},
		},
		{
			name:          "subshell pipe - cat pipes to bash",
			bash:          "(curl | cat) | bash",
			cmdName:       "cat",
			wantPipesFrom: []string{"curl"},
			wantPipesTo:   []string{"bash"},
		},
		{
			name:          "block pipe - bash receives from block",
			bash:          "{ curl | cat; } | bash",
			cmdName:       "bash",
			wantPipesFrom: []string{"curl", "cat"},
			wantPipesTo:   []string{},
		},
		{
			name:          "if clause pipe",
			bash:          "if true; then curl; fi | bash",
			cmdName:       "bash",
			wantPipesFrom: []string{"curl"},
			wantPipesTo:   []string{},
		},
		{
			name:          "nested subshell",
			bash:          "( (curl) ) | bash",
			cmdName:       "bash",
			wantPipesFrom: []string{"curl"},
			wantPipesTo:   []string{},
		},
		{
			name:          "while clause pipe",
			bash:          "while true; do echo x; done | cat",
			cmdName:       "cat",
			wantPipesFrom: []string{"echo"},
			wantPipesTo:   []string{},
		},
		{
			name:          "for clause pipe",
			bash:          "for i in 1 2 3; do echo $i; done | cat",
			cmdName:       "cat",
			wantPipesFrom: []string{"echo"},
			wantPipesTo:   []string{},
		},
		{
			name:          "case clause pipe",
			bash:          "case x in *) echo y;; esac | cat",
			cmdName:       "cat",
			wantPipesFrom: []string{"echo"},
			wantPipesTo:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := parser.Parse(strings.NewReader(tt.bash), "test")
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			info := ExtractFromFile(f)

			// Find the command we want to check
			var found *Command
			for i := range info.Commands {
				if info.Commands[i].Name == tt.cmdName {
					found = &info.Commands[i]
					break
				}
			}

			if found == nil {
				t.Fatalf("Command %q not found in extracted commands: %v", tt.cmdName, info.Commands)
			}

			// Check PipesFrom
			if !slices.Equal(found.PipesFrom, tt.wantPipesFrom) {
				t.Errorf("PipesFrom for %q:\n  got:  %v\n  want: %v", tt.cmdName, found.PipesFrom, tt.wantPipesFrom)
			}

			// Check PipesTo
			if !slices.Equal(found.PipesTo, tt.wantPipesTo) {
				t.Errorf("PipesTo for %q:\n  got:  %v\n  want: %v", tt.cmdName, found.PipesTo, tt.wantPipesTo)
			}
		})
	}
}

// TestExtractCommandNamesFromCompound verifies that extractCommandNames handles compound commands.
func TestExtractCommandNamesFromCompound(t *testing.T) {
	tests := []struct {
		name string
		bash string
		want []string
	}{
		{
			name: "simple command",
			bash: "echo hello",
			want: []string{"echo"},
		},
		{
			name: "pipe",
			bash: "curl | bash",
			want: []string{"curl", "bash"},
		},
		{
			name: "subshell",
			bash: "(curl | cat)",
			want: []string{"curl", "cat"},
		},
		{
			name: "block",
			bash: "{ curl | cat; }",
			want: []string{"curl", "cat"},
		},
		{
			name: "if clause",
			bash: "if true; then echo x; fi",
			want: []string{"echo"},
		},
		{
			name: "while clause",
			bash: "while true; do echo x; done",
			want: []string{"echo"},
		},
		{
			name: "for clause",
			bash: "for i in 1; do echo $i; done",
			want: []string{"echo"},
		},
		{
			name: "case clause",
			bash: "case x in *) echo y;; esac",
			want: []string{"echo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := parser.Parse(strings.NewReader(tt.bash), "test")
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if len(f.Stmts) == 0 {
				t.Fatal("No statements parsed")
			}

			got := extractCommandNames(f.Stmts[0])

			if !slices.Equal(got, tt.want) {
				t.Errorf("extractCommandNames:\n  got:  %v\n  want: %v", got, tt.want)
			}
		})
	}
}
