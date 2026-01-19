package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBuiltin(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		// POSIX special builtins
		{"break", true},
		{":", true},
		{".", true},
		{"continue", true},
		{"eval", true},
		{"exec", true},
		{"exit", true},
		{"export", true},
		{"return", true},
		{"set", true},
		{"shift", true},
		{"trap", true},
		{"unset", true},

		// POSIX regular builtins
		{"cd", true},
		{"pwd", true},
		{"true", true},
		{"false", true},
		{"read", true},
		{"type", true},
		{"alias", true},
		{"jobs", true},
		{"kill", true},

		// Bash-specific builtins
		{"source", true},
		{"declare", true},
		{"local", true},
		{"history", true},
		{"shopt", true},
		{"pushd", true},
		{"popd", true},

		// Reserved words
		{"if", true},
		{"then", true},
		{"else", true},
		{"fi", true},
		{"for", true},
		{"while", true},
		{"do", true},
		{"done", true},
		{"case", true},
		{"esac", true},
		{"[", true},
		{"[[", true},

		// Not builtins - external commands
		{"ls", false},
		{"cat", false},
		{"grep", false},
		{"git", false},
		{"rm", false},
		{"bash", false},
		{"echo", false}, // echo is external (though bash has a builtin version)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBuiltin(tc.name)
			if got != tc.expected {
				t.Errorf("IsBuiltin(%q) = %v, want %v", tc.name, got, tc.expected)
			}
		})
	}
}

func TestCommandResolver_Resolve_Builtin(t *testing.T) {
	resolver := NewCommandResolver(nil)

	tests := []string{"cd", "exit", "if", "[[", "source"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			result := resolver.Resolve(name)
			if !result.IsBuiltin {
				t.Errorf("Resolve(%q).IsBuiltin = false, want true", name)
			}
			if result.Path != "" {
				t.Errorf("Resolve(%q).Path = %q, want empty for builtin", name, result.Path)
			}
			if result.Unresolved {
				t.Errorf("Resolve(%q).Unresolved = true, want false for builtin", name)
			}
		})
	}
}

func TestCommandResolver_Resolve_AbsolutePath(t *testing.T) {
	// Create a temporary executable
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "myexec")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	resolver := NewCommandResolver(nil)

	// Test existing absolute path
	result := resolver.Resolve(exePath)
	if result.IsBuiltin {
		t.Error("Expected not builtin")
	}
	if result.Unresolved {
		t.Error("Expected resolved")
	}
	if result.Path != exePath {
		t.Errorf("Path = %q, want %q", result.Path, exePath)
	}

	// Test non-existent absolute path
	result = resolver.Resolve("/nonexistent/path/to/command")
	if !result.Unresolved {
		t.Error("Expected unresolved for non-existent path")
	}
}

func TestCommandResolver_Resolve_RelativePath(t *testing.T) {
	// Create a temporary executable
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "myexec")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	// Change to tmpDir so we can use relative path
	oldWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	resolver := NewCommandResolver(nil)

	// Test relative path ./myexec
	result := resolver.Resolve("./myexec")
	if result.IsBuiltin {
		t.Error("Expected not builtin")
	}
	if result.Unresolved {
		t.Error("Expected resolved")
	}
	if result.Path != exePath {
		t.Errorf("Path = %q, want %q", result.Path, exePath)
	}
}

func TestCommandResolver_Resolve_PathLookup(t *testing.T) {
	resolver := NewCommandResolver(nil)

	// Test looking up a common command (should exist on most systems)
	result := resolver.Resolve("ls")
	if result.IsBuiltin {
		t.Error("ls should not be a builtin")
	}
	if result.Unresolved {
		t.Error("ls should be resolved on most systems")
	}
	if result.Path == "" {
		t.Error("Expected non-empty path for ls")
	}
	if !filepath.IsAbs(result.Path) {
		t.Errorf("Expected absolute path, got %q", result.Path)
	}
}

func TestCommandResolver_Resolve_AllowedPaths(t *testing.T) {
	// Create a temporary directory with an executable
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "myexec")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create another directory without the executable
	emptyDir := t.TempDir()

	// Resolver with only the empty directory in allowed paths
	resolver := NewCommandResolver([]string{emptyDir})
	result := resolver.Resolve("myexec")
	if !result.Unresolved {
		t.Error("Expected unresolved when command not in allowed paths")
	}

	// Resolver with tmpDir in allowed paths
	resolver = NewCommandResolver([]string{tmpDir})
	result = resolver.Resolve("myexec")
	if result.Unresolved {
		t.Error("Expected resolved when command in allowed paths")
	}
	if result.Path != exePath {
		t.Errorf("Path = %q, want %q", result.Path, exePath)
	}
}

func TestCommandResolver_Caching(t *testing.T) {
	resolver := NewCommandResolver(nil)

	// Resolve the same command twice
	result1 := resolver.Resolve("ls")
	result2 := resolver.Resolve("ls")

	// Results should be identical
	if result1.Path != result2.Path {
		t.Errorf("Cached path mismatch: %q vs %q", result1.Path, result2.Path)
	}
	if result1.IsBuiltin != result2.IsBuiltin {
		t.Error("Cached IsBuiltin mismatch")
	}
	if result1.Unresolved != result2.Unresolved {
		t.Error("Cached Unresolved mismatch")
	}
}

func TestCommandResolver_Symlink(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the actual executable
	realPath := filepath.Join(tmpDir, "real_exec")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to it
	linkPath := filepath.Join(tmpDir, "linked_exec")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skip("symlinks not supported")
	}

	resolver := NewCommandResolver([]string{tmpDir})

	// Resolve the symlink
	result := resolver.Resolve("linked_exec")
	if result.Unresolved {
		t.Error("Expected symlink to resolve")
	}
	// The resolved path should be the real path, not the symlink
	if result.Path != realPath {
		t.Errorf("Expected symlink to resolve to real path %q, got %q", realPath, result.Path)
	}
}
