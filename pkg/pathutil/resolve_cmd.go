package pathutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CommandResolver handles resolving command names to their absolute filesystem paths.
// It supports caching per evaluation, builtin detection, and configurable search paths.
type CommandResolver struct {
	allowedPaths []string          // paths to search for commands (defaults to $PATH)
	cache        map[string]string // cache of resolved paths
}

// ResolveResult represents the result of resolving a command name.
type ResolveResult struct {
	Path       string // absolute path to the command (empty if unresolved or builtin)
	IsBuiltin  bool   // true if this is a shell builtin
	Unresolved bool   // true if command could not be found
}

// NewCommandResolver creates a new CommandResolver.
// If allowedPaths is nil or empty, it falls back to using the system PATH.
func NewCommandResolver(allowedPaths []string) *CommandResolver {
	return &CommandResolver{
		allowedPaths: allowedPaths,
		cache:        make(map[string]string),
	}
}

// Resolve looks up a command name and returns its resolved information.
// The result is cached for the lifetime of this resolver.
func (r *CommandResolver) Resolve(name string) ResolveResult {
	// Check if it's a builtin first
	if IsBuiltin(name) {
		return ResolveResult{IsBuiltin: true}
	}

	// If the command is already an absolute path, just verify it exists
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return ResolveResult{Path: name}
		}
		return ResolveResult{Unresolved: true}
	}

	// If it's a relative path (contains / but not absolute), resolve it
	if strings.Contains(name, "/") {
		cwd, _ := os.Getwd()
		absPath := filepath.Join(cwd, name)
		absPath = filepath.Clean(absPath)
		if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
			if _, err := os.Stat(resolved); err == nil {
				return ResolveResult{Path: resolved}
			}
		}
		return ResolveResult{Unresolved: true}
	}

	// Check cache
	if cached, ok := r.cache[name]; ok {
		if cached == "" {
			return ResolveResult{Unresolved: true}
		}
		return ResolveResult{Path: cached}
	}

	// Look up the command
	path := r.lookPath(name)
	r.cache[name] = path

	if path == "" {
		return ResolveResult{Unresolved: true}
	}
	return ResolveResult{Path: path}
}

// lookPath searches for the command in the allowed paths or falls back to exec.LookPath.
func (r *CommandResolver) lookPath(name string) string {
	// If we have allowed paths, search them explicitly
	if len(r.allowedPaths) > 0 {
		for _, dir := range r.allowedPaths {
			// Expand variables in the allowed path
			expandedDir := os.ExpandEnv(dir)
			path := filepath.Join(expandedDir, name)
			if info, err := os.Stat(path); err == nil {
				// Check if it's executable
				if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
					// Resolve symlinks
					if resolved, err := filepath.EvalSymlinks(path); err == nil {
						return resolved
					}
					return path
				}
			}
		}
		return ""
	}

	// Fall back to exec.LookPath (uses $PATH)
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}

	// Resolve symlinks for security
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// IsBuiltin checks if a command name is a shell builtin or reserved word.
// These bypass path resolution entirely.
func IsBuiltin(name string) bool {
	_, ok := builtins[name]
	return ok
}

// builtins contains all bash builtins and reserved words.
// These commands are executed by the shell itself, not as external programs.
var builtins = map[string]struct{}{
	// POSIX special builtins
	"break":    {},
	":":        {},
	".":        {},
	"continue": {},
	"eval":     {},
	"exec":     {},
	"exit":     {},
	"export":   {},
	"readonly": {},
	"return":   {},
	"set":      {},
	"shift":    {},
	"times":    {},
	"trap":     {},
	"unset":    {},

	// POSIX regular builtins
	"alias":   {},
	"bg":      {},
	"cd":      {},
	"command": {},
	"false":   {},
	"fc":      {},
	"fg":      {},
	"getopts": {},
	"hash":    {},
	"jobs":    {},
	"kill":    {},
	"newgrp":  {},
	"pwd":     {},
	"read":    {},
	"true":    {},
	"type":    {},
	"ulimit":  {},
	"umask":   {},
	"unalias": {},
	"wait":    {},

	// Bash-specific builtins
	"bind":      {},
	"builtin":   {},
	"caller":    {},
	"compgen":   {},
	"complete":  {},
	"compopt":   {},
	"declare":   {},
	"dirs":      {},
	"disown":    {},
	"enable":    {},
	"help":      {},
	"history":   {},
	"let":       {},
	"local":     {},
	"logout":    {},
	"mapfile":   {},
	"popd":      {},
	"printf":    {},
	"pushd":     {},
	"readarray": {},
	"shopt":     {},
	"source":    {},
	"suspend":   {},
	"typeset":   {},

	// Reserved words (control flow, etc.)
	"if":       {},
	"then":     {},
	"else":     {},
	"elif":     {},
	"fi":       {},
	"case":     {},
	"esac":     {},
	"for":      {},
	"while":    {},
	"until":    {},
	"do":       {},
	"done":     {},
	"in":       {},
	"function": {},
	"select":   {},
	"time":     {},
	"coproc":   {},
	"[":        {},
	"[[":       {},
}
