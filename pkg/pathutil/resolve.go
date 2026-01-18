package pathutil

import (
	"path/filepath"
	"strings"
)

// ResolvePath resolves a path argument to an absolute path.
// It handles:
//   - ~ expansion to home directory
//   - Relative path resolution against cwd
//   - Path normalization (cleaning . and ..)
//   - Symlink resolution for security
//
// For paths that don't exist, it resolves the deepest existing ancestor
// and appends the remaining components.
func ResolvePath(path, cwd, home string) string {
	if path == "" {
		return ""
	}

	// Expand ~ to home directory
	if path == "~" {
		path = home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, path[2:])
	}

	// Make absolute relative to cwd
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}

	// Clean the path (normalize . and ..)
	path = filepath.Clean(path)

	// Try to resolve symlinks for security
	// This prevents escaping via symlinks
	resolved, err := resolveWithSymlinks(path)
	if err == nil {
		return resolved
	}

	// If path doesn't exist, resolve as much as we can
	return resolveNonExistent(path)
}

// resolveWithSymlinks attempts to resolve all symlinks in a path.
func resolveWithSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

// resolveNonExistent handles paths where part of the path doesn't exist.
// It resolves the deepest existing ancestor and appends the remaining path.
func resolveNonExistent(path string) string {
	// Find the deepest existing ancestor
	current := path
	var remaining []string

	for current != "/" && current != "." {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			// Found existing ancestor - rebuild path from here
			for i := len(remaining) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, remaining[i])
			}
			return resolved
		}

		// Move up one directory
		remaining = append(remaining, filepath.Base(current))
		current = filepath.Dir(current)
	}

	// No existing ancestor found, return cleaned original
	return filepath.Clean(path)
}

// IsPathLike checks if a string looks like a filesystem path.
// Used to heuristically detect path arguments.
func IsPathLike(s string) bool {
	if s == "" {
		return false
	}

	// Starts with path indicators
	if strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/") ||
		s == "~" ||
		s == "." ||
		s == ".." {
		return true
	}

	// Contains path separator (but not just flags like --foo/bar which would be unusual)
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "-") {
		return true
	}

	return false
}
