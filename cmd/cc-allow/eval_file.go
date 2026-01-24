package main

import (
	"path/filepath"
	"strings"

	"cc-allow/pkg/pathutil"
)

// evaluateFileTool checks a file tool request against the merged configuration.
// Returns allow, deny, or ask based on matching patterns.
func evaluateFileTool(chain *ConfigChain, toolName, filePath string) Result {
	if chain.Merged == nil {
		return Result{Action: "ask", Source: "no configuration loaded"}
	}

	merged := chain.Merged

	// Set up path resolution context
	projectRoot := findProjectRoot()
	pathVars := pathutil.NewPathVars(projectRoot)
	matchCtx := &MatchContext{PathVars: pathVars}

	// Resolve the file path to absolute
	absPath := resolveFilePath(filePath, pathVars)
	logDebug("  Resolved path: %q -> %q", filePath, absPath)

	return checkFilePathAgainstRules(merged, toolName, absPath, matchCtx)
}

// checkFilePathAgainstRules checks an absolute file path against file rules.
// This is the core file rule checking logic, usable for both file tools and command args.
// toolName should be "Read", "Write", or "Edit".
func checkFilePathAgainstRules(merged *MergedConfig, toolName, absPath string, matchCtx *MatchContext) Result {
	// 1. Check deny lists first (deny always wins)
	if result, ok := checkFileDenyList(merged, toolName, absPath, matchCtx); ok {
		return result
	}

	// 2. Check allow lists
	if result, ok := checkFileAllowList(merged, toolName, absPath, matchCtx); ok {
		return result
	}

	// 3. Use default policy
	defaultAction := merged.Files.Default.Value
	return Result{
		Action: defaultAction,
		Source: merged.Files.Default.Source + ": files.default",
	}
}

// resolveFilePath converts a file path to an absolute path.
func resolveFilePath(filePath string, pathVars *pathutil.PathVars) string {
	if filepath.IsAbs(filePath) {
		return filepath.Clean(filePath)
	}
	// Relative path - resolve from cwd
	return filepath.Clean(filepath.Join(pathVars.Cwd, filePath))
}

// checkFileDenyList checks if the path matches any deny patterns for the tool.
func checkFileDenyList(merged *MergedConfig, toolName, absPath string, matchCtx *MatchContext) (Result, bool) {
	entries := merged.Files.Deny[toolName]
	for _, entry := range entries {
		if matchFilePattern(entry.Pattern, absPath, matchCtx) {
			msg := entry.Message
			if msg == "" {
				msg = "File access denied"
			}
			return Result{
				Action:  "deny",
				Message: msg,
				Source:  entry.Source + ": files." + strings.ToLower(toolName) + ".deny",
			}, true
		}
	}
	return Result{}, false
}

// checkFileAllowList checks if the path matches any allow patterns for the tool.
func checkFileAllowList(merged *MergedConfig, toolName, absPath string, matchCtx *MatchContext) (Result, bool) {
	entries := merged.Files.Allow[toolName]
	for _, entry := range entries {
		if matchFilePattern(entry.Pattern, absPath, matchCtx) {
			return Result{
				Action: "allow",
				Source: entry.Source + ": files." + strings.ToLower(toolName) + ".allow",
			}, true
		}
	}
	return Result{}, false
}

// matchFilePattern checks if a path matches a pattern string.
func matchFilePattern(pattern, absPath string, matchCtx *MatchContext) bool {
	p, err := ParsePattern(pattern)
	if err != nil {
		logDebug("  Pattern parse error for %q: %v", pattern, err)
		return false
	}
	return p.MatchWithContext(absPath, matchCtx)
}
