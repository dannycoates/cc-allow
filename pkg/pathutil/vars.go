package pathutil

import (
	"os"
	"path/filepath"
	"strings"
)

// PathVars holds the variables available for path pattern expansion.
type PathVars struct {
	ProjectRoot string // detected project root
	Home        string // user's home directory
	Cwd         string // current working directory
	HomeSet     bool   // true if HOME was available
	PluginRoot  string // deprecated: backward compat for $CLAUDE_PLUGIN_ROOT
}

// NewPathVars creates PathVars with the current environment.
func NewPathVars(projectRoot string) *PathVars {
	home, err := os.UserHomeDir()
	homeSet := err == nil && home != ""
	cwd, _ := os.Getwd()

	// Backward compat: $CLAUDE_PLUGIN_ROOT derived from executable location
	// This variable is deprecated - use path:$HOME/.claude/plugins/** instead
	pluginRoot := detectPluginRoot(home)

	return &PathVars{
		ProjectRoot: projectRoot,
		Home:        home,
		Cwd:         cwd,
		HomeSet:     homeSet,
		PluginRoot:  pluginRoot,
	}
}

// detectPluginRoot determines the plugin root from the executable path.
// Returns empty string if not running from a plugin installation.
// Expected structure: $HOME/.claude/plugins/cache/<org>/<repo>/<version>/bin/cc-allow
func detectPluginRoot(home string) string {
	if home == "" {
		return ""
	}

	exe, err := os.Executable()
	if err != nil {
		return ""
	}

	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}

	// Check if executable is under the plugin cache
	cachePrefix := filepath.Join(home, ".claude", "plugins", "cache")
	if !strings.HasPrefix(exe, cachePrefix+string(filepath.Separator)) {
		return ""
	}

	// Go up from bin/cc-allow to plugin root
	// exe = .../cache/<org>/<repo>/<version>/bin/cc-allow
	binDir := filepath.Dir(exe)       // .../bin
	pluginRoot := filepath.Dir(binDir) // .../<version>

	return pluginRoot
}

// ExpandPattern expands variables in a path pattern string.
// Supported variables:
//   - $PROJECT_ROOT - the detected project root
//   - $HOME - user's home directory
//   - $CLAUDE_PLUGIN_ROOT - deprecated, expands to fixed path for backward compat
func (v *PathVars) ExpandPattern(pattern string) string {
	result := pattern

	// Expand $PROJECT_ROOT
	if v.ProjectRoot != "" {
		result = strings.ReplaceAll(result, "$PROJECT_ROOT", v.ProjectRoot)
	}

	// Expand $CLAUDE_PLUGIN_ROOT (deprecated, backward compat)
	if v.PluginRoot != "" {
		result = strings.ReplaceAll(result, "$CLAUDE_PLUGIN_ROOT", v.PluginRoot)
	}

	// Expand $HOME
	if v.Home != "" {
		result = strings.ReplaceAll(result, "$HOME", v.Home)
	}

	return result
}

// HasPathVars returns true if the pattern contains any path variables.
func HasPathVars(pattern string) bool {
	return strings.Contains(pattern, "$PROJECT_ROOT") ||
		strings.Contains(pattern, "$CLAUDE_PLUGIN_ROOT") ||
		strings.Contains(pattern, "$HOME")
}
