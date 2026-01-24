package pathutil

import (
	"os"
	"strings"
)

// PathVars holds the variables available for path pattern expansion.
type PathVars struct {
	ProjectRoot   string // detected project root
	PluginRoot    string // from CLAUDE_PLUGIN_ROOT env var
	Home          string // user's home directory
	Cwd           string // current working directory
	HomeSet       bool   // true if HOME was available
	PluginRootSet bool   // true if CLAUDE_PLUGIN_ROOT was set
}

// NewPathVars creates PathVars with the current environment.
func NewPathVars(projectRoot string) *PathVars {
	home, err := os.UserHomeDir()
	homeSet := err == nil && home != ""
	cwd, _ := os.Getwd()
	pluginRoot := os.Getenv("CLAUDE_PLUGIN_ROOT")
	return &PathVars{
		ProjectRoot:   projectRoot,
		PluginRoot:    pluginRoot,
		Home:          home,
		Cwd:           cwd,
		HomeSet:       homeSet,
		PluginRootSet: pluginRoot != "",
	}
}

// ExpandPattern expands variables in a path pattern string.
// Supported variables:
//   - $PROJECT_ROOT - the detected project root
//   - $CLAUDE_PLUGIN_ROOT - plugin root from environment variable
//   - $HOME - user's home directory
func (v *PathVars) ExpandPattern(pattern string) string {
	result := pattern

	// Expand $PROJECT_ROOT
	if v.ProjectRoot != "" {
		result = strings.ReplaceAll(result, "$PROJECT_ROOT", v.ProjectRoot)
	}

	// Expand $CLAUDE_PLUGIN_ROOT
	if v.PluginRoot != "" {
		result = strings.ReplaceAll(result, "$CLAUDE_PLUGIN_ROOT", v.PluginRoot)
	}

	// Expand $HOME
	if v.Home != "" {
		result = strings.ReplaceAll(result, "$HOME", v.Home)
	}

	return result
}
