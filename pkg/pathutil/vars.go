package pathutil

import (
	"os"
	"strings"
)

// PathVars holds the variables available for path pattern expansion.
type PathVars struct {
	ProjectRoot string // detected project root
	Home        string // user's home directory
	Cwd         string // current working directory
}

// NewPathVars creates PathVars with the current environment.
func NewPathVars(projectRoot string) *PathVars {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	return &PathVars{
		ProjectRoot: projectRoot,
		Home:        home,
		Cwd:         cwd,
	}
}

// ExpandPattern expands variables in a path pattern string.
// Supported variables:
//   - $PROJECT_ROOT - the detected project root
//   - $HOME - user's home directory
func (v *PathVars) ExpandPattern(pattern string) string {
	result := pattern

	// Expand $PROJECT_ROOT
	if v.ProjectRoot != "" {
		result = strings.ReplaceAll(result, "$PROJECT_ROOT", v.ProjectRoot)
	}

	// Expand $HOME
	if v.Home != "" {
		result = strings.ReplaceAll(result, "$HOME", v.Home)
	}

	return result
}
