package main

import "fmt"

// Action represents a permission decision: allow, deny, or ask.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAsk   Action = "ask"
)

// IsValid reports whether a is a recognized action.
func (a Action) IsValid() bool {
	switch a {
	case ActionAllow, ActionDeny, ActionAsk:
		return true
	}
	return false
}

// String returns the string representation of the action.
func (a Action) String() string {
	return string(a)
}

// Priority returns the strictness priority (deny=2 > ask=1 > allow=0).
// Used for tie-breaking when multiple rules match.
func (a Action) Priority() int {
	switch a {
	case ActionDeny:
		return 2
	case ActionAsk:
		return 1
	case ActionAllow:
		return 0
	default:
		return -1
	}
}

// ToolName identifies a Claude Code tool type.
type ToolName string

const (
	ToolBash     ToolName = "Bash"
	ToolRead     ToolName = "Read"
	ToolWrite    ToolName = "Write"
	ToolEdit     ToolName = "Edit"
	ToolWebFetch ToolName = "WebFetch"
	ToolGlob     ToolName = "Glob"
	ToolGrep     ToolName = "Grep"
)

// ExitCode represents the process exit code for a permission decision.
type ExitCode int

const (
	ExitAllow ExitCode = 0 // Success, command explicitly allowed
	ExitAsk   ExitCode = 1 // Non-blocking, ask user via Claude Code's default behavior
	ExitDeny  ExitCode = 2 // Blocking error, command explicitly denied
	ExitError ExitCode = 3 // Processing error (parse failure, config error, etc.)
)

// ExitCode returns the process exit code corresponding to this action.
func (a Action) ExitCode() ExitCode {
	switch a {
	case ActionAllow:
		return ExitAllow
	case ActionDeny:
		return ExitDeny
	case ActionAsk:
		return ExitAsk
	default:
		return ExitError
	}
}

// ParseAction converts a raw string (from TOML) to an Action.
// Returns an error with context if the string is non-empty and not a valid action.
func ParseAction(s, field string) (Action, error) {
	if s == "" {
		return "", nil
	}
	a := Action(s)
	if !a.IsValid() {
		return "", &ConfigValidationError{
			Location: field,
			Value:    s,
			Message:  fmt.Sprintf("invalid action (must be %q, %q, or %q)", ActionAllow, ActionDeny, ActionAsk),
		}
	}
	return a, nil
}
