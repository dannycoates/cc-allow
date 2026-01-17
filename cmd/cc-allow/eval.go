package main

import (
	"path/filepath"
)

// Result represents the evaluation result.
type Result struct {
	Action  string // "allow", "deny", or "pass"
	Message string
	Command string // the command that caused denial (if any)
}

// Evaluator applies configuration rules to extracted commands.
type Evaluator struct {
	cfg *Config
}

// NewEvaluator creates a new evaluator with the given configuration.
func NewEvaluator(cfg *Config) *Evaluator {
	return &Evaluator{cfg: cfg}
}

// Evaluate checks all extracted info against the configuration.
func (e *Evaluator) Evaluate(info *ExtractedInfo) Result {
	// Check parse error
	if info.ParseError != nil {
		return Result{
			Action:  "deny",
			Message: "Parse error: " + info.ParseError.Error(),
		}
	}

	// Check constructs
	if result := e.checkConstructs(info); result.Action != "" {
		return result
	}

	// Check each command - collect results
	// If any command is denied, return deny immediately
	// If any command is explicitly allowed, track it
	// Otherwise, all commands pass through
	hasExplicitAllow := false

	for _, cmd := range info.Commands {
		result := e.evaluateCommand(cmd)
		switch result.Action {
		case "deny":
			return result
		case "allow":
			hasExplicitAllow = true
		}
		// "pass" continues to next command
	}

	// Check redirects
	for _, redir := range info.Redirects {
		result := e.evaluateRedirect(redir)
		switch result.Action {
		case "deny":
			return result
		case "allow":
			hasExplicitAllow = true
		}
	}

	// If any command/redirect was explicitly allowed, return allow
	if hasExplicitAllow {
		return Result{Action: "allow"}
	}

	// Otherwise pass through
	return Result{Action: "pass"}
}

// checkConstructs verifies shell constructs against policy.
func (e *Evaluator) checkConstructs(info *ExtractedInfo) Result {
	if info.Constructs.HasFunctionDefs {
		switch e.cfg.Constructs.FunctionDefinitions {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Function definitions are not allowed",
			}
		case "allow":
			// explicitly allowed, continue checking
		}
		// "pass" continues
	}

	if info.Constructs.HasBackground {
		switch e.cfg.Constructs.Background {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Background execution (&) is not allowed",
			}
		case "allow":
			// explicitly allowed, continue checking
		}
	}

	// No decision from constructs
	return Result{}
}

// evaluateCommand checks a single command against all rules.
func (e *Evaluator) evaluateCommand(cmd Command) Result {
	// Handle dynamic commands
	if cmd.IsDynamic {
		switch e.cfg.Policy.DynamicCommands {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic command names are not allowed",
				Command: cmd.Name,
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{Action: "pass"}
		}
	}

	// Check quick deny list
	if ContainsExact([]string{cmd.Name}, e.cfg.Commands.Deny.Names) {
		msg := e.cfg.Commands.Deny.Message
		if msg == "" {
			msg = e.cfg.Policy.DefaultMessage
		}
		return Result{
			Action:  "deny",
			Message: msg,
			Command: cmd.Name,
		}
	}

	// Check quick allow list (but still need to check rules for context)
	inAllowList := ContainsExact([]string{cmd.Name}, e.cfg.Commands.Allow.Names)

	// Evaluate detailed rules in order (first match wins)
	for _, rule := range e.cfg.Rules {
		if result, matched := e.matchRule(rule, cmd); matched {
			return result
		}
	}

	// If in allow list and no rule matched, allow
	if inAllowList {
		return Result{Action: "allow"}
	}

	// Use default policy
	return Result{
		Action:  e.cfg.Policy.Default,
		Message: e.cfg.Policy.DefaultMessage,
		Command: cmd.Name,
	}
}

// matchRule checks if a rule matches the command and returns the result.
// Returns (result, matched) where matched indicates if the rule applied.
func (e *Evaluator) matchRule(rule Rule, cmd Command) (Result, bool) {
	// Check command name match
	if rule.Command != "*" && rule.Command != cmd.Name {
		return Result{}, false
	}

	// Get arguments (excluding command name)
	args := cmd.Args
	if len(args) > 0 {
		args = args[1:]
	}

	// Check args.contains
	if len(rule.Args.Contains) > 0 {
		if !Contains(args, rule.Args.Contains) {
			return Result{}, false
		}
	}

	// Check args.any_match
	if len(rule.Args.AnyMatch) > 0 {
		matcher, err := NewMatcher(rule.Args.AnyMatch)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AnyMatch(args) {
			return Result{}, false
		}
	}

	// Check args.all_match
	if len(rule.Args.AllMatch) > 0 {
		matcher, err := NewMatcher(rule.Args.AllMatch)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AllMatch(args) {
			return Result{}, false
		}
	}

	// Check args.position
	for pos, pattern := range rule.Args.Position {
		if !MatchPosition(args, pos, pattern) {
			return Result{}, false
		}
	}

	// Check pipe.to context
	if len(rule.Pipe.To) > 0 {
		// This rule only matches if the command pipes to a restricted target
		pipesToRestricted := false
		for _, pipeDest := range cmd.PipesTo {
			if ContainsExact([]string{pipeDest}, rule.Pipe.To) {
				pipesToRestricted = true
				break
			}
		}
		if !pipesToRestricted {
			return Result{}, false
		}
	}

	// Rule matched - return the action
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.cfg.Policy.DefaultMessage
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
		Command: cmd.Name,
	}, true
}

// evaluateRedirect checks a redirect against redirect rules.
func (e *Evaluator) evaluateRedirect(redir Redirect) Result {
	// Dynamic redirects
	if redir.IsDynamic {
		switch e.cfg.Policy.DynamicCommands {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic redirect targets are not allowed",
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{Action: "pass"}
		}
	}

	// Evaluate redirect rules in order
	for _, rule := range e.cfg.Redirects {
		if result, matched := e.matchRedirectRule(rule, redir); matched {
			return result
		}
	}

	// No rule matched - pass through
	return Result{Action: "pass"}
}

// matchRedirectRule checks if a redirect rule matches.
func (e *Evaluator) matchRedirectRule(rule RedirectRule, redir Redirect) (Result, bool) {
	// Check append mode filter
	if rule.Append != nil {
		if *rule.Append != redir.Append {
			return Result{}, false
		}
	}

	// Check exact matches
	if len(rule.To.Exact) > 0 {
		// Match against basename for convenience
		basename := filepath.Base(redir.Target)
		if !ContainsExact([]string{redir.Target, basename}, rule.To.Exact) {
			return Result{}, false
		}
	}

	// Check pattern matches
	if len(rule.To.Pattern) > 0 {
		matcher, err := NewMatcher(rule.To.Pattern)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AnyMatch([]string{redir.Target}) {
			return Result{}, false
		}
	}

	// Rule matched
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.cfg.Policy.DefaultMessage
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
	}, true
}
