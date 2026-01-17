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

// combineActions merges two actions following these rules:
// - deny always wins (any config can deny, and it can't be undone)
// - allow is preserved unless denied (pass doesn't override allow)
// - pass means "no opinion" and defers to the other action
func combineActions(current, new string) string {
	// If already denied, stay denied (deny is sticky)
	if current == "deny" {
		return "deny"
	}
	// New deny overrides anything
	if new == "deny" {
		return "deny"
	}
	// If current is allow and new is pass, keep allow (pass doesn't override)
	if current == "allow" && new == "pass" {
		return "allow"
	}
	// If current is pass and new is allow, become allow
	if current == "pass" && new == "allow" {
		return "allow"
	}
	// Both same, or both pass
	return current
}

// combineResults merges two results, keeping the message from the stricter action.
func combineResults(current, new Result) Result {
	combined := combineActions(current.Action, new.Action)

	// Keep the message from whichever result determined the action
	if combined == "deny" {
		if new.Action == "deny" {
			return new
		}
		return current
	}
	if combined == "allow" {
		if new.Action == "allow" {
			return new
		}
		return current
	}
	// Both pass
	return Result{Action: "pass"}
}

// Evaluator applies configuration rules to extracted commands.
type Evaluator struct {
	chain *ConfigChain
}

// NewEvaluator creates a new evaluator with the given configuration chain.
func NewEvaluator(chain *ConfigChain) *Evaluator {
	return &Evaluator{chain: chain}
}

// NewEvaluatorSingle creates an evaluator from a single config (for backwards compatibility).
func NewEvaluatorSingle(cfg *Config) *Evaluator {
	return &Evaluator{chain: &ConfigChain{Configs: []*Config{cfg}}}
}

// Evaluate checks all extracted info against all configurations.
// Combines results: deny wins over all, allow preserved unless denied, pass is neutral.
func (e *Evaluator) Evaluate(info *ExtractedInfo) Result {
	// Check parse error
	if info.ParseError != nil {
		return Result{
			Action:  "deny",
			Message: "Parse error: " + info.ParseError.Error(),
		}
	}

	// Track overall result across all configs
	overallResult := Result{Action: "pass"} // start with "no opinion"

	// Evaluate against each config, combining results
	for _, cfg := range e.chain.Configs {
		result := e.evaluateWithConfig(cfg, info)
		overallResult = combineResults(overallResult, result)

		// Early exit: if already denied, no point checking more configs
		if overallResult.Action == "deny" {
			return overallResult
		}
	}

	return overallResult
}

// evaluateWithConfig evaluates info against a single config.
// Within a single config: deny beats all, then allow beats pass.
func (e *Evaluator) evaluateWithConfig(cfg *Config, info *ExtractedInfo) Result {
	// Check constructs
	if result := e.checkConstructsWithConfig(cfg, info); result.Action == "deny" {
		return result
	}

	// Track whether any command/redirect was explicitly allowed
	hasExplicitAllow := false

	// Check each command
	for _, cmd := range info.Commands {
		cmdResult := e.evaluateCommandWithConfig(cfg, cmd)
		switch cmdResult.Action {
		case "deny":
			return cmdResult // deny beats all
		case "allow":
			hasExplicitAllow = true
		}
		// "pass" continues to next command
	}

	// Check redirects
	for _, redir := range info.Redirects {
		redirResult := e.evaluateRedirectWithConfig(cfg, redir)
		switch redirResult.Action {
		case "deny":
			return redirResult
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

// checkConstructsWithConfig verifies shell constructs against a single config's policy.
func (e *Evaluator) checkConstructsWithConfig(cfg *Config, info *ExtractedInfo) Result {
	if info.Constructs.HasFunctionDefs {
		switch cfg.Constructs.FunctionDefinitions {
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
		switch cfg.Constructs.Background {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Background execution (&) is not allowed",
			}
		case "allow":
			// explicitly allowed, continue checking
		}
	}

	// No denial from constructs
	return Result{Action: "pass"}
}

// evaluateCommandWithConfig checks a single command against a single config's rules.
func (e *Evaluator) evaluateCommandWithConfig(cfg *Config, cmd Command) Result {
	// Handle dynamic commands
	if cmd.IsDynamic {
		switch cfg.Policy.DynamicCommands {
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
	if ContainsExact([]string{cmd.Name}, cfg.Commands.Deny.Names) {
		msg := cfg.Commands.Deny.Message
		if msg == "" {
			msg = cfg.Policy.DefaultMessage
		}
		return Result{
			Action:  "deny",
			Message: msg,
			Command: cmd.Name,
		}
	}

	// Check quick allow list (but still need to check rules for context)
	inAllowList := ContainsExact([]string{cmd.Name}, cfg.Commands.Allow.Names)

	// Evaluate detailed rules in order (first match wins)
	for _, rule := range cfg.Rules {
		if result, matched := e.matchRuleWithConfig(cfg, rule, cmd); matched {
			return result
		}
	}

	// If in allow list and no rule matched, allow
	if inAllowList {
		return Result{Action: "allow"}
	}

	// Use default policy
	return Result{
		Action:  cfg.Policy.Default,
		Message: cfg.Policy.DefaultMessage,
		Command: cmd.Name,
	}
}

// matchRuleWithConfig checks if a rule matches the command and returns the result.
// Returns (result, matched) where matched indicates if the rule applied.
func (e *Evaluator) matchRuleWithConfig(cfg *Config, rule Rule, cmd Command) (Result, bool) {
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

	// Check pipe.from context
	if len(rule.Pipe.From) > 0 {
		// This rule only matches if the command receives from a restricted source
		receivesFromRestricted := false

		// Check for wildcard "*" - matches any piped input
		if ContainsExact([]string{"*"}, rule.Pipe.From) {
			// If command has ANY upstream commands, it matches
			if len(cmd.PipesFrom) > 0 {
				receivesFromRestricted = true
			}
		} else {
			// Check if any upstream command is in the restricted list
			for _, pipeSource := range cmd.PipesFrom {
				if ContainsExact([]string{pipeSource}, rule.Pipe.From) {
					receivesFromRestricted = true
					break
				}
			}
		}
		if !receivesFromRestricted {
			return Result{}, false
		}
	}

	// Rule matched - return the action
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = cfg.Policy.DefaultMessage
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
		Command: cmd.Name,
	}, true
}

// evaluateRedirectWithConfig checks a redirect against a single config's rules.
func (e *Evaluator) evaluateRedirectWithConfig(cfg *Config, redir Redirect) Result {
	// Dynamic redirects
	if redir.IsDynamic {
		switch cfg.Policy.DynamicCommands {
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
	for _, rule := range cfg.Redirects {
		if result, matched := e.matchRedirectRuleWithConfig(cfg, rule, redir); matched {
			return result
		}
	}

	// No rule matched - pass through
	return Result{Action: "pass"}
}

// matchRedirectRuleWithConfig checks if a redirect rule matches.
func (e *Evaluator) matchRedirectRuleWithConfig(cfg *Config, rule RedirectRule, redir Redirect) (Result, bool) {
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
		msg = cfg.Policy.DefaultMessage
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
	}, true
}
