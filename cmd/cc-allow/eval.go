package main

import (
	"path/filepath"
	"sort"
	"strconv"
)

// Result represents the evaluation result.
type Result struct {
	Action  string // "allow", "deny", or "ask"
	Message string
	Command string // the command that triggered this result (if any)
	Source  string // describes what triggered this result (for debugging)
}

// combineActionsStrict merges two actions with strictness order: deny > ask > allow
// Used when combining multiple commands within a single config - if ANY command
// needs user confirmation, the whole thing should ask.
func combineActionsStrict(current, new string) string {
	// deny is strictest
	if current == "deny" || new == "deny" {
		return "deny"
	}
	// ask is next strictest
	if current == "ask" || new == "ask" {
		return "ask"
	}
	// both allow
	return "allow"
}

// combineActionsAcrossConfigs merges actions from different configs.
// "ask" means "no opinion" and defers to explicit decisions from other configs.
// deny > allow > ask
func combineActionsAcrossConfigs(current, new string) string {
	// deny always wins
	if current == "deny" || new == "deny" {
		return "deny"
	}
	// allow wins over ask (ask means "no opinion")
	if current == "allow" || new == "allow" {
		return "allow"
	}
	// both ask
	return "ask"
}

// combineResults merges two results using strict ordering (for within-config use).
// Keeps all fields from whichever result determined the action.
func combineResults(current, new Result) Result {
	combined := combineActionsStrict(current.Action, new.Action)

	// Return the result that determined the combined action (preserves all fields)
	if combined == "deny" {
		if new.Action == "deny" {
			return new
		}
		return current
	}
	if combined == "ask" {
		if new.Action == "ask" {
			return new
		}
		return current
	}
	// Both allow - prefer new if it has more info
	if new.Action == "allow" {
		return new
	}
	return current
}

// combineResultsAcrossConfigs merges results from different configs.
// "ask" is treated as "no opinion" and defers to explicit allow.
func combineResultsAcrossConfigs(current, new Result) Result {
	combined := combineActionsAcrossConfigs(current.Action, new.Action)

	// Return the result that determined the combined action (preserves all fields)
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
	// Both ask - prefer the one with more info (Source set)
	if new.Source != "" {
		return new
	}
	return current
}

// actionPriority returns a priority value for tie-breaking when rules have equal specificity.
// Higher values win. Order: deny (2) > ask (1) > allow (0)
func actionPriority(action string) int {
	switch action {
	case "deny":
		return 2
	case "ask":
		return 1
	default:
		return 0
	}
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
// Combines results: deny wins over all, allow preserved unless denied, ask is neutral.
func (e *Evaluator) Evaluate(info *ExtractedInfo) Result {
	// Check parse error
	if info.ParseError != nil {
		return Result{
			Action:  "deny",
			Message: "Parse error: " + info.ParseError.Error(),
		}
	}

	// Track overall result across all configs
	overallResult := Result{Action: "ask"} // start with no decision, configs provide decisions

	// Evaluate against each config, combining results
	for _, cfg := range e.chain.Configs {
		result := e.evaluateWithConfig(cfg, info)
		overallResult = combineResultsAcrossConfigs(overallResult, result)

		// Early exit: if already denied, no point checking more configs
		if overallResult.Action == "deny" {
			return overallResult
		}
	}

	return overallResult
}

// evaluateWithConfig evaluates info against a single config.
// Strictness order: deny > ask > allow. All commands must be allowed for allow result.
func (e *Evaluator) evaluateWithConfig(cfg *Config, info *ExtractedInfo) Result {
	// Check constructs first (can deny or ask)
	constructResult := e.checkConstructsWithConfig(cfg, info)
	if constructResult.Action == "deny" {
		return constructResult
	}

	// Track the strictest result seen (deny > ask > allow)
	result := Result{Action: "allow"}

	// If constructs returned "ask", that's our starting point
	if constructResult.Action == "ask" {
		result = constructResult
	}

	// Check each command
	for _, cmd := range info.Commands {
		cmdResult := e.evaluateCommandWithConfig(cfg, cmd)
		result = combineResults(result, cmdResult)
		if result.Action == "deny" {
			return result // early exit on deny
		}
	}

	// Check redirects
	for _, redir := range info.Redirects {
		redirResult := e.evaluateRedirectWithConfig(cfg, redir)
		result = combineResults(result, redirResult)
		if result.Action == "deny" {
			return result // early exit on deny
		}
	}

	// Check heredocs (only if constructs.heredocs != "deny", which already returned above)
	// If constructs.heredocs = "allow", check [[heredoc]] rules for fine-grained control
	if cfg.Constructs.Heredocs == "allow" {
		for _, hdoc := range info.Heredocs {
			hdocResult := e.evaluateHeredocWithConfig(cfg, hdoc)
			result = combineResults(result, hdocResult)
			if result.Action == "deny" {
				return result // early exit on deny
			}
		}
	}

	// If no actual runnable commands, ask - don't auto-allow
	// (Function definitions define but don't execute; background is just a modifier)
	if len(info.Commands) == 0 && len(info.Redirects) == 0 && len(info.Heredocs) == 0 {
		return Result{Action: "ask", Source: "no executable commands in input"}
	}

	return result
}

// checkConstructsWithConfig verifies shell constructs against a single config's policy.
func (e *Evaluator) checkConstructsWithConfig(cfg *Config, info *ExtractedInfo) Result {
	// Start with allow - only change if there's an issue
	result := Result{Action: "allow"}

	if info.Constructs.HasFunctionDefs {
		switch cfg.Constructs.FunctionDefinitions {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Function definitions are not allowed",
				Source:  cfg.Path + ": constructs.function_definitions=deny",
			}
		case "ask":
			result = Result{
				Action:  "ask",
				Message: "Function definitions need approval",
				Source:  cfg.Path + ": constructs.function_definitions=ask",
			}
		}
		// "allow" continues checking
	}

	if info.Constructs.HasBackground {
		switch cfg.Constructs.Background {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Background execution (&) is not allowed",
				Source:  cfg.Path + ": constructs.background=deny",
			}
		case "ask":
			result = combineResults(result, Result{
				Action:  "ask",
				Message: "Background execution needs approval",
				Source:  cfg.Path + ": constructs.background=ask",
			})
		}
	}

	if info.Constructs.HasHeredocs {
		switch cfg.Constructs.Heredocs {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Heredocs are not allowed",
				Source:  cfg.Path + ": constructs.heredocs=deny",
			}
		case "ask":
			result = combineResults(result, Result{
				Action:  "ask",
				Message: "Heredocs need approval",
				Source:  cfg.Path + ": constructs.heredocs=ask",
			})
		}
		// "allow" continues to check [[heredoc]] rules
	}

	return result
}

// evaluateCommandWithConfig checks a single command against a single config's rules.
func (e *Evaluator) evaluateCommandWithConfig(cfg *Config, cmd Command) Result {
	logDebug("  Evaluating command %q", cmd.Name)

	// Handle dynamic commands
	if cmd.IsDynamic {
		logDebug("    Command is dynamic, policy.dynamic_commands=%s", cfg.Policy.DynamicCommands)
		switch cfg.Policy.DynamicCommands {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic command names are not allowed",
				Command: cmd.Name,
				Source:  cfg.Path + ": dynamic command",
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{
				Action:  "ask",
				Command: cmd.Name,
				Source:  cfg.Path + ": dynamic command requires approval",
			}
		}
	}

	// Check quick deny list
	if ContainsExact([]string{cmd.Name}, cfg.Commands.Deny.Names) {
		logDebug("    Matched commands.deny.names")
		msg := cfg.Commands.Deny.Message
		if msg == "" {
			msg = cfg.Policy.DefaultMessage
		}
		return Result{
			Action:  "deny",
			Message: msg,
			Command: cmd.Name,
			Source:  cfg.Path + ": commands.deny.names",
		}
	}

	// Check quick allow list (but still need to check rules for context)
	inAllowList := ContainsExact([]string{cmd.Name}, cfg.Commands.Allow.Names)
	if inAllowList {
		logDebug("    In commands.allow.names (checking rules for context)")
	}

	// Collect all matching rules with their specificity scores
	type ruleMatch struct {
		index       int
		rule        Rule
		specificity int
		result      Result
	}
	var matches []ruleMatch

	for i, rule := range cfg.Rules {
		if result, matched := e.matchRuleWithConfig(cfg, rule, cmd); matched {
			spec := rule.Specificity()
			logDebug("    Rule[%d] matched: command=%q action=%s specificity=%d", i, rule.Command, rule.Action, spec)
			matches = append(matches, ruleMatch{
				index:       i,
				rule:        rule,
				specificity: spec,
				result:      result,
			})
		}
	}

	// If we have matches, pick the most specific one
	// Tie-break: deny > ask > allow (most restrictive wins)
	if len(matches) > 0 {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].specificity != matches[j].specificity {
				return matches[i].specificity > matches[j].specificity
			}
			return actionPriority(matches[i].rule.Action) > actionPriority(matches[j].rule.Action)
		})
		winner := matches[0]
		logDebug("    Selected rule[%d] with specificity=%d action=%s", winner.index, winner.specificity, winner.rule.Action)
		return winner.result
	}

	// If in allow list and no rule matched, allow
	if inAllowList {
		logDebug("    No rules matched, using allow list")
		return Result{Action: "allow"}
	}

	// Use default policy
	logDebug("    No rules matched, using policy.default=%s", cfg.Policy.Default)
	return Result{
		Action:  cfg.Policy.Default,
		Message: cfg.Policy.DefaultMessage,
		Command: cmd.Name,
		Source:  cfg.Path + ": policy.default (command not in allow/deny lists)",
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
	for posStr, pattern := range rule.Args.Position {
		pos, _ := strconv.Atoi(posStr) // Already validated in Config.Validate()
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

	// Build source description
	source := cfg.Path + ": rule matched (command=" + rule.Command
	if len(rule.Args.Contains) > 0 {
		source += ", args.contains"
	}
	if len(rule.Args.AnyMatch) > 0 {
		source += ", args.any_match"
	}
	if len(rule.Args.AllMatch) > 0 {
		source += ", args.all_match"
	}
	if len(rule.Args.Position) > 0 {
		source += ", args.position"
	}
	if len(rule.Pipe.To) > 0 {
		source += ", pipe.to"
	}
	if len(rule.Pipe.From) > 0 {
		source += ", pipe.from"
	}
	source += ")"

	return Result{
		Action:  rule.Action,
		Message: msg,
		Command: cmd.Name,
		Source:  source,
	}, true
}

// evaluateRedirectWithConfig checks a redirect against a single config's rules.
func (e *Evaluator) evaluateRedirectWithConfig(cfg *Config, redir Redirect) Result {
	logDebug("  Evaluating redirect to %q (append=%v, fd=%v)", redir.Target, redir.Append, redir.IsFdRedirect)

	// File descriptor redirects (like 2>&1) are always safe - just combining streams
	if redir.IsFdRedirect {
		logDebug("    File descriptor redirect, auto-allowing")
		return Result{Action: "allow"}
	}

	// Dynamic redirects
	if redir.IsDynamic {
		logDebug("    Redirect is dynamic, policy.dynamic_commands=%s", cfg.Policy.DynamicCommands)
		switch cfg.Policy.DynamicCommands {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic redirect targets are not allowed",
				Source:  cfg.Path + ": dynamic redirect to " + redir.Target,
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{
				Action:  "ask",
				Source:  cfg.Path + ": dynamic redirect requires approval",
			}
		}
	}

	// Evaluate redirect rules in order
	for i, rule := range cfg.Redirects {
		if result, matched := e.matchRedirectRuleWithConfig(cfg, rule, redir); matched {
			logDebug("    Matched redirect rule[%d]: action=%s", i, rule.Action)
			return result
		}
	}

	// No rule matched - use policy default
	logDebug("    No redirect rules matched, using policy.default=%s", cfg.Policy.Default)
	return Result{
		Action: cfg.Policy.Default,
		Source: cfg.Path + ": policy.default (redirect to " + redir.Target + " not in rules)",
	}
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

	// Build source description
	source := cfg.Path + ": redirect rule matched (to=" + redir.Target
	if rule.Append != nil {
		source += ", append"
	}
	if len(rule.To.Exact) > 0 {
		source += ", to.exact"
	}
	if len(rule.To.Pattern) > 0 {
		source += ", to.pattern"
	}
	source += ")"

	return Result{
		Action:  rule.Action,
		Message: msg,
		Source:  source,
	}, true
}

// evaluateHeredocWithConfig checks a heredoc against a single config's [[heredoc]] rules.
// This is only called when constructs.heredocs = "allow" (deny already returned above).
func (e *Evaluator) evaluateHeredocWithConfig(cfg *Config, hdoc Heredoc) Result {
	logDebug("  Evaluating heredoc (delimiter=%q, body length=%d)", hdoc.Delimiter, len(hdoc.Body))

	// Evaluate heredoc rules in order (first match wins, like redirects)
	for i, rule := range cfg.Heredocs {
		if result, matched := e.matchHeredocRuleWithConfig(cfg, rule, hdoc); matched {
			logDebug("    Matched heredoc rule[%d]: action=%s", i, rule.Action)
			return result
		}
	}

	// No rule matched - heredocs are allowed by default when constructs.heredocs = "allow"
	logDebug("    No heredoc rules matched, allowing")
	return Result{Action: "allow"}
}

// matchHeredocRuleWithConfig checks if a heredoc rule matches.
func (e *Evaluator) matchHeredocRuleWithConfig(cfg *Config, rule HeredocRule, hdoc Heredoc) (Result, bool) {
	// Check content_match patterns against the heredoc body
	if len(rule.ContentMatch) > 0 {
		matcher, err := NewMatcher(rule.ContentMatch)
		if err != nil {
			return Result{}, false
		}
		// Match against the heredoc body content
		if !matcher.AnyMatch([]string{hdoc.Body}) {
			return Result{}, false
		}
	}

	// Rule matched (or had no conditions, which matches all heredocs)
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = cfg.Policy.DefaultMessage
	}

	// Build source description
	source := cfg.Path + ": heredoc rule matched"
	if len(rule.ContentMatch) > 0 {
		source += " (content_match)"
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
		Source:  source,
	}, true
}
