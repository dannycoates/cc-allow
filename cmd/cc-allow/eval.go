package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"cc-allow/pkg/pathutil"
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
	chain        *ConfigChain
	merged       *MergedConfig
	matchCtx     *MatchContext
	pathResolver *pathutil.CommandResolver
	configError  error // non-nil if config validation failed
}

// NewEvaluator creates a new evaluator with the given configuration chain.
func NewEvaluator(chain *ConfigChain) *Evaluator {
	projectRoot := findProjectRoot()

	// Validate all configs in the chain
	var configError error
	for _, cfg := range chain.Configs {
		if err := cfg.Validate(); err != nil {
			configError = err
			break
		}
	}

	// Compute merged config if not already set
	merged := chain.Merged
	if merged == nil && len(chain.Configs) > 0 {
		merged = MergeConfigs(chain.Configs)
		chain.Merged = merged
	}

	// Use the merged config's allowed paths (already unioned)
	var allowedPaths []string
	if merged != nil {
		allowedPaths = merged.Policy.AllowedPaths
	}

	pathVars := pathutil.NewPathVars(projectRoot)

	// Check if config uses $HOME but HOME is not available
	if configError == nil && !pathVars.HomeSet && merged != nil && mergedConfigUsesHome(merged) {
		configError = fmt.Errorf("config uses $HOME but HOME environment variable is not set")
	}

	return &Evaluator{
		chain:  chain,
		merged: merged,
		matchCtx: &MatchContext{
			PathVars: pathVars,
		},
		pathResolver: pathutil.NewCommandResolver(allowedPaths),
		configError:  configError,
	}
}

// Evaluate checks all extracted info against the merged configuration.
// Uses the single merged config with proper inheritance and strictness semantics.
func (e *Evaluator) Evaluate(info *ExtractedInfo) Result {
	// Check config validation error (fail safe - ask if config is invalid)
	// We use "ask" rather than "deny" so Claude Code's permission system handles it
	if e.configError != nil {
		return Result{
			Action:  "ask",
			Message: "Config validation error: " + e.configError.Error(),
			Source:  "config validation failed",
		}
	}

	// Check parse error
	if info.ParseError != nil {
		return Result{
			Action:  "deny",
			Message: "Parse error: " + info.ParseError.Error(),
		}
	}

	// Use merged config for evaluation
	if e.merged == nil {
		return Result{Action: "ask", Source: "no configuration loaded"}
	}

	logDebug("--- Evaluating against merged config (from %d source(s)) ---", len(e.merged.Sources))

	// Check constructs first (can deny or ask)
	constructResult := e.checkConstructsMerged(info)
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
		cmdResult := e.evaluateCommandMerged(cmd)
		result = combineResults(result, cmdResult)
		if result.Action == "deny" {
			return result // early exit on deny
		}
	}

	// Check redirects
	for _, redir := range info.Redirects {
		redirResult := e.evaluateRedirectMerged(redir)
		result = combineResults(result, redirResult)
		if result.Action == "deny" {
			return result // early exit on deny
		}
	}

	// Check heredocs (only if constructs.heredocs != "deny", which already returned above)
	if e.merged.Constructs.Heredocs.Value == "allow" {
		for _, hdoc := range info.Heredocs {
			hdocResult := e.evaluateHeredocMerged(hdoc)
			result = combineResults(result, hdocResult)
			if result.Action == "deny" {
				return result // early exit on deny
			}
		}
	}

	// If no actual runnable commands, ask - don't auto-allow
	if len(info.Commands) == 0 && len(info.Redirects) == 0 && len(info.Heredocs) == 0 {
		return Result{Action: "ask", Source: "no executable commands in input"}
	}

	return result
}

// checkConstructsMerged verifies shell constructs against the merged config's policy.
func (e *Evaluator) checkConstructsMerged(info *ExtractedInfo) Result {
	result := Result{Action: "allow"}

	if info.Constructs.HasFunctionDefs {
		tv := e.merged.Constructs.FunctionDefinitions
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Function definitions are not allowed",
				Source:  tv.Source + ": constructs.function_definitions=deny",
			}
		case "ask":
			result = Result{
				Action:  "ask",
				Message: "Function definitions need approval",
				Source:  tv.Source + ": constructs.function_definitions=ask",
			}
		}
	}

	if info.Constructs.HasBackground {
		tv := e.merged.Constructs.Background
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Background execution (&) is not allowed",
				Source:  tv.Source + ": constructs.background=deny",
			}
		case "ask":
			result = combineResults(result, Result{
				Action:  "ask",
				Message: "Background execution needs approval",
				Source:  tv.Source + ": constructs.background=ask",
			})
		}
	}

	if info.Constructs.HasHeredocs {
		tv := e.merged.Constructs.Heredocs
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Heredocs are not allowed",
				Source:  tv.Source + ": constructs.heredocs=deny",
			}
		case "ask":
			result = combineResults(result, Result{
				Action:  "ask",
				Message: "Heredocs need approval",
				Source:  tv.Source + ": constructs.heredocs=ask",
			})
		}
	}

	return result
}

// evaluateCommandMerged checks a single command against the merged config.
func (e *Evaluator) evaluateCommandMerged(cmd Command) Result {
	logDebug("  Evaluating command %q", cmd.Name)

	// Handle dynamic commands
	if cmd.IsDynamic {
		tv := e.merged.Policy.DynamicCommands
		logDebug("    Command is dynamic, policy.dynamic_commands=%s (from %s)", tv.Value, tv.Source)
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic command names are not allowed",
				Command: cmd.Name,
				Source:  tv.Source + ": dynamic command",
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{
				Action:  "ask",
				Command: cmd.Name,
				Source:  tv.Source + ": dynamic command requires approval",
			}
		}
	}

	// Resolve command path using effective CWD (which tracks cd commands in the script)
	resolveResult := e.pathResolver.ResolveWithCwd(cmd.Name, cmd.EffectiveCwd)
	cmd.ResolvedPath = resolveResult.Path
	cmd.IsBuiltin = resolveResult.IsBuiltin

	logDebug("    Resolved: path=%q builtin=%v unresolved=%v", cmd.ResolvedPath, cmd.IsBuiltin, resolveResult.Unresolved)

	// Handle unresolved commands
	if resolveResult.Unresolved {
		tv := e.merged.Policy.UnresolvedCommands
		if tv.Value == "deny" {
			logDebug("    Command not found, policy.unresolved_commands=deny")
			return Result{
				Action:  "deny",
				Message: "Command not found in allowed paths",
				Command: cmd.Name,
				Source:  tv.Source + ": unresolved command",
			}
		}
	}

	// Check merged deny list
	for _, entry := range e.merged.CommandsDeny {
		if e.matchCommandNameSingle(cmd.Name, cmd.ResolvedPath, entry.Name) {
			logDebug("    Matched commands.deny (from %s)", entry.Source)
			msg := entry.Message
			if msg == "" {
				msg = e.merged.Policy.DefaultMessage.Value
			}
			return Result{
				Action:  "deny",
				Message: msg,
				Command: cmd.Name,
				Source:  entry.Source + ": commands.deny.names",
			}
		}
	}

	// Check merged allow list
	var inAllowList bool
	var allowSource string
	for _, entry := range e.merged.CommandsAllow {
		if e.matchCommandNameSingle(cmd.Name, cmd.ResolvedPath, entry.Name) {
			inAllowList = true
			allowSource = entry.Source
			logDebug("    In commands.allow (from %s, checking rules for context)", entry.Source)
			break
		}
	}

	// Collect all matching rules (skip shadowed rules)
	type ruleMatch struct {
		index       int
		rule        TrackedRule
		specificity int
		result      Result
	}
	var matches []ruleMatch

	for i, tr := range e.merged.Rules {
		if tr.Shadowed {
			continue // skip shadowed rules
		}
		if result, matched := e.matchTrackedRule(tr, cmd); matched {
			spec := tr.Rule.Specificity()
			logDebug("    Rule[%d] matched: command=%q action=%s specificity=%d (from %s)", i, tr.Rule.Command, tr.Rule.Action, spec, tr.Source)
			matches = append(matches, ruleMatch{
				index:       i,
				rule:        tr,
				specificity: spec,
				result:      result,
			})
		}
	}

	// Pick the most specific rule
	if len(matches) > 0 {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].specificity != matches[j].specificity {
				return matches[i].specificity > matches[j].specificity
			}
			return actionPriority(matches[i].rule.Rule.Action) > actionPriority(matches[j].rule.Rule.Action)
		})
		winner := matches[0]
		logDebug("    Selected rule[%d] with specificity=%d action=%s", winner.index, winner.specificity, winner.rule.Rule.Action)
		return winner.result
	}

	// If in allow list and no rule matched, allow
	if inAllowList {
		logDebug("    No rules matched, using allow list")
		return Result{Action: "allow", Source: allowSource + ": commands.allow.names"}
	}

	// For unresolved commands with "ask" policy
	if resolveResult.Unresolved {
		tv := e.merged.Policy.UnresolvedCommands
		if tv.Value == "ask" {
			logDebug("    No rules matched, command unresolved, policy.unresolved_commands=ask")
			return Result{
				Action:  "ask",
				Message: "Command not found in allowed paths",
				Command: cmd.Name,
				Source:  tv.Source + ": unresolved command requires approval",
			}
		}
	}

	// Use default policy
	tv := e.merged.Policy.Default
	logDebug("    No rules matched, using policy.default=%s (from %s)", tv.Value, tv.Source)
	return Result{
		Action:  tv.Value,
		Message: e.merged.Policy.DefaultMessage.Value,
		Command: cmd.Name,
		Source:  tv.Source + ": policy.default (command not in allow/deny lists)",
	}
}

// matchCommandNameSingle checks if a command matches a single pattern.
func (e *Evaluator) matchCommandNameSingle(name, resolvedPath, pattern string) bool {
	if strings.HasPrefix(pattern, "path:") {
		if resolvedPath == "" {
			return false
		}
		p, err := ParsePattern(pattern)
		if err != nil {
			return false
		}
		return p.MatchWithContext(resolvedPath, e.matchCtx)
	}
	// Exact match against name or basename of resolved path
	if pattern == name {
		return true
	}
	if resolvedPath != "" && pattern == filepath.Base(resolvedPath) {
		return true
	}
	return false
}

// matchTrackedRule checks if a tracked rule matches the command.
func (e *Evaluator) matchTrackedRule(tr TrackedRule, cmd Command) (Result, bool) {
	rule := tr.Rule

	// Check command name match
	if rule.Command != "*" {
		if !e.matchRuleCommand(rule.Command, cmd) {
			return Result{}, false
		}
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
		if !matcher.AnyMatchWithContext(args, e.matchCtx) {
			return Result{}, false
		}
	}

	// Check args.all_match
	if len(rule.Args.AllMatch) > 0 {
		matcher, err := NewMatcher(rule.Args.AllMatch)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AllMatchWithContext(args, e.matchCtx) {
			return Result{}, false
		}
	}

	// Check args.position
	for posStr, pattern := range rule.Args.Position {
		pos, _ := strconv.Atoi(posStr)
		if !MatchPositionWithContext(args, pos, pattern, e.matchCtx) {
			return Result{}, false
		}
	}

	// Check pipe.to context
	if len(rule.Pipe.To) > 0 {
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
		receivesFromRestricted := false
		if ContainsExact([]string{"*"}, rule.Pipe.From) {
			if len(cmd.PipesFrom) > 0 {
				receivesFromRestricted = true
			}
		} else {
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

	// Rule matched
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}

	// Build source description
	source := tr.Source + ": rule matched (command=" + rule.Command
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

// evaluateRedirectMerged checks a redirect against the merged config.
func (e *Evaluator) evaluateRedirectMerged(redir Redirect) Result {
	logDebug("  Evaluating redirect to %q (append=%v, fd=%v)", redir.Target, redir.Append, redir.IsFdRedirect)

	// File descriptor redirects are always safe
	if redir.IsFdRedirect {
		logDebug("    File descriptor redirect, auto-allowing")
		return Result{Action: "allow"}
	}

	// Dynamic redirects
	if redir.IsDynamic {
		tv := e.merged.Policy.DynamicCommands
		logDebug("    Redirect is dynamic, policy.dynamic_commands=%s", tv.Value)
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic redirect targets are not allowed",
				Source:  tv.Source + ": dynamic redirect to " + redir.Target,
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{
				Action:  "ask",
				Source:  tv.Source + ": dynamic redirect requires approval",
			}
		}
	}

	// Evaluate redirect rules (skip shadowed)
	for i, tr := range e.merged.Redirects {
		if tr.Shadowed {
			continue
		}
		if result, matched := e.matchTrackedRedirectRule(tr, redir); matched {
			logDebug("    Matched redirect rule[%d]: action=%s (from %s)", i, tr.RedirectRule.Action, tr.Source)
			return result
		}
	}

	// No rule matched - use policy default
	tv := e.merged.Policy.Default
	logDebug("    No redirect rules matched, using policy.default=%s (from %s)", tv.Value, tv.Source)
	return Result{
		Action: tv.Value,
		Source: tv.Source + ": policy.default (redirect to " + redir.Target + " not in rules)",
	}
}

// matchTrackedRedirectRule checks if a redirect rule matches.
func (e *Evaluator) matchTrackedRedirectRule(tr TrackedRedirectRule, redir Redirect) (Result, bool) {
	rule := tr.RedirectRule

	// Check append mode filter
	if rule.Append != nil {
		if *rule.Append != redir.Append {
			return Result{}, false
		}
	}

	// Check exact matches
	if len(rule.To.Exact) > 0 {
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
		if !matcher.AnyMatchWithContext([]string{redir.Target}, e.matchCtx) {
			return Result{}, false
		}
	}

	// Rule matched
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}

	source := tr.Source + ": redirect rule matched (to=" + redir.Target
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

// evaluateHeredocMerged checks a heredoc or here-string against the merged config.
func (e *Evaluator) evaluateHeredocMerged(hdoc Heredoc) Result {
	if hdoc.IsHereString {
		logDebug("  Evaluating here-string (body length=%d)", len(hdoc.Body))
	} else {
		logDebug("  Evaluating heredoc (delimiter=%q, body length=%d)", hdoc.Delimiter, len(hdoc.Body))
	}

	// Evaluate heredoc rules (skip shadowed)
	for i, tr := range e.merged.Heredocs {
		if tr.Shadowed {
			continue
		}
		if result, matched := e.matchTrackedHeredocRule(tr, hdoc); matched {
			logDebug("    Matched heredoc rule[%d]: action=%s (from %s)", i, tr.HeredocRule.Action, tr.Source)
			return result
		}
	}

	// No rule matched - heredocs are allowed by default when constructs.heredocs = "allow"
	logDebug("    No heredoc rules matched, allowing")
	return Result{Action: "allow"}
}

// matchTrackedHeredocRule checks if a heredoc rule matches.
func (e *Evaluator) matchTrackedHeredocRule(tr TrackedHeredocRule, hdoc Heredoc) (Result, bool) {
	rule := tr.HeredocRule

	if len(rule.ContentMatch) > 0 {
		matcher, err := NewMatcher(rule.ContentMatch)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AnyMatch([]string{hdoc.Body}) {
			return Result{}, false
		}
	}

	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}

	ruleType := "heredoc"
	if hdoc.IsHereString {
		ruleType = "here-string"
	}
	source := tr.Source + ": " + ruleType + " rule matched"
	if len(rule.ContentMatch) > 0 {
		source += " (content_match)"
	}

	return Result{
		Action:  rule.Action,
		Message: msg,
		Source:  source,
	}, true
}

// matchRuleCommand checks if a rule's command pattern matches the command.
// Supports:
//   - "*" - matches any command (handled by caller)
//   - "path:..." - matches against resolved path using path pattern
//   - exact string - matches against command name
func (e *Evaluator) matchRuleCommand(ruleCommand string, cmd Command) bool {
	if strings.HasPrefix(ruleCommand, "path:") {
		// Path pattern - match against resolved path
		if cmd.ResolvedPath == "" {
			return false // Can't match path pattern without resolved path
		}
		p, err := ParsePattern(ruleCommand)
		if err != nil {
			return false
		}
		return p.MatchWithContext(cmd.ResolvedPath, e.matchCtx)
	}
	// Exact match against command name
	return ruleCommand == cmd.Name
}

// mergedConfigUsesHome checks if any pattern in the merged config uses $HOME.
func mergedConfigUsesHome(m *MergedConfig) bool {
	// Check commands.allow.names
	for _, entry := range m.CommandsAllow {
		if strings.Contains(entry.Name, "$HOME") {
			return true
		}
	}

	// Check commands.deny.names
	for _, entry := range m.CommandsDeny {
		if strings.Contains(entry.Name, "$HOME") {
			return true
		}
	}

	// Check rules
	for _, tr := range m.Rules {
		if ruleUsesHome(tr.Rule) {
			return true
		}
	}

	// Check redirect rules
	for _, rr := range m.Redirects {
		for _, p := range rr.To.Pattern {
			if strings.Contains(p, "$HOME") {
				return true
			}
		}
	}

	// Check heredoc rules
	for _, hr := range m.Heredocs {
		for _, p := range hr.ContentMatch {
			if strings.Contains(p, "$HOME") {
				return true
			}
		}
	}

	return false
}

// ruleUsesHome checks if a rule uses $HOME in any of its patterns.
func ruleUsesHome(rule Rule) bool {
	if strings.Contains(rule.Command, "$HOME") {
		return true
	}
	for _, p := range rule.Args.AnyMatch {
		if strings.Contains(p, "$HOME") {
			return true
		}
	}
	for _, p := range rule.Args.AllMatch {
		if strings.Contains(p, "$HOME") {
			return true
		}
	}
	for _, p := range rule.Args.Position {
		if strings.Contains(p, "$HOME") {
			return true
		}
	}
	return false
}
