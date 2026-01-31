package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"cc-allow/pkg/pathutil"
)

// defaultFileAccessTypes maps known commands to their default file access type.
var defaultFileAccessTypes = map[string]string{
	// Read commands
	"cat": "Read", "less": "Read", "more": "Read", "head": "Read", "tail": "Read",
	"grep": "Read", "egrep": "Read", "fgrep": "Read", "find": "Read", "file": "Read",
	"wc": "Read", "diff": "Read", "cmp": "Read", "stat": "Read", "od": "Read",
	"xxd": "Read", "hexdump": "Read", "strings": "Read",
	// Write commands
	"rm": "Write", "rmdir": "Write", "touch": "Write", "mkdir": "Write",
	"chmod": "Write", "chown": "Write", "chgrp": "Write", "ln": "Write", "unlink": "Write",
	// Edit commands
	"sed": "Edit",
}

// Result represents the evaluation result.
type Result struct {
	Action  string // "allow", "deny", or "ask"
	Message string
	Command string // the command that triggered this result
	Source  string // describes what triggered this result
}

// combineActionsStrict merges two actions with strictness order: deny > ask > allow
func combineActionsStrict(current, new string) string {
	if current == "deny" || new == "deny" {
		return "deny"
	}
	if current == "ask" || new == "ask" {
		return "ask"
	}
	return "allow"
}

// combineResults merges two results using strict ordering.
func combineResults(current, new Result) Result {
	combined := combineActionsStrict(current.Action, new.Action)
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
	if new.Action == "allow" {
		return new
	}
	return current
}

// actionPriority returns a priority value for tie-breaking.
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
	configError  error
}

// NewEvaluator creates a new evaluator with the given configuration chain.
func NewEvaluator(chain *ConfigChain) *Evaluator {
	projectRoot := findProjectRoot()

	var configError error
	for _, cfg := range chain.Configs {
		if err := cfg.Validate(); err != nil {
			configError = err
			break
		}
	}

	merged := chain.Merged
	if merged == nil && len(chain.Configs) > 0 {
		merged = MergeConfigs(chain.Configs)
		chain.Merged = merged
	}

	var allowedPaths []string
	if merged != nil {
		allowedPaths = merged.Policy.AllowedPaths
	}

	pathVars := pathutil.NewPathVars(projectRoot)

	if configError == nil && !pathVars.HomeSet && merged != nil && mergedConfigUsesHome(merged) {
		configError = fmt.Errorf("config uses $HOME but HOME environment variable is not set")
	}

	return &Evaluator{
		chain:  chain,
		merged: merged,
		matchCtx: &MatchContext{
			PathVars: pathVars,
			Merged:   merged,
		},
		pathResolver: pathutil.NewCommandResolver(allowedPaths),
		configError:  configError,
	}
}

// Evaluate checks all extracted info against the merged configuration.
func (e *Evaluator) Evaluate(info *ExtractedInfo) Result {
	if e.configError != nil {
		return Result{
			Action:  "ask",
			Message: "Config validation error: " + e.configError.Error(),
			Source:  "config validation failed",
		}
	}

	if info.ParseError != nil {
		return Result{
			Action:  "deny",
			Message: "Parse error: " + info.ParseError.Error(),
		}
	}

	if e.merged == nil {
		return Result{Action: "ask", Source: "no configuration loaded"}
	}

	logDebug("--- Evaluating against merged config (from %d source(s)) ---", len(e.merged.Sources))

	// Check constructs first
	constructResult := e.checkConstructs(info)
	if constructResult.Action == "deny" {
		return constructResult
	}

	result := Result{Action: "allow"}
	if constructResult.Action == "ask" {
		result = constructResult
	}

	// Check each command
	for _, cmd := range info.Commands {
		cmdResult := e.evaluateCommand(cmd)
		result = combineResults(result, cmdResult)
		if result.Action == "deny" {
			return result
		}
	}

	// Check redirects
	for _, redir := range info.Redirects {
		redirResult := e.evaluateRedirect(redir)
		result = combineResults(result, redirResult)
		if result.Action == "deny" {
			return result
		}
	}

	// Check heredocs
	if e.merged.Constructs.Heredocs.Value == "allow" {
		for _, hdoc := range info.Heredocs {
			hdocResult := e.evaluateHeredoc(hdoc)
			result = combineResults(result, hdocResult)
			if result.Action == "deny" {
				return result
			}
		}
	}

	if len(info.Commands) == 0 && len(info.Redirects) == 0 && len(info.Heredocs) == 0 {
		return Result{Action: "ask", Source: "no executable commands in input"}
	}

	return result
}

// checkConstructs verifies shell constructs against config policy.
func (e *Evaluator) checkConstructs(info *ExtractedInfo) Result {
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

// evaluateCommand checks a single command against the merged config.
func (e *Evaluator) evaluateCommand(cmd Command) Result {
	logDebug("  Evaluating command %q", cmd.Name)

	// Handle dynamic commands
	if cmd.IsDynamic {
		tv := e.merged.Policy.DynamicCommands
		logDebug("    Command is dynamic, policy.dynamic_commands=%s", tv.Value)
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

	// Resolve command path
	resolveResult := e.pathResolver.ResolveWithCwd(cmd.Name, cmd.EffectiveCwd)
	cmd.ResolvedPath = resolveResult.Path
	cmd.IsBuiltin = resolveResult.IsBuiltin

	logDebug("    Resolved: path=%q builtin=%v unresolved=%v", cmd.ResolvedPath, cmd.IsBuiltin, resolveResult.Unresolved)

	// Handle unresolved commands
	if resolveResult.Unresolved {
		tv := e.merged.Policy.UnresolvedCommands
		if tv.Value == "deny" {
			return Result{
				Action:  "deny",
				Message: "Command not found in allowed paths",
				Command: cmd.Name,
				Source:  tv.Source + ": unresolved command",
			}
		}
	}

	// Check deny list
	for _, entry := range e.merged.CommandsDeny {
		if e.matchCommandName(cmd.Name, cmd.ResolvedPath, entry.Name) {
			logDebug("    Matched commands.deny (from %s)", entry.Source)
			msg := entry.Message
			if msg == "" {
				msg = e.merged.Policy.DefaultMessage.Value
			}
			tmplCtx := newCommandTemplateContext(cmd, e.matchCtx)
			msg = templateMessage(msg, tmplCtx)
			return Result{
				Action:  "deny",
				Message: msg,
				Command: cmd.Name,
				Source:  entry.Source + ": bash.deny.commands",
			}
		}
	}

	// Check allow list
	var inAllowList bool
	var allowSource string
	for _, entry := range e.merged.CommandsAllow {
		if e.matchCommandName(cmd.Name, cmd.ResolvedPath, entry.Name) {
			inAllowList = true
			allowSource = entry.Source
			logDebug("    In bash.allow.commands (from %s)", entry.Source)
			break
		}
	}

	// Collect matching rules
	type ruleMatch struct {
		index       int
		rule        TrackedRule
		specificity int
		result      Result
	}
	var matches []ruleMatch

	for i, tr := range e.merged.Rules {
		if tr.Shadowed {
			continue
		}
		if result, matched := e.matchRule(tr, cmd); matched {
			spec := tr.BashRule.Specificity()
			logDebug("    Rule[%d] matched: command=%q action=%s specificity=%d", i, tr.Command, tr.Action, spec)
			matches = append(matches, ruleMatch{
				index:       i,
				rule:        tr,
				specificity: spec,
				result:      result,
			})
		}
	}

	// Pick most specific rule
	if len(matches) > 0 {
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].specificity != matches[j].specificity {
				return matches[i].specificity > matches[j].specificity
			}
			return actionPriority(matches[i].rule.Action) > actionPriority(matches[j].rule.Action)
		})
		winner := matches[0]
		logDebug("    Selected rule[%d] with specificity=%d action=%s", winner.index, winner.specificity, winner.rule.Action)

		// Check file arguments if rule allows
		if winner.result.Action == "allow" && e.shouldRespectFileRules(&winner.rule) {
			fileResult := e.checkCommandFileArgs(cmd, &winner.rule)
			if fileResult.Action != "allow" {
				return fileResult
			}
		}
		return winner.result
	}

	// If in allow list, allow
	if inAllowList {
		logDebug("    No rules matched, using allow list")
		if e.shouldRespectFileRules(nil) {
			fileResult := e.checkCommandFileArgs(cmd, nil)
			if fileResult.Action != "allow" {
				return fileResult
			}
		}
		return Result{Action: "allow", Source: allowSource + ": bash.allow.commands"}
	}

	// Unresolved command ask handling
	if resolveResult.Unresolved {
		tv := e.merged.Policy.UnresolvedCommands
		if tv.Value == "ask" {
			return Result{
				Action:  "ask",
				Message: "Command not found in allowed paths",
				Command: cmd.Name,
				Source:  tv.Source + ": unresolved command requires approval",
			}
		}
	}

	// Default policy
	tv := e.merged.Policy.Default
	logDebug("    No rules matched, using policy.default=%s", tv.Value)

	if tv.Value == "allow" && e.shouldRespectFileRules(nil) {
		fileResult := e.checkCommandFileArgs(cmd, nil)
		if fileResult.Action != "allow" {
			return fileResult
		}
	}

	return Result{
		Action:  tv.Value,
		Message: e.merged.Policy.DefaultMessage.Value,
		Command: cmd.Name,
		Source:  tv.Source + ": bash.default",
	}
}

// matchCommandName checks if a command matches a pattern.
func (e *Evaluator) matchCommandName(name, resolvedPath, pattern string) bool {
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
	if pattern == name {
		return true
	}
	if resolvedPath != "" && pattern == filepath.Base(resolvedPath) {
		return true
	}
	return false
}

// matchRule checks if a rule matches the command.
func (e *Evaluator) matchRule(tr TrackedRule, cmd Command) (Result, bool) {
	rule := tr.BashRule

	// Check command name
	if !e.matchRuleCommand(rule.Command, cmd) {
		return Result{}, false
	}

	// Check subcommands (positional args from path like [[bash.allow.git.status]])
	args := cmd.Args
	if len(args) > 0 {
		args = args[1:] // exclude command name
	}
	for i, sub := range rule.Subcommands {
		if i >= len(args) || args[i] != sub {
			return Result{}, false
		}
	}

	// Adjust args for subcommand offset
	if len(rule.Subcommands) > 0 && len(args) > len(rule.Subcommands) {
		args = args[len(rule.Subcommands):]
	}

	// Check args boolean expressions
	if rule.Args.Any != nil {
		if !e.evaluateBoolExpr(rule.Args.Any, args) {
			return Result{}, false
		}
	}
	if rule.Args.All != nil {
		if !e.evaluateBoolExprAll(rule.Args.All, args) {
			return Result{}, false
		}
	}
	if rule.Args.Not != nil {
		if e.evaluateBoolExpr(rule.Args.Not, args) {
			return Result{}, false
		}
	}
	if rule.Args.Xor != nil {
		if !e.evaluateBoolExprXor(rule.Args.Xor, args) {
			return Result{}, false
		}
	}

	// Check args.position
	for posStr, fp := range rule.Args.Position {
		pos, _ := strconv.Atoi(posStr)
		if !matchPositionFlexible(args, pos, fp.Patterns, e.matchCtx) {
			return Result{}, false
		}
	}

	// Check pipe.to
	if len(rule.Pipe.To) > 0 {
		matched := false
		for _, pipeDest := range cmd.PipesTo {
			for _, toPattern := range rule.Pipe.To {
				p, err := ParsePattern(toPattern)
				if err != nil {
					continue
				}
				if p.MatchWithContext(pipeDest, e.matchCtx) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return Result{}, false
		}
	}

	// Check pipe.from
	if len(rule.Pipe.From) > 0 {
		matched := false
		for _, pipeSource := range cmd.PipesFrom {
			for _, fromPattern := range rule.Pipe.From {
				p, err := ParsePattern(fromPattern)
				if err != nil {
					continue
				}
				if p.MatchWithContext(pipeSource, e.matchCtx) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return Result{}, false
		}
	}

	// Rule matched
	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}
	tmplCtx := newCommandTemplateContext(cmd, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

	source := tr.Source + ": rule matched (command=" + rule.Command + ")"

	return Result{
		Action:  rule.Action,
		Message: msg,
		Command: cmd.Name,
		Source:  source,
	}, true
}

// matchRuleCommand checks if a rule's command pattern matches.
func (e *Evaluator) matchRuleCommand(ruleCommand string, cmd Command) bool {
	if strings.HasPrefix(ruleCommand, "path:") {
		if cmd.ResolvedPath != "" {
			p, err := ParsePattern(ruleCommand)
			if err != nil {
				return false
			}
			if p.MatchWithContext(cmd.ResolvedPath, e.matchCtx) {
				return true
			}
		}
		p, err := ParsePattern(ruleCommand)
		if err != nil {
			return false
		}
		return p.MatchWithContext(cmd.Name, e.matchCtx)
	}
	p, err := ParsePattern(ruleCommand)
	if err != nil {
		return false
	}
	return p.MatchWithContext(cmd.Name, e.matchCtx)
}

// evaluateBoolExpr evaluates a boolean expression against args using OR semantics for flat patterns.
// This is used for args.any where any pattern matching any arg is sufficient.
func (e *Evaluator) evaluateBoolExpr(expr *BoolExpr, args []string) bool {
	return e.evaluateBoolExprWithSemantics(expr, args, false)
}

// evaluateBoolExprAll evaluates a boolean expression against args using AND semantics for flat patterns.
// This is used for args.all where ALL patterns must each match at least one arg.
func (e *Evaluator) evaluateBoolExprAll(expr *BoolExpr, args []string) bool {
	return e.evaluateBoolExprWithSemantics(expr, args, true)
}

// evaluateBoolExprWithSemantics evaluates a boolean expression against args.
// If andSemantics is true, flat patterns use AND (all patterns must match).
// If andSemantics is false, flat patterns use OR (any pattern matching is sufficient).
func (e *Evaluator) evaluateBoolExprWithSemantics(expr *BoolExpr, args []string, andSemantics bool) bool {
	if expr == nil {
		return true
	}

	// Handle flat patterns
	if len(expr.Patterns) > 0 {
		if andSemantics {
			// AND semantics: ALL patterns must match some arg
			for _, pattern := range expr.Patterns {
				if !matchAnyArg(args, pattern, e.matchCtx) {
					return false
				}
			}
			// All patterns matched
			if !expr.hasOperators() && !expr.IsSequence {
				return true
			}
		} else {
			// OR semantics: any pattern matches any arg
			for _, pattern := range expr.Patterns {
				if matchAnyArg(args, pattern, e.matchCtx) {
					return true
				}
			}
			// If only patterns, need at least one match
			if !expr.hasOperators() && !expr.IsSequence {
				return false
			}
		}
	}

	// Handle sequence (sliding window match)
	if expr.IsSequence {
		return matchSequence(args, expr.Sequence, e.matchCtx)
	}

	// Handle nested operators - these define their own semantics
	if len(expr.Any) > 0 {
		for _, child := range expr.Any {
			if e.evaluateBoolExprWithSemantics(child, args, false) { // nested Any uses OR
				return true
			}
		}
		return false
	}

	if len(expr.All) > 0 {
		for _, child := range expr.All {
			if !e.evaluateBoolExprWithSemantics(child, args, true) { // nested All uses AND
				return false
			}
		}
		return true
	}

	if expr.Not != nil {
		return !e.evaluateBoolExprWithSemantics(expr.Not, args, andSemantics)
	}

	if len(expr.Xor) > 0 {
		return e.evaluateBoolExprXor(&BoolExpr{Any: expr.Xor}, args)
	}

	return true
}

// evaluateBoolExprXor evaluates XOR (exactly one must match).
func (e *Evaluator) evaluateBoolExprXor(expr *BoolExpr, args []string) bool {
	if expr == nil {
		return true
	}

	// Count how many children match
	count := 0
	for _, child := range expr.Xor {
		if e.evaluateBoolExpr(child, args) {
			count++
		}
	}
	return count == 1
}

// shouldRespectFileRules determines if file rules should be checked.
func (e *Evaluator) shouldRespectFileRules(rule *TrackedRule) bool {
	if rule != nil && rule.RespectFileRules != nil {
		if *rule.RespectFileRules {
			return e.hasFileRulesConfigured()
		}
		return false
	}
	if e.merged.Policy.RespectFileRules.Value {
		return e.hasFileRulesConfigured()
	}
	return false
}

// hasFileRulesConfigured checks if any file rules are configured.
func (e *Evaluator) hasFileRulesConfigured() bool {
	for _, entries := range e.merged.Files.Deny {
		if len(entries) > 0 {
			return true
		}
	}
	for _, entries := range e.merged.Files.Allow {
		if len(entries) > 0 {
			return true
		}
	}
	return false
}

// checkCommandFileArgs checks file arguments against file rules.
func (e *Evaluator) checkCommandFileArgs(cmd Command, rule *TrackedRule) Result {
	result := Result{Action: "allow"}

	args := cmd.Args
	if len(args) > 0 {
		args = args[1:]
	}
	if len(args) == 0 {
		return result
	}

	defaultAccessType := e.getFileAccessType(cmd.Name, rule)

	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		accessType := defaultAccessType
		if accessType == "" {
			continue
		}
		if !e.isPathArgument(arg, cmd.EffectiveCwd, accessType) {
			continue
		}
		absPath := pathutil.ResolvePath(arg, cmd.EffectiveCwd, e.matchCtx.PathVars.Home)
		fileResult := checkFilePathAgainstRules(e.merged, accessType, absPath, e.matchCtx)
		fileResult.Command = cmd.Name
		if fileResult.Action == "deny" {
			fileResult.Message = fmt.Sprintf("File argument denied: %s (arg %d)", arg, i)
		}
		result = combineResults(result, fileResult)
		if result.Action == "deny" {
			return result
		}
	}
	return result
}

// getFileAccessType returns the file access type for a command.
func (e *Evaluator) getFileAccessType(cmdName string, rule *TrackedRule) string {
	if rule != nil && rule.FileAccessType != "" {
		return rule.FileAccessType
	}
	if accessType, ok := defaultFileAccessTypes[cmdName]; ok {
		return accessType
	}
	return ""
}

// isPathArgument checks if an argument appears to be a file path.
func (e *Evaluator) isPathArgument(arg, cwd, accessType string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}
	if pathutil.IsPathLike(arg) {
		return true
	}
	if pathutil.HasFileExtension(arg) {
		absPath := pathutil.ResolvePath(arg, cwd, e.matchCtx.PathVars.Home)
		switch accessType {
		case "Write":
			return pathutil.DirExists(filepath.Dir(absPath))
		default:
			return pathutil.FileExists(absPath)
		}
	}
	return false
}

// evaluateRedirect checks a redirect against the merged config.
func (e *Evaluator) evaluateRedirect(redir Redirect) Result {
	logDebug("  Evaluating redirect to %q", redir.Target)

	if redir.IsFdRedirect {
		return Result{Action: "allow"}
	}

	if redir.IsDynamic {
		tv := e.merged.Policy.DynamicCommands
		switch tv.Value {
		case "deny":
			return Result{
				Action:  "deny",
				Message: "Dynamic redirect targets are not allowed",
				Source:  tv.Source + ": dynamic redirect",
			}
		case "allow":
			return Result{Action: "allow"}
		default:
			return Result{Action: "ask", Source: tv.Source + ": dynamic redirect requires approval"}
		}
	}

	// Check redirect rules
	for i, tr := range e.merged.Redirects {
		if tr.Shadowed {
			continue
		}
		if result, matched := e.matchRedirectRule(tr, redir); matched {
			logDebug("    Matched redirect rule[%d]: action=%s", i, tr.Action)
			return result
		}
	}

	// Check file rules if enabled
	if e.merged.RedirectsPolicy.RespectFileRules.Value && e.hasFileRulesConfigured() {
		accessType := "Write"
		if redir.IsInput {
			accessType = "Read"
		}
		absPath := pathutil.ResolvePath(redir.Target, e.matchCtx.PathVars.Cwd, e.matchCtx.PathVars.Home)
		fileResult := checkFilePathAgainstRules(e.merged, accessType, absPath, e.matchCtx)
		if fileResult.Action == "deny" {
			fileResult.Message = "Redirect target denied: " + redir.Target
			return fileResult
		}
		if fileResult.Action == "allow" {
			return fileResult
		}
	}

	tv := e.merged.Policy.Default
	return Result{
		Action: tv.Value,
		Source: tv.Source + ": bash.default (redirect)",
	}
}

// matchRedirectRule checks if a redirect rule matches.
func (e *Evaluator) matchRedirectRule(tr TrackedRedirectRule, redir Redirect) (Result, bool) {
	rule := tr.RedirectRule

	if rule.Append != nil && *rule.Append != redir.Append {
		return Result{}, false
	}

	if len(rule.Paths) > 0 {
		matcher, err := NewMatcher(rule.Paths)
		if err != nil {
			return Result{}, false
		}
		if !matcher.AnyMatchWithContext([]string{redir.Target}, e.matchCtx) {
			return Result{}, false
		}
	}

	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}
	tmplCtx := newRedirectTemplateContext(redir, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

	return Result{
		Action:  rule.Action,
		Message: msg,
		Source:  tr.Source + ": redirect rule matched",
	}, true
}

// evaluateHeredoc checks a heredoc against the merged config.
func (e *Evaluator) evaluateHeredoc(hdoc Heredoc) Result {
	logDebug("  Evaluating heredoc")

	for i, tr := range e.merged.Heredocs {
		if tr.Shadowed {
			continue
		}
		if result, matched := e.matchHeredocRule(tr, hdoc); matched {
			logDebug("    Matched heredoc rule[%d]: action=%s", i, tr.Action)
			return result
		}
	}

	return Result{Action: "allow"}
}

// matchHeredocRule checks if a heredoc rule matches.
func (e *Evaluator) matchHeredocRule(tr TrackedHeredocRule, hdoc Heredoc) (Result, bool) {
	rule := tr.HeredocRule

	if rule.Content != nil {
		if !e.evaluateBoolExpr(rule.Content, []string{hdoc.Body}) {
			return Result{}, false
		}
	}

	msg := rule.Message
	if msg == "" && rule.Action == "deny" {
		msg = e.merged.Policy.DefaultMessage.Value
	}
	tmplCtx := newHeredocTemplateContext(hdoc, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

	return Result{
		Action:  rule.Action,
		Message: msg,
		Source:  tr.Source + ": heredoc rule matched",
	}, true
}

// checkFilePathAgainstRules checks a file path against file tool rules.
func checkFilePathAgainstRules(merged *MergedConfig, toolName, path string, ctx *MatchContext) Result {
	// Check deny patterns first
	for _, entry := range merged.Files.Deny[toolName] {
		p, err := ParsePattern(entry.Pattern)
		if err != nil {
			continue
		}
		if p.MatchWithContext(path, ctx) {
			msg := entry.Message
			if msg == "" {
				msg = "File access denied"
			}
			tmplCtx := newFileTemplateContext(toolName, path, ctx)
			msg = templateMessage(msg, tmplCtx)
			return Result{
				Action:  "deny",
				Message: msg,
				Source:  entry.Source + ": " + strings.ToLower(toolName) + ".deny.paths",
			}
		}
	}

	// Check allow patterns
	for _, entry := range merged.Files.Allow[toolName] {
		p, err := ParsePattern(entry.Pattern)
		if err != nil {
			continue
		}
		if p.MatchWithContext(path, ctx) {
			return Result{
				Action: "allow",
				Source: entry.Source + ": " + strings.ToLower(toolName) + ".allow.paths",
			}
		}
	}

	// Default
	return Result{
		Action: merged.Files.Default.Value,
		Source: merged.Files.Default.Source + ": files default",
	}
}

// evaluateFileTool evaluates a file tool request.
func evaluateFileTool(chain *ConfigChain, toolName, filePath string) Result {
	merged := chain.Merged
	if merged == nil {
		return Result{Action: "ask", Source: "no configuration loaded"}
	}

	projectRoot := findProjectRoot()
	pathVars := pathutil.NewPathVars(projectRoot)
	ctx := &MatchContext{
		PathVars: pathVars,
		Merged:   merged,
	}

	absPath := pathutil.ResolvePath(filePath, pathVars.Cwd, pathVars.Home)
	return checkFilePathAgainstRules(merged, toolName, absPath, ctx)
}

// Helper functions

// matchAnyArg checks if any arg matches the pattern.
func matchAnyArg(args []string, pattern string, ctx *MatchContext) bool {
	p, err := ParsePattern(pattern)
	if err != nil {
		return false
	}
	for _, arg := range args {
		if p.MatchWithContext(arg, ctx) {
			return true
		}
	}
	return false
}

// matchSequence uses a sliding window to find consecutive args matching the sequence.
func matchSequence(args []string, seq map[string]FlexiblePattern, ctx *MatchContext) bool {
	if len(seq) == 0 {
		return true
	}

	maxPos := 0
	for posStr := range seq {
		if pos, err := strconv.Atoi(posStr); err == nil && pos > maxPos {
			maxPos = pos
		}
	}

	for start := 0; start <= len(args)-(maxPos+1); start++ {
		if matchSequenceAt(args, start, seq, ctx) {
			return true
		}
	}
	return false
}

// matchSequenceAt checks if args at the given start position match the sequence.
func matchSequenceAt(args []string, start int, seq map[string]FlexiblePattern, ctx *MatchContext) bool {
	for posStr, fp := range seq {
		pos, err := strconv.Atoi(posStr)
		if err != nil {
			return false
		}
		if !matchPositionFlexible(args, start+pos, fp.Patterns, ctx) {
			return false
		}
	}
	return true
}

// matchPositionFlexible checks if the arg at a position matches any pattern.
func matchPositionFlexible(args []string, pos int, patterns []string, ctx *MatchContext) bool {
	if pos < 0 || pos >= len(args) {
		return false
	}
	for _, pattern := range patterns {
		if MatchPositionWithContext(args, pos, pattern, ctx) {
			return true
		}
	}
	return false
}

// mergedConfigUsesHome checks if any pattern uses $HOME.
func mergedConfigUsesHome(m *MergedConfig) bool {
	return mergedConfigContainsVar(m, "$HOME")
}

// mergedConfigContainsVar checks if any pattern in the merged config contains the variable.
func mergedConfigContainsVar(m *MergedConfig, varName string) bool {
	// Check command lists
	for _, entry := range m.CommandsAllow {
		if strings.Contains(entry.Name, varName) {
			return true
		}
	}
	for _, entry := range m.CommandsDeny {
		if strings.Contains(entry.Name, varName) {
			return true
		}
	}

	// Check rules
	for _, tr := range m.Rules {
		if ruleContainsVar(&tr.BashRule, varName) {
			return true
		}
	}

	// Check redirects
	for _, rr := range m.Redirects {
		for _, p := range rr.Paths {
			if strings.Contains(p, varName) {
				return true
			}
		}
	}

	// Check heredocs
	for _, hr := range m.Heredocs {
		if boolExprContainsVar(hr.Content, varName) {
			return true
		}
	}

	// Check file patterns
	for _, entries := range m.Files.Allow {
		for _, entry := range entries {
			if strings.Contains(entry.Pattern, varName) {
				return true
			}
		}
	}
	for _, entries := range m.Files.Deny {
		for _, entry := range entries {
			if strings.Contains(entry.Pattern, varName) {
				return true
			}
		}
	}

	// Check aliases
	for _, alias := range m.Aliases {
		for _, p := range alias.Patterns {
			if strings.Contains(p, varName) {
				return true
			}
		}
	}

	return false
}

// ruleContainsVar checks if a BashRule contains the variable in any pattern.
func ruleContainsVar(rule *BashRule, varName string) bool {
	if strings.Contains(rule.Command, varName) {
		return true
	}
	if argsMatchContainsVar(&rule.Args, varName) {
		return true
	}
	// Pipe.To and Pipe.From are command names, not paths, so skip them
	return false
}

// argsMatchContainsVar checks if an ArgsMatch contains the variable.
func argsMatchContainsVar(args *ArgsMatch, varName string) bool {
	if boolExprContainsVar(args.Any, varName) {
		return true
	}
	if boolExprContainsVar(args.All, varName) {
		return true
	}
	if boolExprContainsVar(args.Not, varName) {
		return true
	}
	if boolExprContainsVar(args.Xor, varName) {
		return true
	}
	for _, fp := range args.Position {
		for _, p := range fp.Patterns {
			if strings.Contains(p, varName) {
				return true
			}
		}
	}
	return false
}

// boolExprContainsVar recursively checks if a BoolExpr contains the variable.
func boolExprContainsVar(expr *BoolExpr, varName string) bool {
	if expr == nil {
		return false
	}
	// Check simple patterns
	for _, p := range expr.Patterns {
		if strings.Contains(p, varName) {
			return true
		}
	}
	// Check sequence patterns
	for _, fp := range expr.Sequence {
		for _, p := range fp.Patterns {
			if strings.Contains(p, varName) {
				return true
			}
		}
	}
	// Check nested expressions
	for _, child := range expr.Any {
		if boolExprContainsVar(child, varName) {
			return true
		}
	}
	for _, child := range expr.All {
		if boolExprContainsVar(child, varName) {
			return true
		}
	}
	for _, child := range expr.Xor {
		if boolExprContainsVar(child, varName) {
			return true
		}
	}
	if boolExprContainsVar(expr.Not, varName) {
		return true
	}
	return false
}
