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
// Commands not in this map default to "ask" for their file arguments.
var defaultFileAccessTypes = map[string]string{
	// Read commands
	"cat":   "Read",
	"less":  "Read",
	"more":  "Read",
	"head":  "Read",
	"tail":  "Read",
	"grep":  "Read",
	"egrep": "Read",
	"fgrep": "Read",
	"find":  "Read",
	"file":  "Read",
	"wc":    "Read",
	"diff":  "Read",
	"cmp":   "Read",
	"stat":  "Read",
	"od":    "Read",
	"xxd":   "Read",
	"hexdump": "Read",
	"strings": "Read",

	// Write commands (modify/delete/create)
	"rm":    "Write",
	"rmdir": "Write",
	"touch": "Write",
	"mkdir": "Write",
	"chmod": "Write",
	"chown": "Write",
	"chgrp": "Write",
	"ln":    "Write",
	"unlink": "Write",

	// Edit commands (modify in place)
	"sed": "Edit", // Note: only -i makes it edit, but we're conservative
}

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

	// Check if config uses $CLAUDE_PLUGIN_ROOT but env var is not set
	if configError == nil && !pathVars.PluginRootSet && merged != nil && mergedConfigUsesPluginRoot(merged) {
		configError = fmt.Errorf("config uses $CLAUDE_PLUGIN_ROOT but CLAUDE_PLUGIN_ROOT environment variable is not set")
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
			// Apply template substitution
			tmplCtx := newCommandTemplateContext(cmd, e.matchCtx)
			msg = templateMessage(msg, tmplCtx)
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

		// If the rule allows the command, check file arguments
		if winner.result.Action == "allow" && e.shouldRespectFileRules(&winner.rule) {
			fileResult := e.checkCommandFileArgs(cmd, &winner.rule)
			if fileResult.Action != "allow" {
				return fileResult
			}
		}
		return winner.result
	}

	// If in allow list and no rule matched, allow
	if inAllowList {
		logDebug("    No rules matched, using allow list")
		// Check file arguments with policy defaults
		if e.shouldRespectFileRules(nil) {
			fileResult := e.checkCommandFileArgs(cmd, nil)
			if fileResult.Action != "allow" {
				return fileResult
			}
		}
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

	// If policy allows, check file arguments
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
	if !e.matchRuleCommand(rule.Command, cmd) {
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

	// Check args.any_match (OR across elements: any element matching succeeds)
	if len(rule.Args.AnyMatch) > 0 {
		matched := false
		for _, elem := range rule.Args.AnyMatch {
			if matchElement(args, elem, e.matchCtx) {
				matched = true
				break
			}
		}
		if !matched {
			return Result{}, false
		}
	}

	// Check args.all_match (AND across elements: all elements must match)
	if len(rule.Args.AllMatch) > 0 {
		for _, elem := range rule.Args.AllMatch {
			if !matchElement(args, elem, e.matchCtx) {
				return Result{}, false
			}
		}
	}

	// Check args.position (values can be string or array, OR semantics for arrays)
	for posStr, fp := range rule.Args.Position {
		pos, _ := strconv.Atoi(posStr)
		if !matchPositionFlexible(args, pos, fp.Patterns, e.matchCtx) {
			return Result{}, false
		}
	}

	// Check pipe.to context
	if len(rule.Pipe.To) > 0 {
		pipesToRestricted := false
		for _, pipeDest := range cmd.PipesTo {
			for _, toPattern := range rule.Pipe.To {
				p, err := ParsePattern(toPattern)
				if err != nil {
					continue
				}
				if p.MatchWithContext(pipeDest, e.matchCtx) {
					pipesToRestricted = true
					break
				}
			}
			if pipesToRestricted {
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
		for _, pipeSource := range cmd.PipesFrom {
			for _, fromPattern := range rule.Pipe.From {
				p, err := ParsePattern(fromPattern)
				if err != nil {
					continue
				}
				if p.MatchWithContext(pipeSource, e.matchCtx) {
					receivesFromRestricted = true
					break
				}
			}
			if receivesFromRestricted {
				break
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
	// Apply template substitution
	tmplCtx := newCommandTemplateContext(cmd, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

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

// hasFileRulesConfigured checks if any file rules are configured.
// Returns true if there are any deny or allow patterns for any file tool.
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

// shouldRespectFileRules determines if file rules should be checked for a command.
// Returns true if policy.respect_file_rules is "true" (or unset, defaulting to true),
// AND there are actually file rules configured. If no file rules exist, checking is skipped.
// Rule-level settings can override this behavior.
func (e *Evaluator) shouldRespectFileRules(rule *TrackedRule) bool {
	// Rule-level override takes precedence (explicit true/false)
	if rule != nil && rule.Rule.RespectFileRules != nil {
		// Even if explicitly enabled, only check if there are rules to check against
		if *rule.Rule.RespectFileRules {
			return e.hasFileRulesConfigured()
		}
		return false
	}
	// Policy default - only enabled if there are file rules configured
	if e.merged.Policy.RespectFileRules.Value == "true" {
		return e.hasFileRulesConfigured()
	}
	return false
}

// getFileAccessType returns the file access type for a command.
// Priority: rule.file_access_type > defaultFileAccessTypes map > "ask"
func (e *Evaluator) getFileAccessType(cmdName string, rule *TrackedRule) string {
	// Rule-level override
	if rule != nil && rule.Rule.FileAccessType != "" {
		return rule.Rule.FileAccessType
	}
	// Check known command types
	if accessType, ok := defaultFileAccessTypes[cmdName]; ok {
		return accessType
	}
	// Unknown commands default to checking all file rules (returns "ask" to indicate unknown)
	return ""
}

// isPathArgument checks if an argument appears to be a file path.
// Uses heuristics: path indicators (/,./,~) or file extension + existence check.
func (e *Evaluator) isPathArgument(arg, cwd, accessType string) bool {
	// Skip flags
	if strings.HasPrefix(arg, "-") {
		return false
	}

	// Check for obvious path indicators
	if pathutil.IsPathLike(arg) {
		return true
	}

	// Extension heuristic for bare filenames (e.g., "README.md", "file.txt")
	if pathutil.HasFileExtension(arg) {
		// Verify existence based on access type
		absPath := pathutil.ResolvePath(arg, cwd, e.matchCtx.PathVars.Home)
		switch accessType {
		case "Write":
			// For write operations, check if parent directory exists
			return pathutil.DirExists(filepath.Dir(absPath))
		default:
			// For read/edit operations, check if file exists
			return pathutil.FileExists(absPath)
		}
	}

	return false
}

// checkCommandFileArgs checks file arguments against file rules.
// Returns a result that should be combined with the command's normal evaluation.
func (e *Evaluator) checkCommandFileArgs(cmd Command, rule *TrackedRule) Result {
	result := Result{Action: "allow"}

	// Get arguments (excluding command name)
	args := cmd.Args
	if len(args) > 0 {
		args = args[1:]
	}
	if len(args) == 0 {
		return result
	}

	// Get the default access type for this command
	defaultAccessType := e.getFileAccessType(cmd.Name, rule)

	logDebug("    Checking file args (default_access_type=%q)", defaultAccessType)

	for i, arg := range args {
		posKey := strconv.Itoa(i) // "0", "1", etc. (0-based)

		// Determine the access type for this argument
		var accessType string

		// Check if this position has a rule: prefix pattern (positional file rule)
		if rule != nil && rule.Rule.Args.Position != nil {
			if fp, ok := rule.Rule.Args.Position[posKey]; ok && len(fp.Patterns) > 0 {
				// Use the first pattern to determine file rule type
				p, err := ParsePattern(fp.Patterns[0])
				if err == nil && p.IsFileRulePattern() {
					accessType = p.FileRuleType
					logDebug("      Arg[%d] %q: using positional rule type %q", i, arg, accessType)
				}
			}
		}

		// Fall back to default access type if no positional rule
		if accessType == "" {
			accessType = defaultAccessType
		}

		// If we still don't have an access type, skip this arg
		if accessType == "" {
			continue
		}

		// Check if this looks like a path argument
		if !e.isPathArgument(arg, cmd.EffectiveCwd, accessType) {
			continue
		}

		// Resolve to absolute path
		absPath := pathutil.ResolvePath(arg, cmd.EffectiveCwd, e.matchCtx.PathVars.Home)
		logDebug("      Arg[%d] %q -> %q: checking %s rules", i, arg, absPath, accessType)

		// Check against file rules
		fileResult := checkFilePathAgainstRules(e.merged, accessType, absPath, e.matchCtx)
		fileResult.Command = cmd.Name
		if fileResult.Action == "deny" {
			fileResult.Message = "File argument denied: " + arg
		}

		result = combineResults(result, fileResult)
		if result.Action == "deny" {
			return result // Early exit on deny
		}
	}

	return result
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

	// No pattern rule matched - check file rules if enabled AND there are file rules configured
	if e.merged.RedirectsPolicy.RespectFileRules.Value == "true" && e.hasFileRulesConfigured() {
		// Determine file access type based on redirect direction
		accessType := "Write"
		if redir.IsInput {
			accessType = "Read"
		}

		// Resolve target path
		absPath := pathutil.ResolvePath(redir.Target, e.matchCtx.PathVars.Cwd, e.matchCtx.PathVars.Home)
		logDebug("    Checking redirect target against %s file rules: %q -> %q", accessType, redir.Target, absPath)

		fileResult := checkFilePathAgainstRules(e.merged, accessType, absPath, e.matchCtx)
		if fileResult.Action == "deny" {
			fileResult.Message = "Redirect target denied: " + redir.Target
			return fileResult
		}
		if fileResult.Action == "allow" {
			return fileResult
		}
		// If "ask", fall through to policy default
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
	// Apply template substitution
	tmplCtx := newRedirectTemplateContext(redir, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

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
	// Apply template substitution
	tmplCtx := newHeredocTemplateContext(hdoc, e.matchCtx)
	msg = templateMessage(msg, tmplCtx)

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
//   - "path:..." - path pattern matched against resolved path (if path-like) or command name (if glob-like)
//   - "re:..." - regex matched against command name
//   - literal string - exact match against command name
func (e *Evaluator) matchRuleCommand(ruleCommand string, cmd Command) bool {
	if strings.HasPrefix(ruleCommand, "path:") {
		// Path pattern - first check if it matches the resolved path
		if cmd.ResolvedPath != "" {
			p, err := ParsePattern(ruleCommand)
			if err != nil {
				return false
			}
			if p.MatchWithContext(cmd.ResolvedPath, e.matchCtx) {
				return true
			}
		}
		// Also try matching against command name (for glob-like patterns like "path:*")
		p, err := ParsePattern(ruleCommand)
		if err != nil {
			return false
		}
		return p.MatchWithContext(cmd.Name, e.matchCtx)
	}
	// Parse and match against command name
	p, err := ParsePattern(ruleCommand)
	if err != nil {
		return false
	}
	return p.MatchWithContext(cmd.Name, e.matchCtx)
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
	for _, elem := range rule.Args.AnyMatch {
		if matchElementContains(elem, "$HOME") {
			return true
		}
	}
	for _, elem := range rule.Args.AllMatch {
		if matchElementContains(elem, "$HOME") {
			return true
		}
	}
	for _, fp := range rule.Args.Position {
		for _, p := range fp.Patterns {
			if strings.Contains(p, "$HOME") {
				return true
			}
		}
	}
	return false
}

// mergedConfigUsesPluginRoot checks if any pattern in the merged config uses $CLAUDE_PLUGIN_ROOT.
func mergedConfigUsesPluginRoot(m *MergedConfig) bool {
	// Check commands.allow.names
	for _, entry := range m.CommandsAllow {
		if strings.Contains(entry.Name, "$CLAUDE_PLUGIN_ROOT") {
			return true
		}
	}

	// Check commands.deny.names
	for _, entry := range m.CommandsDeny {
		if strings.Contains(entry.Name, "$CLAUDE_PLUGIN_ROOT") {
			return true
		}
	}

	// Check rules
	for _, tr := range m.Rules {
		if ruleUsesPluginRoot(tr.Rule) {
			return true
		}
	}

	// Check redirect rules
	for _, rr := range m.Redirects {
		for _, p := range rr.To.Pattern {
			if strings.Contains(p, "$CLAUDE_PLUGIN_ROOT") {
				return true
			}
		}
	}

	// Check heredoc rules
	for _, hr := range m.Heredocs {
		for _, p := range hr.ContentMatch {
			if strings.Contains(p, "$CLAUDE_PLUGIN_ROOT") {
				return true
			}
		}
	}

	return false
}

// ruleUsesPluginRoot checks if a rule uses $CLAUDE_PLUGIN_ROOT in any of its patterns.
func ruleUsesPluginRoot(rule Rule) bool {
	if strings.Contains(rule.Command, "$CLAUDE_PLUGIN_ROOT") {
		return true
	}
	for _, elem := range rule.Args.AnyMatch {
		if matchElementContains(elem, "$CLAUDE_PLUGIN_ROOT") {
			return true
		}
	}
	for _, elem := range rule.Args.AllMatch {
		if matchElementContains(elem, "$CLAUDE_PLUGIN_ROOT") {
			return true
		}
	}
	for _, fp := range rule.Args.Position {
		for _, p := range fp.Patterns {
			if strings.Contains(p, "$CLAUDE_PLUGIN_ROOT") {
				return true
			}
		}
	}
	return false
}

// matchElement checks if a MatchElement matches the args.
// For string patterns: any arg matches the pattern.
// For sequence objects: consecutive args match relative positions.
func matchElement(args []string, elem MatchElement, ctx *MatchContext) bool {
	if elem.IsSequence {
		return matchSequence(args, elem.Sequence, ctx)
	}
	// String pattern: any arg matches
	return matchAnyArg(args, elem.Pattern, ctx)
}

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

	// Find max position index in the sequence
	maxPos := 0
	for posStr := range seq {
		if pos, err := strconv.Atoi(posStr); err == nil && pos > maxPos {
			maxPos = pos
		}
	}

	// Slide window over args
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

// matchPositionFlexible checks if the arg at a position matches any of the patterns (OR semantics).
func matchPositionFlexible(args []string, pos int, patterns []string, ctx *MatchContext) bool {
	if pos < 0 || pos >= len(args) {
		return false
	}
	for _, pattern := range patterns {
		if MatchPositionWithContext(args, pos, pattern, ctx) {
			return true // OR: any pattern matches
		}
	}
	return false
}

// matchElementContains checks if a MatchElement contains a substring in any pattern.
func matchElementContains(elem MatchElement, substr string) bool {
	if elem.IsSequence {
		for _, fp := range elem.Sequence {
			for _, p := range fp.Patterns {
				if strings.Contains(p, substr) {
					return true
				}
			}
		}
	} else {
		if strings.Contains(elem.Pattern, substr) {
			return true
		}
	}
	return false
}
