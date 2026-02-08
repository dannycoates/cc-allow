package main

// Config merging logic for cc-allow v2 format.
// Handles merging multiple configs with stricter-wins semantics.

import "maps"

// mergeTrackedAction merges an action field, keeping the stricter value.
// Accepts a raw string from TOML config and converts to Action.
func mergeTrackedAction(current Tracked[Action], newVal string, newSource string) Tracked[Action] {
	if newVal == "" {
		return current
	}
	action := Action(newVal)
	if !current.IsSet() {
		return Tracked[Action]{Value: action, Source: newSource}
	}
	if action.Priority() > current.Value.Priority() {
		return Tracked[Action]{Value: action, Source: newSource}
	}
	return current
}

// mergeTrackedString merges a string field (later non-empty values win).
func mergeTrackedString(current Tracked[string], newVal, newSource string) Tracked[string] {
	if newVal == "" {
		return current
	}
	return Tracked[string]{Value: newVal, Source: newSource}
}

// mergeTrackedBool merges a *bool into a Tracked[bool] (later values win).
func mergeTrackedBool(current Tracked[bool], newVal *bool, newSource string) Tracked[bool] {
	if newVal == nil {
		return current
	}
	return Tracked[bool]{Value: *newVal, Source: newSource}
}

// newEmptyMergedConfig creates a MergedConfig with all fields unset.
func newEmptyMergedConfig() *MergedConfig {
	return &MergedConfig{
		Sources:       []string{},
		CommandsDeny:  []TrackedCommandEntry{},
		CommandsAllow: []TrackedCommandEntry{},
		Files: MergedFilesConfig{
			DefaultMessage: make(map[string]Tracked[string]),
			Allow:          make(map[string][]TrackedFilePatternEntry),
			Deny:           make(map[string][]TrackedFilePatternEntry),
		},
		Aliases:   make(map[string]Alias),
		Rules:     []TrackedRule[BashRule]{},
		Redirects: []TrackedRule[RedirectRule]{},
		Heredocs:  []TrackedRule[HeredocRule]{},
	}
}

// mergeConfigInto merges a config into an existing MergedConfig.
func mergeConfigInto(merged *MergedConfig, cfg *Config) {
	source := cfg.Path
	merged.Sources = append(merged.Sources, source)

	// Merge bash policy fields
	merged.Policy.Default = mergeTrackedAction(merged.Policy.Default, cfg.Bash.Default, source)
	merged.Policy.DynamicCommands = mergeTrackedAction(merged.Policy.DynamicCommands, cfg.Bash.DynamicCommands, source)
	merged.Policy.UnresolvedCommands = mergeTrackedAction(merged.Policy.UnresolvedCommands, cfg.Bash.UnresolvedCommands, source)
	merged.Policy.DefaultMessage = mergeTrackedString(merged.Policy.DefaultMessage, cfg.Bash.DefaultMessage, source)
	merged.Policy.RespectFileRules = mergeTrackedBool(merged.Policy.RespectFileRules, cfg.Bash.RespectFileRules, source)

	// Merge constructs
	merged.Constructs.Subshells = mergeTrackedAction(merged.Constructs.Subshells, cfg.Bash.Constructs.Subshells, source)
	merged.Constructs.FunctionDefinitions = mergeTrackedAction(merged.Constructs.FunctionDefinitions, cfg.Bash.Constructs.FunctionDefinitions, source)
	merged.Constructs.Background = mergeTrackedAction(merged.Constructs.Background, cfg.Bash.Constructs.Background, source)
	merged.Constructs.Heredocs = mergeTrackedAction(merged.Constructs.Heredocs, cfg.Bash.Constructs.Heredocs, source)

	// Merge bash.deny.commands (union)
	for _, cmd := range cfg.Bash.Deny.Commands {
		merged.CommandsDeny = append(merged.CommandsDeny, TrackedCommandEntry{
			Name:    cmd,
			Source:  source,
			Message: cfg.Bash.Deny.Message,
		})
	}

	// Merge bash.allow.commands (union or replace)
	if cfg.Bash.Allow.Mode == "replace" {
		merged.CommandsAllow = merged.CommandsAllow[:0]
		// Remove allow-action rules from earlier configs
		filtered := merged.Rules[:0]
		for _, r := range merged.Rules {
			if r.Rule.Action != ActionAllow {
				filtered = append(filtered, r)
			}
		}
		merged.Rules = filtered
	}
	for _, cmd := range cfg.Bash.Allow.Commands {
		merged.CommandsAllow = append(merged.CommandsAllow, TrackedCommandEntry{
			Name:    cmd,
			Source:  source,
			Message: cfg.Bash.Allow.Message,
		})
	}

	// Merge bash rules with shadowing detection
	merged.Rules = mergeRules(merged.Rules, cfg.getParsedRules(), source)

	// Merge redirect policy
	merged.RedirectsPolicy.RespectFileRules = mergeTrackedBool(
		merged.RedirectsPolicy.RespectFileRules, cfg.Bash.Redirects.RespectFileRules, source)

	// Merge redirect rules
	merged.Redirects = mergeRedirectRules(merged.Redirects, cfg.getParsedRedirects(), source)

	// Merge heredoc rules
	merged.Heredocs = mergeHeredocRules(merged.Heredocs, cfg.getParsedHeredocs(), source)

	// Merge file tool configs
	mergeFileToolConfig(&merged.Files, "Read", &cfg.Read, source)
	mergeFileToolConfig(&merged.Files, "Write", &cfg.Write, source)
	mergeFileToolConfig(&merged.Files, "Edit", &cfg.Edit, source)

	// Merge WebFetch URL patterns (reuses file tool merge infrastructure)
	mergeFileToolConfig(&merged.Files, "WebFetch", &cfg.WebFetch.FileToolConfig, source)

	// Merge Safe Browsing settings (strictest wins: once enabled, stays enabled)
	if cfg.WebFetch.SafeBrowsing.Enabled {
		merged.SafeBrowsing.Enabled = true
	}
	if cfg.WebFetch.SafeBrowsing.APIKey != "" {
		merged.SafeBrowsing.APIKey = cfg.WebFetch.SafeBrowsing.APIKey
	}

	// Merge aliases (later configs can add or override)
	maps.Copy(merged.Aliases, cfg.Aliases)

	// Debug config
	if cfg.Debug.LogFile != "" {
		merged.Debug.LogFile = cfg.Debug.LogFile
	}
}

// mergeFileToolConfig merges a file tool config into the merged files config.
func mergeFileToolConfig(merged *MergedFilesConfig, toolName string, cfg *FileToolConfig, source string) {
	// Merge default (stricter wins)
	merged.Default = mergeTrackedAction(merged.Default, cfg.Default, source)

	// Merge default message per tool (later configs override)
	if cfg.DefaultMessage != "" {
		merged.DefaultMessage[toolName] = Tracked[string]{Value: cfg.DefaultMessage, Source: source}
	}

	// Merge deny patterns (union)
	for _, path := range cfg.Deny.Paths {
		merged.Deny[toolName] = append(merged.Deny[toolName], TrackedFilePatternEntry{
			Pattern: path,
			Source:  source,
			Message: cfg.Deny.Message,
		})
	}

	// Merge allow patterns (union or replace)
	if cfg.Allow.Mode == "replace" {
		merged.Allow[toolName] = merged.Allow[toolName][:0]
	}
	for _, path := range cfg.Allow.Paths {
		merged.Allow[toolName] = append(merged.Allow[toolName], TrackedFilePatternEntry{
			Pattern: path,
			Source:  source,
		})
	}
}

// applyMergedDefaults fills in system defaults for unset fields.
func applyMergedDefaults(merged *MergedConfig) {
	if !merged.Policy.Default.IsSet() {
		merged.Policy.Default = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Policy.DynamicCommands.IsSet() {
		merged.Policy.DynamicCommands = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Policy.UnresolvedCommands.IsSet() {
		merged.Policy.UnresolvedCommands = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Policy.DefaultMessage.IsSet() {
		merged.Policy.DefaultMessage = Tracked[string]{Value: "Command not allowed", Source: "(default)"}
	}
	if !merged.Policy.RespectFileRules.IsSet() {
		merged.Policy.RespectFileRules = Tracked[bool]{Value: true, Source: "(default)"}
	}
	if !merged.Constructs.Subshells.IsSet() {
		merged.Constructs.Subshells = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Constructs.FunctionDefinitions.IsSet() {
		merged.Constructs.FunctionDefinitions = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Constructs.Background.IsSet() {
		merged.Constructs.Background = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if !merged.Constructs.Heredocs.IsSet() {
		merged.Constructs.Heredocs = Tracked[Action]{Value: ActionAllow, Source: "(default)"}
	}
	if !merged.Files.Default.IsSet() {
		merged.Files.Default = Tracked[Action]{Value: ActionAsk, Source: "(default)"}
	}
	if _, ok := merged.Files.DefaultMessage["Read"]; !ok {
		merged.Files.DefaultMessage["Read"] = Tracked[string]{Value: "File read requires approval: {{.FilePath}}", Source: "(default)"}
	}
	if _, ok := merged.Files.DefaultMessage["Write"]; !ok {
		merged.Files.DefaultMessage["Write"] = Tracked[string]{Value: "File write requires approval: {{.FilePath}}", Source: "(default)"}
	}
	if _, ok := merged.Files.DefaultMessage["Edit"]; !ok {
		merged.Files.DefaultMessage["Edit"] = Tracked[string]{Value: "File edit requires approval: {{.FilePath}}", Source: "(default)"}
	}
	if _, ok := merged.Files.DefaultMessage["WebFetch"]; !ok {
		merged.Files.DefaultMessage["WebFetch"] = Tracked[string]{Value: "URL fetch requires approval: {{.FilePath}}", Source: "(default)"}
	}
	if !merged.RedirectsPolicy.RespectFileRules.IsSet() {
		merged.RedirectsPolicy.RespectFileRules = Tracked[bool]{Value: false, Source: "(default)"}
	}
}

// MergeConfigs merges multiple configs into a single MergedConfig.
func MergeConfigs(configs []*Config) *MergedConfig {
	merged := newEmptyMergedConfig()
	for _, cfg := range configs {
		mergeConfigInto(merged, cfg)
	}
	applyMergedDefaults(merged)
	return merged
}

// rulesExactMatch returns true if two rules have identical patterns.
// Rules with different args or pipe conditions are not considered exact matches.
func rulesExactMatch(a, b BashRule) bool {
	if a.Command != b.Command {
		return false
	}
	if !slicesEqual(a.Subcommands, b.Subcommands) {
		return false
	}
	// Check pipe conditions
	if !slicesEqual(a.Pipe.To, b.Pipe.To) {
		return false
	}
	if !slicesEqual(a.Pipe.From, b.Pipe.From) {
		return false
	}
	// Check if args conditions differ
	if !argsMatchEqual(a.Args, b.Args) {
		return false
	}
	return true
}

// argsMatchEqual compares two ArgsMatch for equality.
func argsMatchEqual(a, b ArgsMatch) bool {
	// Check if both have or don't have Any/All/Not/Xor
	if (a.Any == nil) != (b.Any == nil) {
		return false
	}
	if (a.All == nil) != (b.All == nil) {
		return false
	}
	if (a.Not == nil) != (b.Not == nil) {
		return false
	}
	if (a.Xor == nil) != (b.Xor == nil) {
		return false
	}
	// Check position map lengths (quick check)
	if len(a.Position) != len(b.Position) {
		return false
	}
	// For non-nil boolean expressions, compare patterns
	if a.Any != nil && !boolExprPatternsEqual(a.Any, b.Any) {
		return false
	}
	if a.All != nil && !boolExprPatternsEqual(a.All, b.All) {
		return false
	}
	if a.Not != nil && !boolExprPatternsEqual(a.Not, b.Not) {
		return false
	}
	if a.Xor != nil && !boolExprPatternsEqual(a.Xor, b.Xor) {
		return false
	}
	// Check position patterns
	for k, va := range a.Position {
		vb, ok := b.Position[k]
		if !ok {
			return false
		}
		if !slicesEqual(va.Patterns, vb.Patterns) {
			return false
		}
	}
	return true
}

// boolExprPatternsEqual compares two BoolExpr for equality.
func boolExprPatternsEqual(a, b *BoolExpr) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Compare patterns
	if !slicesEqual(a.Patterns, b.Patterns) {
		return false
	}
	// Compare isSequence and sequence contents
	if a.IsSequence != b.IsSequence {
		return false
	}
	if len(a.Sequence) != len(b.Sequence) {
		return false
	}
	for k, va := range a.Sequence {
		vb, ok := b.Sequence[k]
		if !ok || !slicesEqual(va.Patterns, vb.Patterns) {
			return false
		}
	}
	// Compare nested structures lengths
	if len(a.Any) != len(b.Any) || len(a.All) != len(b.All) || len(a.Xor) != len(b.Xor) {
		return false
	}
	// Recursively compare nested Any/All/Xor
	for i := range a.Any {
		if !boolExprPatternsEqual(a.Any[i], b.Any[i]) {
			return false
		}
	}
	for i := range a.All {
		if !boolExprPatternsEqual(a.All[i], b.All[i]) {
			return false
		}
	}
	for i := range a.Xor {
		if !boolExprPatternsEqual(a.Xor[i], b.Xor[i]) {
			return false
		}
	}
	if (a.Not == nil) != (b.Not == nil) {
		return false
	}
	if a.Not != nil && !boolExprPatternsEqual(a.Not, b.Not) {
		return false
	}
	return true
}

// slicesEqual compares two string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mergeRules merges new rules into existing rules with shadowing detection.
func mergeRules(merged []TrackedRule[BashRule], newRules []BashRule, newSource string) []TrackedRule[BashRule] {
	for _, newRule := range newRules {
		tr := TrackedRule[BashRule]{Rule: newRule, Source: newSource}

		// Check for shadowing
		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if rulesExactMatch(existing.Rule, newRule) {
				if newRule.Action.Priority() > existing.Rule.Action.Priority() {
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					tr.Shadowed = true
				}
				break
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// redirectRulesExactMatch returns true if two redirect rules have identical patterns.
func redirectRulesExactMatch(a, b RedirectRule) bool {
	aAppend := a.Append != nil && *a.Append
	bAppend := b.Append != nil && *b.Append
	if aAppend != bAppend {
		return false
	}
	return slicesEqual(a.Paths, b.Paths)
}

// mergeRedirectRules merges redirect rules with shadowing detection.
func mergeRedirectRules(merged []TrackedRule[RedirectRule], newRules []RedirectRule, newSource string) []TrackedRule[RedirectRule] {
	for _, newRule := range newRules {
		tr := TrackedRule[RedirectRule]{Rule: newRule, Source: newSource}

		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if redirectRulesExactMatch(existing.Rule, newRule) {
				if newRule.Action.Priority() > existing.Rule.Action.Priority() {
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					tr.Shadowed = true
				}
				break
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// mergeHeredocRules merges heredoc rules with shadowing detection.
func mergeHeredocRules(merged []TrackedRule[HeredocRule], newRules []HeredocRule, newSource string) []TrackedRule[HeredocRule] {
	for _, newRule := range newRules {
		tr := TrackedRule[HeredocRule]{Rule: newRule, Source: newSource}
		// Heredoc rules don't shadow each other currently
		merged = append(merged, tr)
	}
	return merged
}
