package main

// Config merging logic for cc-allow v2 format.
// Handles merging multiple configs with stricter-wins semantics.

// actionStrictness returns the strictness level of an action.
// Higher values are stricter: deny(2) > ask(1) > allow(0).
func actionStrictness(action string) int {
	switch action {
	case "deny":
		return 2
	case "ask":
		return 1
	case "allow":
		return 0
	default:
		return -1 // unset or invalid
	}
}

// isStricter returns true if newVal is stricter than currentVal.
func isStricter(newVal, currentVal string) bool {
	return actionStrictness(newVal) > actionStrictness(currentVal)
}

// mergeTrackedAction merges an action field, keeping the stricter value.
func mergeTrackedAction(current Tracked[string], newVal, newSource string) Tracked[string] {
	if newVal == "" {
		return current
	}
	if !current.IsSet() {
		return Tracked[string]{Value: newVal, Source: newSource}
	}
	if isStricter(newVal, current.Value) {
		return Tracked[string]{Value: newVal, Source: newSource}
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
			Allow: make(map[string][]TrackedFilePatternEntry),
			Deny:  make(map[string][]TrackedFilePatternEntry),
		},
		Aliases:   make(map[string]Alias),
		Rules:     []TrackedRule{},
		Redirects: []TrackedRedirectRule{},
		Heredocs:  []TrackedHeredocRule{},
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

	// Merge bash.allow.commands (union)
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

	// Merge aliases (later configs can add or override)
	for name, alias := range cfg.Aliases {
		merged.Aliases[name] = alias
	}

	// Debug config
	if cfg.Debug.LogFile != "" {
		merged.Debug.LogFile = cfg.Debug.LogFile
	}
}

// mergeFileToolConfig merges a file tool config into the merged files config.
func mergeFileToolConfig(merged *MergedFilesConfig, toolName string, cfg *FileToolConfig, source string) {
	// Merge default (stricter wins)
	merged.Default = mergeTrackedAction(merged.Default, cfg.Default, source)

	// Merge deny patterns (union)
	for _, path := range cfg.Deny.Paths {
		merged.Deny[toolName] = append(merged.Deny[toolName], TrackedFilePatternEntry{
			Pattern: path,
			Source:  source,
			Message: cfg.Deny.Message,
		})
	}

	// Merge allow patterns (union)
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
		merged.Policy.Default = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Policy.DynamicCommands.IsSet() {
		merged.Policy.DynamicCommands = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Policy.UnresolvedCommands.IsSet() {
		merged.Policy.UnresolvedCommands = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Policy.DefaultMessage.IsSet() {
		merged.Policy.DefaultMessage = Tracked[string]{Value: "Command not allowed", Source: "(default)"}
	}
	if !merged.Policy.RespectFileRules.IsSet() {
		merged.Policy.RespectFileRules = Tracked[bool]{Value: true, Source: "(default)"}
	}
	if !merged.Constructs.Subshells.IsSet() {
		merged.Constructs.Subshells = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Constructs.FunctionDefinitions.IsSet() {
		merged.Constructs.FunctionDefinitions = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Constructs.Background.IsSet() {
		merged.Constructs.Background = Tracked[string]{Value: "ask", Source: "(default)"}
	}
	if !merged.Constructs.Heredocs.IsSet() {
		merged.Constructs.Heredocs = Tracked[string]{Value: "allow", Source: "(default)"}
	}
	if !merged.Files.Default.IsSet() {
		merged.Files.Default = Tracked[string]{Value: "ask", Source: "(default)"}
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
func mergeRules(merged []TrackedRule, newRules []BashRule, newSource string) []TrackedRule {
	for _, newRule := range newRules {
		tr := TrackedRule{BashRule: newRule, Source: newSource}

		// Check for shadowing
		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if rulesExactMatch(existing.BashRule, newRule) {
				if isStricter(newRule.Action, existing.BashRule.Action) {
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
func mergeRedirectRules(merged []TrackedRedirectRule, newRules []RedirectRule, newSource string) []TrackedRedirectRule {
	for _, newRule := range newRules {
		tr := TrackedRedirectRule{RedirectRule: newRule, Source: newSource}

		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if redirectRulesExactMatch(existing.RedirectRule, newRule) {
				if isStricter(newRule.Action, existing.RedirectRule.Action) {
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

// heredocRulesExactMatch returns true if two heredoc rules have identical patterns.
func heredocRulesExactMatch(a, b HeredocRule) bool {
	// Compare content patterns - simplified for now
	return false // No exact match detection for heredocs
}

// mergeHeredocRules merges heredoc rules with shadowing detection.
func mergeHeredocRules(merged []TrackedHeredocRule, newRules []HeredocRule, newSource string) []TrackedHeredocRule {
	for _, newRule := range newRules {
		tr := TrackedHeredocRule{HeredocRule: newRule, Source: newSource}
		// Heredoc rules don't shadow each other currently
		merged = append(merged, tr)
	}
	return merged
}
