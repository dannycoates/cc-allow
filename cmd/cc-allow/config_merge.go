package main

// Config merging logic for cc-allow.
// Handles merging multiple configs with stricter-wins semantics and shadowing detection.

// actionStrictness returns the strictness level of an action.
// Higher values are stricter: deny(2) > ask(1) > allow(0).
// Empty string (unset) returns -1.
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

// mergeTrackedValue merges a policy field, keeping the stricter value.
// If current is unset (empty), any new value is accepted.
// If new is unset, current is kept.
// Otherwise, new only wins if it's stricter.
func mergeTrackedValue(current TrackedValue, newVal, newSource string) TrackedValue {
	// If new is unset, keep current
	if newVal == "" {
		return current
	}
	// If current is unset, accept new
	if current.Value == "" {
		return TrackedValue{Value: newVal, Source: newSource}
	}
	// Both set - new wins only if stricter
	if isStricter(newVal, current.Value) {
		return TrackedValue{Value: newVal, Source: newSource}
	}
	return current
}

// mergeTrackedMessage merges a message field.
// Unlike policy fields, messages don't have strictness - later non-empty values win.
func mergeTrackedMessage(current TrackedValue, newVal, newSource string) TrackedValue {
	if newVal == "" {
		return current
	}
	// Non-empty new value overwrites
	return TrackedValue{Value: newVal, Source: newSource}
}

// newEmptyMergedConfig creates a MergedConfig with all fields unset.
func newEmptyMergedConfig() *MergedConfig {
	return &MergedConfig{
		Sources:       []string{},
		CommandsDeny:  []TrackedCommandEntry{},
		CommandsAllow: []TrackedCommandEntry{},
		Rules:         []TrackedRule{},
		Redirects:     []TrackedRedirectRule{},
		Heredocs:      []TrackedHeredocRule{},
	}
}

// mergeConfigInto merges a raw config into an existing MergedConfig.
// The raw config can only make things stricter, not looser.
func mergeConfigInto(merged *MergedConfig, cfg *Config) {
	source := cfg.Path
	merged.Sources = append(merged.Sources, source)

	// Merge policy fields (stricter wins)
	merged.Policy.Default = mergeTrackedValue(merged.Policy.Default, cfg.Policy.Default, source)
	merged.Policy.DynamicCommands = mergeTrackedValue(merged.Policy.DynamicCommands, cfg.Policy.DynamicCommands, source)
	merged.Policy.UnresolvedCommands = mergeTrackedValue(merged.Policy.UnresolvedCommands, cfg.Policy.UnresolvedCommands, source)
	merged.Policy.DefaultMessage = mergeTrackedMessage(merged.Policy.DefaultMessage, cfg.Policy.DefaultMessage, source)

	// Merge allowed_paths (union)
	for _, p := range cfg.Policy.AllowedPaths {
		merged.Policy.AllowedPaths = append(merged.Policy.AllowedPaths, p)
		merged.Policy.AllowedPathsSources = append(merged.Policy.AllowedPathsSources, source)
	}

	// Merge constructs (stricter wins)
	merged.Constructs.Subshells = mergeTrackedValue(merged.Constructs.Subshells, cfg.Constructs.Subshells, source)
	merged.Constructs.FunctionDefinitions = mergeTrackedValue(merged.Constructs.FunctionDefinitions, cfg.Constructs.FunctionDefinitions, source)
	merged.Constructs.Background = mergeTrackedValue(merged.Constructs.Background, cfg.Constructs.Background, source)
	merged.Constructs.Heredocs = mergeTrackedValue(merged.Constructs.Heredocs, cfg.Constructs.Heredocs, source)

	// Merge commands.deny list (union - anything denied anywhere stays denied)
	for _, name := range cfg.Commands.Deny.Names {
		merged.CommandsDeny = append(merged.CommandsDeny, TrackedCommandEntry{
			Name:    name,
			Source:  source,
			Message: cfg.Commands.Deny.Message,
		})
	}

	// Merge commands.allow list (union)
	for _, name := range cfg.Commands.Allow.Names {
		merged.CommandsAllow = append(merged.CommandsAllow, TrackedCommandEntry{
			Name:    name,
			Source:  source,
			Message: cfg.Commands.Allow.Message,
		})
	}

	// Merge rules with shadowing detection
	merged.Rules = mergeRules(merged.Rules, cfg.Rules, source)

	// Merge redirects with shadowing detection
	merged.Redirects = mergeRedirectRules(merged.Redirects, cfg.Redirects, source)

	// Merge heredocs with shadowing detection
	merged.Heredocs = mergeHeredocRules(merged.Heredocs, cfg.Heredocs, source)

	// Debug config - take non-empty values
	if cfg.Debug.LogFile != "" {
		merged.Debug.LogFile = cfg.Debug.LogFile
	}
}

// applyMergedDefaults fills in system defaults for any unset fields in MergedConfig.
func applyMergedDefaults(merged *MergedConfig) {
	if merged.Policy.Default.Value == "" {
		merged.Policy.Default = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.DynamicCommands.Value == "" {
		merged.Policy.DynamicCommands = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.UnresolvedCommands.Value == "" {
		merged.Policy.UnresolvedCommands = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Policy.DefaultMessage.Value == "" {
		merged.Policy.DefaultMessage = TrackedValue{Value: "Command not allowed", Source: "(default)"}
	}
	if merged.Constructs.Subshells.Value == "" {
		merged.Constructs.Subshells = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.FunctionDefinitions.Value == "" {
		merged.Constructs.FunctionDefinitions = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.Background.Value == "" {
		merged.Constructs.Background = TrackedValue{Value: "ask", Source: "(default)"}
	}
	if merged.Constructs.Heredocs.Value == "" {
		merged.Constructs.Heredocs = TrackedValue{Value: "allow", Source: "(default)"}
	}
}

// MergeConfigs merges multiple raw configs into a single MergedConfig.
// Configs are processed in order; each can only make things stricter.
func MergeConfigs(configs []*Config) *MergedConfig {
	merged := newEmptyMergedConfig()
	for _, cfg := range configs {
		mergeConfigInto(merged, cfg)
	}
	applyMergedDefaults(merged)
	return merged
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

// mapsEqual compares two string maps for equality.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// rulesExactMatch returns true if two rules have identical command and args patterns.
// Used for shadowing detection - only exact matches are considered overlapping.
func rulesExactMatch(a, b Rule) bool {
	return a.Command == b.Command &&
		slicesEqual(a.Args.Contains, b.Args.Contains) &&
		slicesEqual(a.Args.AnyMatch, b.Args.AnyMatch) &&
		slicesEqual(a.Args.AllMatch, b.Args.AllMatch) &&
		mapsEqual(a.Args.Position, b.Args.Position) &&
		slicesEqual(a.Pipe.To, b.Pipe.To) &&
		slicesEqual(a.Pipe.From, b.Pipe.From)
}

// mergeRules merges new rules into existing rules with shadowing detection.
// If a new rule exactly matches an existing rule:
// - If new is stricter, new shadows existing (existing.Shadowed = true)
// - If new is same or looser, new gets shadowed (new.Shadowed = true)
func mergeRules(merged []TrackedRule, newRules []Rule, newSource string) []TrackedRule {
	for _, newRule := range newRules {
		tr := TrackedRule{Rule: newRule, Source: newSource}

		// Check if this shadows an existing rule (exact same pattern)
		for i, existing := range merged {
			if existing.Shadowed {
				continue // already shadowed, skip
			}
			if rulesExactMatch(existing.Rule, newRule) {
				if isStricter(newRule.Action, existing.Rule.Action) {
					// New rule is stricter, it shadows the existing
					tr.Shadowing = existing.Source
					merged[i].Shadowed = true
				} else {
					// New rule is same or looser, it gets shadowed
					tr.Shadowed = true
				}
				break // only shadow one matching rule
			}
		}
		merged = append(merged, tr)
	}
	return merged
}

// redirectRulesExactMatch returns true if two redirect rules have identical patterns.
func redirectRulesExactMatch(a, b RedirectRule) bool {
	// Check append mode
	aAppend := a.Append != nil && *a.Append
	bAppend := b.Append != nil && *b.Append
	if aAppend != bAppend {
		return false
	}
	return slicesEqual(a.To.Pattern, b.To.Pattern) &&
		slicesEqual(a.To.Exact, b.To.Exact)
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
	return slicesEqual(a.ContentMatch, b.ContentMatch)
}

// mergeHeredocRules merges heredoc rules with shadowing detection.
func mergeHeredocRules(merged []TrackedHeredocRule, newRules []HeredocRule, newSource string) []TrackedHeredocRule {
	for _, newRule := range newRules {
		tr := TrackedHeredocRule{HeredocRule: newRule, Source: newSource}

		for i, existing := range merged {
			if existing.Shadowed {
				continue
			}
			if heredocRulesExactMatch(existing.HeredocRule, newRule) {
				if isStricter(newRule.Action, existing.HeredocRule.Action) {
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
