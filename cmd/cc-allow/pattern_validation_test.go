package main

import (
	"strings"
	"testing"
)

// These tests verify that invalid patterns are properly detected and reported,
// rather than being silently ignored (which could cause security rules to be bypassed).

// ============================================================================
// Tests for fail-safe behavior: invalid configs cause "ask", not silent bypass
// ============================================================================

func TestInvalidRegexInAnyMatchCausesAsk(t *testing.T) {
	// Config with invalid regex - evaluator should validate and ask (defer to Claude Code)
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "allow",
			DynamicCommands: "ask",
		},
		Rules: []Rule{
			{
				Command: "rm",
				Action:  "deny",
				Message: "Should deny rm with recursive flag",
				Args:    ArgsMatch{AnyMatch: []string{"re:[invalid"}}, // Invalid regex!
			},
		},
	}

	// With fail-safe behavior, invalid config should result in "ask"
	r := parseAndEval(t, cfg, "rm -rf /")
	if r.Action != "ask" {
		t.Errorf("Expected ask due to invalid config, got %s", r.Action)
	}
	if !strings.Contains(r.Message, "Config validation error") {
		t.Errorf("Expected config validation error message, got: %s", r.Message)
	}
}

func TestInvalidRegexInAllMatchCausesAsk(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "allow",
			DynamicCommands: "ask",
		},
		Rules: []Rule{
			{
				Command: "rm",
				Action:  "deny",
				Message: "Should deny rm with both -r and -f",
				Args:    ArgsMatch{AllMatch: []string{"-r", "re:(unclosed"}}, // Second pattern invalid
			},
		},
	}

	r := parseAndEval(t, cfg, "rm -r -f /")
	if r.Action != "ask" {
		t.Errorf("Expected ask due to invalid config, got %s", r.Action)
	}
}

func TestInvalidRegexInPositionCausesAsk(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "allow",
			DynamicCommands: "ask",
		},
		Rules: []Rule{
			{
				Command: "chmod",
				Action:  "deny",
				Message: "Should deny chmod 777",
				Args:    ArgsMatch{Position: map[string]string{"0": "re:777["}}, // Invalid regex
			},
		},
	}

	r := parseAndEval(t, cfg, "chmod 777 /etc/passwd")
	if r.Action != "ask" {
		t.Errorf("Expected ask due to invalid config, got %s", r.Action)
	}
}

func TestInvalidRegexInRedirectPatternCausesAsk(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "allow",
			DynamicCommands: "ask",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"echo"}},
		},
		Redirects: []RedirectRule{
			{
				Action:  "deny",
				Message: "Should deny redirects to /etc",
				To:      RedirectTarget{Pattern: []string{"re:/etc/["}}, // Invalid regex
			},
		},
	}

	r := parseAndEval(t, cfg, "echo test > /etc/passwd")
	if r.Action != "ask" {
		t.Errorf("Expected ask due to invalid config, got %s", r.Action)
	}
}

func TestInvalidRegexInHeredocContentMatchCausesAsk(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			Default:         "allow",
			DynamicCommands: "ask",
		},
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"cat"}},
		},
		Constructs: ConstructsConfig{
			Heredocs: "allow",
		},
		Heredocs: []HeredocRule{
			{
				Action:       "deny",
				Message:      "Should deny heredocs with DROP TABLE",
				ContentMatch: []string{"re:DROP TABLE["}, // Invalid regex
			},
		},
	}

	r := parseAndEval(t, cfg, "cat <<EOF\nDROP TABLE users;\nEOF")
	if r.Action != "ask" {
		t.Errorf("Expected ask due to invalid config, got %s", r.Action)
	}
}

// ============================================================================
// Tests for Config.Validate() checking all pattern locations
// ============================================================================

func TestValidateChecksCommandsAllowNames(t *testing.T) {
	// commands.allow.names can have patterns that should be validated
	cfg := &Config{
		Commands: CommandsConfig{
			Allow: CommandList{Names: []string{"path:/valid/**", "re:[invalid"}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid patterns in commands.allow.names")
	}
	if err != nil && !strings.Contains(err.Error(), "commands.allow.names") {
		t.Errorf("Error should mention commands.allow.names, got: %v", err)
	}
}

func TestValidateChecksCommandsDenyNames(t *testing.T) {
	// commands.deny.names can have patterns that should be validated
	cfg := &Config{
		Commands: CommandsConfig{
			Deny: CommandList{Names: []string{"re:[invalid"}},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid patterns in commands.deny.names")
	}
	if err != nil && !strings.Contains(err.Error(), "commands.deny.names") {
		t.Errorf("Error should mention commands.deny.names, got: %v", err)
	}
}

func TestValidateChecksRuleCommand(t *testing.T) {
	// rule.command can have patterns that should be validated
	cfg := &Config{
		Rules: []Rule{
			{
				Command: "re:[invalid", // Invalid regex pattern
				Action:  "deny",
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid patterns in rule.command")
	}
	if err != nil && !strings.Contains(err.Error(), "command") {
		t.Errorf("Error should mention command, got: %v", err)
	}
}

// ============================================================================
// Positive tests: Validate() DOES catch these (existing correct behavior)
// ============================================================================

func TestValidateCatchesInvalidArgsAnyMatch(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{
				Command: "test",
				Action:  "deny",
				Args:    ArgsMatch{AnyMatch: []string{"re:[invalid"}},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid regex in args.any_match")
	}
	if err != nil && !strings.Contains(err.Error(), "any_match") {
		t.Errorf("Error should mention any_match, got: %v", err)
	}
}

func TestValidateCatchesInvalidArgsAllMatch(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{
				Command: "test",
				Action:  "deny",
				Args:    ArgsMatch{AllMatch: []string{"re:(unclosed"}},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid regex in args.all_match")
	}
}

func TestValidateCatchesInvalidArgsPosition(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			{
				Command: "test",
				Action:  "deny",
				Args:    ArgsMatch{Position: map[string]string{"0": "re:[bad"}},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid regex in args.position")
	}
}

func TestValidateCatchesInvalidRedirectPattern(t *testing.T) {
	cfg := &Config{
		Redirects: []RedirectRule{
			{
				Action: "deny",
				To:     RedirectTarget{Pattern: []string{"re:[bad"}},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid regex in redirect.to.pattern")
	}
}

func TestValidateCatchesInvalidHeredocContentMatch(t *testing.T) {
	cfg := &Config{
		Heredocs: []HeredocRule{
			{
				Action:       "deny",
				ContentMatch: []string{"re:[bad"},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Errorf("Validate() should catch invalid regex in heredoc.content_match")
	}
}
