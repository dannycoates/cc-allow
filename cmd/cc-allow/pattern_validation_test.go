package main

import (
	"strings"
	"testing"
)

// These tests verify that invalid patterns are properly detected and reported.

func TestInvalidRegexInArgsAnyCausesParseError(t *testing.T) {
	// Config with invalid regex should fail to parse
	config := `
version = "2.0"
[[bash.deny.rm]]
message = "Should deny rm with recursive flag"
args.any = ["re:[invalid"]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Expected parse error for invalid regex in args.any")
	}
}

func TestInvalidRegexInArgsAllCausesParseError(t *testing.T) {
	config := `
version = "2.0"
[[bash.deny.rm]]
message = "Should deny rm"
args.all = ["-r", "re:(unclosed"]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Expected parse error for invalid regex in args.all")
	}
}

func TestInvalidRegexInPositionCausesParseError(t *testing.T) {
	config := `
version = "2.0"
[[bash.deny.chmod]]
message = "Should deny chmod 777"
args.position = { "0" = "re:777[" }
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Expected parse error for invalid regex in args.position")
	}
}

func TestInvalidRegexInRedirectPathsCausesParseError(t *testing.T) {
	config := `
version = "2.0"
[[bash.redirects.deny]]
message = "Should deny redirects to /etc"
paths = ["re:/etc/["]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Expected parse error for invalid regex in redirect paths")
	}
}

func TestInvalidRegexInHeredocContentCausesParseError(t *testing.T) {
	config := `
version = "2.0"
[bash.constructs]
heredocs = "allow"

[[bash.heredocs.deny]]
message = "Should deny heredocs with DROP TABLE"
content.any = ["re:DROP TABLE["]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Expected parse error for invalid regex in heredoc content")
	}
}

func TestValidateChecksAllowCommands(t *testing.T) {
	config := `
version = "2.0"
[bash.allow]
commands = ["path:/valid/**", "re:[invalid"]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Validate() should catch invalid patterns in bash.allow.commands")
	}
	if err != nil && !strings.Contains(err.Error(), "bash.allow.commands") {
		t.Errorf("Error should mention bash.allow.commands, got: %v", err)
	}
}

func TestValidateChecksDenyCommands(t *testing.T) {
	config := `
version = "2.0"
[bash.deny]
commands = ["re:[invalid"]
`
	_, err := ParseConfig(config)
	if err == nil {
		t.Errorf("Validate() should catch invalid patterns in bash.deny.commands")
	}
	if err != nil && !strings.Contains(err.Error(), "bash.deny.commands") {
		t.Errorf("Error should mention bash.deny.commands, got: %v", err)
	}
}

func TestValidPatternsPass(t *testing.T) {
	config := `
version = "2.0"
[bash]
default = "ask"

[bash.allow]
commands = ["ls", "cat", "path:/usr/bin/*", "re:^echo$"]

[bash.deny]
commands = ["sudo"]

[[bash.deny.rm]]
message = "Recursive rm denied"
args.any = ["flags:r", "-rf", "--recursive"]

[[bash.redirects.deny]]
paths = ["path:/etc/**", "re:.*\\.conf$"]

[[bash.heredocs.deny]]
content.any = ["re:DROP\\s+TABLE", "re:DELETE\\s+FROM"]

[read.deny]
paths = ["path:**/*.key", "re:.*\\.pem$"]
`
	_, err := ParseConfig(config)
	if err != nil {
		t.Errorf("Valid patterns should parse without error: %v", err)
	}
}
