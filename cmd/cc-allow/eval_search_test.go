package main

import (
	"os"
	"testing"
)

func TestEvalSearchTool(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		tool       ToolName
		searchPath string
		wantAction Action
	}{
		{
			name: "glob allow in project root",
			config: `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/project/**"]
[read]
default = "allow"
[read.allow]
paths = ["path:/project/**"]
`,
			tool:       ToolGlob,
			searchPath: "/project/src",
			wantAction: ActionAllow,
		},
		{
			name: "grep allow in project root",
			config: `
version = "2.0"
[grep]
default = "allow"
[grep.allow]
paths = ["path:/project/**"]
[read]
default = "allow"
[read.allow]
paths = ["path:/project/**"]
`,
			tool:       ToolGrep,
			searchPath: "/project/src",
			wantAction: ActionAllow,
		},
		{
			name: "glob deny by tool rules",
			config: `
version = "2.0"
[glob.deny]
paths = ["path:/etc/**"]
`,
			tool:       ToolGlob,
			searchPath: "/etc/ssh",
			wantAction: ActionDeny,
		},
		{
			name: "grep deny by tool rules",
			config: `
version = "2.0"
[grep.deny]
paths = ["path:/etc/**"]
`,
			tool:       ToolGrep,
			searchPath: "/etc/ssh",
			wantAction: ActionDeny,
		},
		{
			name: "glob default ask when no match",
			config: `
version = "2.0"
[glob]
default = "ask"
[read]
default = "ask"
`,
			tool:       ToolGlob,
			searchPath: "/some/random/path",
			wantAction: ActionAsk,
		},
		{
			name: "grep default ask when no match",
			config: `
version = "2.0"
[grep]
default = "ask"
[read]
default = "ask"
`,
			tool:       ToolGrep,
			searchPath: "/some/random/path",
			wantAction: ActionAsk,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfigInternal(tt.config)
			if err != nil {
				t.Fatalf("parse config: %v", err)
			}
			applyDefaults(cfg)
			chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
			eval := NewEvaluator(chain)
			result := eval.evaluateSearchTool(tt.tool, tt.searchPath)
			if result.Action != tt.wantAction {
				t.Errorf("got action %q, want %q (source: %s)", result.Action, tt.wantAction, result.Source)
			}
		})
	}
}

func TestEvalSearchToolRespectsReadRules(t *testing.T) {
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/**"]
[read.deny]
paths = ["path:/secret/**"]
message = "Cannot read secret directory"
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)

	// Glob is allowed, but Read denies /secret/**
	result := eval.evaluateSearchTool(ToolGlob, "/secret/data")
	if result.Action != ActionDeny {
		t.Errorf("expected deny from read rules, got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolReadDenyOverridesGlobAllow(t *testing.T) {
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/**"]
[read]
default = "allow"
[read.allow]
paths = ["path:/**"]
[read.deny]
paths = ["path:/home/.ssh/**"]
message = "SSH keys are sensitive"
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)

	result := eval.evaluateSearchTool(ToolGlob, "/home/.ssh/keys")
	if result.Action != ActionDeny {
		t.Errorf("expected deny, got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolReadAskTightensGlobAllow(t *testing.T) {
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/**"]
[read]
default = "ask"
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)

	// Glob allows /tmp, but Read defaults to ask (no allow rule matches)
	result := eval.evaluateSearchTool(ToolGlob, "/tmp/something")
	if result.Action != ActionAsk {
		t.Errorf("expected ask (read default tightens glob allow), got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolDispatch(t *testing.T) {
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/project/**"]
[grep]
default = "allow"
[grep.allow]
paths = ["path:/project/**"]
[read]
default = "allow"
[read.allow]
paths = ["path:/project/**"]
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	dispatcher := NewToolDispatcher(chain)

	// Test Glob dispatch
	globInput := HookInput{ToolName: ToolGlob}
	globInput.ToolInput.Pattern = "**/*.go"
	globInput.ToolInput.Path = "/project/src"
	result := dispatcher.Dispatch(globInput)
	if result.Action != ActionAllow {
		t.Errorf("Glob dispatch: expected allow, got %q (source: %s)", result.Action, result.Source)
	}

	// Test Grep dispatch
	grepInput := HookInput{ToolName: ToolGrep}
	grepInput.ToolInput.Pattern = "TODO"
	grepInput.ToolInput.Path = "/project/src"
	result = dispatcher.Dispatch(grepInput)
	if result.Action != ActionAllow {
		t.Errorf("Grep dispatch: expected allow, got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolRespectFileRulesFalse(t *testing.T) {
	// When respect_file_rules = false, read deny rules should NOT block glob/grep
	config := `
version = "2.0"
[glob]
default = "allow"
respect_file_rules = false
[glob.allow]
paths = ["path:/**"]
[read.deny]
paths = ["path:/secret/**"]
message = "Cannot read secret directory"
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.Path = "test"
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)

	// With respect_file_rules=false, read deny should NOT apply
	result := eval.evaluateSearchTool(ToolGlob, "/secret/data")
	if result.Action != ActionAllow {
		t.Errorf("expected allow (respect_file_rules=false), got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolRespectFileRulesDefault(t *testing.T) {
	// When respect_file_rules is not set, it defaults to true
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/**"]
[read.deny]
paths = ["path:/secret/**"]
message = "Cannot read secret directory"
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	eval := NewEvaluator(chain)

	// Default (unset) should respect read rules
	result := eval.evaluateSearchTool(ToolGlob, "/secret/data")
	if result.Action != ActionDeny {
		t.Errorf("expected deny (default respect_file_rules=true), got %q (source: %s)", result.Action, result.Source)
	}
}

func TestEvalSearchToolDefaultPath(t *testing.T) {
	config := `
version = "2.0"
[glob]
default = "allow"
[glob.allow]
paths = ["path:/**"]
[read]
default = "allow"
[read.allow]
paths = ["path:/**"]
`
	cfg, err := parseConfigInternal(config)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	applyDefaults(cfg)
	chain := &ConfigChain{Configs: []*Config{cfg}, Merged: MergeConfigs([]*Config{cfg})}
	dispatcher := NewToolDispatcher(chain)

	// Empty path should use CWD
	input := HookInput{ToolName: ToolGlob}
	input.ToolInput.Pattern = "*.go"
	result := dispatcher.Dispatch(input)
	// Should resolve CWD and match /** allow pattern
	cwd, _ := os.Getwd()
	if cwd != "" && result.Action != ActionAllow {
		t.Errorf("empty path (CWD=%s): expected allow, got %q (source: %s)", cwd, result.Action, result.Source)
	}
}
