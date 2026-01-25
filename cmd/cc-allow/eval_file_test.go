package main

import (
	"testing"
)

func TestEvalFileTool(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		tool       string
		filePath   string
		wantAction string
	}{
		{
			name: "allow read in project root",
			config: `
[files.read]
allow = ["path:/project/**"]
`,
			tool:       "Read",
			filePath:   "/project/src/main.go",
			wantAction: "allow",
		},
		{
			name: "deny read outside project",
			config: `
[files.read]
allow = ["path:/project/**"]
deny = ["path:/etc/**"]
`,
			tool:       "Read",
			filePath:   "/etc/passwd",
			wantAction: "deny",
		},
		{
			name: "deny wins over allow",
			config: `
[files.read]
allow = ["path:/**"]
deny = ["path:/secret/**"]
`,
			tool:       "Read",
			filePath:   "/secret/key.pem",
			wantAction: "deny",
		},
		{
			name: "default ask when no match",
			config: `
[files]
default = "ask"
[files.read]
allow = ["path:/allowed/**"]
`,
			tool:       "Read",
			filePath:   "/other/file.txt",
			wantAction: "ask",
		},
		{
			name: "default deny when configured",
			config: `
[files]
default = "deny"
[files.read]
allow = ["path:/allowed/**"]
`,
			tool:       "Read",
			filePath:   "/other/file.txt",
			wantAction: "deny",
		},
		{
			name: "write tool separate from read",
			config: `
[files.read]
allow = ["path:/**"]
[files.write]
deny = ["path:/**"]
`,
			tool:       "Write",
			filePath:   "/project/file.txt",
			wantAction: "deny",
		},
		{
			name: "edit tool allow",
			config: `
[files.edit]
allow = ["path:/project/**"]
`,
			tool:       "Edit",
			filePath:   "/project/src/main.go",
			wantAction: "allow",
		},
		{
			name: "glob pattern .env files",
			config: `
[files.read]
deny = ["path:**/.env*"]
`,
			tool:       "Read",
			filePath:   "/project/.env",
			wantAction: "deny",
		},
		{
			name: "glob pattern nested .env",
			config: `
[files.read]
deny = ["path:**/.env*"]
`,
			tool:       "Read",
			filePath:   "/project/config/.env.local",
			wantAction: "deny",
		},
		{
			name: "regex pattern for extensions",
			config: `
[files.read]
deny = ["re:.*\\.(key|pem|p12)$"]
`,
			tool:       "Read",
			filePath:   "/home/user/.ssh/id_rsa.pem",
			wantAction: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.config)
			if err != nil {
				t.Fatalf("ParseConfig failed: %v", err)
			}

			chain := &ConfigChain{
				Configs: []*Config{cfg},
				Merged:  MergeConfigs([]*Config{cfg}),
			}

			result := evaluateFileTool(chain, tt.tool, tt.filePath)
			if result.Action != tt.wantAction {
				t.Errorf("evaluateFileTool(%s, %s) = %q, want %q (source: %s)",
					tt.tool, tt.filePath, result.Action, tt.wantAction, result.Source)
			}
		})
	}
}

func TestEvalFileToolConfigMerge(t *testing.T) {
	// Test that config merging works correctly for file tools
	globalConfig := `
[files]
default = "ask"
[files.read]
allow = ["path:/**"]
`
	projectConfig := `
[files.read]
deny = ["path:/secrets/**"]
`

	global, err := parseConfigRaw(globalConfig)
	if err != nil {
		t.Fatalf("parseConfigRaw(global) failed: %v", err)
	}
	global.Path = "global"

	project, err := parseConfigRaw(projectConfig)
	if err != nil {
		t.Fatalf("parseConfigRaw(project) failed: %v", err)
	}
	project.Path = "project"

	chain := &ConfigChain{
		Configs: []*Config{global, project},
		Merged:  MergeConfigs([]*Config{global, project}),
	}

	tests := []struct {
		name       string
		tool       string
		filePath   string
		wantAction string
	}{
		{
			name:       "global allow works",
			tool:       "Read",
			filePath:   "/home/user/file.txt",
			wantAction: "allow",
		},
		{
			name:       "project deny overrides global allow",
			tool:       "Read",
			filePath:   "/secrets/key.txt",
			wantAction: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateFileTool(chain, tt.tool, tt.filePath)
			if result.Action != tt.wantAction {
				t.Errorf("evaluateFileTool(%s, %s) = %q, want %q",
					tt.tool, tt.filePath, result.Action, tt.wantAction)
			}
		})
	}
}

func TestEvalFileToolDenyMessage(t *testing.T) {
	config := `
[files.write]
deny = ["path:/etc/**"]
deny_message = "Cannot write to system files"
`
	cfg, err := ParseConfig(config)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	chain := &ConfigChain{
		Configs: []*Config{cfg},
		Merged:  MergeConfigs([]*Config{cfg}),
	}

	result := evaluateFileTool(chain, "Write", "/etc/hosts")
	if result.Action != "deny" {
		t.Errorf("expected deny, got %s", result.Action)
	}
	if result.Message != "Cannot write to system files" {
		t.Errorf("expected custom message, got %q", result.Message)
	}
}

func TestFilePatternValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "valid glob pattern",
			config: `
[files.read]
allow = ["path:**/*.go"]
`,
			wantErr: false,
		},
		{
			name: "valid regex pattern",
			config: `
[files.read]
deny = ["re:.*\\.env$"]
`,
			wantErr: false,
		},
		{
			name: "invalid regex pattern",
			config: `
[files.read]
deny = ["re:[invalid"]
`,
			wantErr: true,
		},
		{
			name: "valid path pattern",
			config: `
[files.write]
allow = ["path:$PROJECT_ROOT/**"]
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
