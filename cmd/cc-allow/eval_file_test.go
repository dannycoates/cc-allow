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
version = "2.0"
[read.allow]
paths = ["path:/project/**"]
`,
			tool:       "Read",
			filePath:   "/project/src/main.go",
			wantAction: "allow",
		},
		{
			name: "deny read outside project",
			config: `
version = "2.0"
[read.allow]
paths = ["path:/project/**"]

[read.deny]
paths = ["path:/etc/**"]
`,
			tool:       "Read",
			filePath:   "/etc/passwd",
			wantAction: "deny",
		},
		{
			name: "deny wins over allow",
			config: `
version = "2.0"
[read.allow]
paths = ["path:/**"]

[read.deny]
paths = ["path:/secret/**"]
`,
			tool:       "Read",
			filePath:   "/secret/key.pem",
			wantAction: "deny",
		},
		{
			name: "default ask when no match",
			config: `
version = "2.0"
[read]
default = "ask"

[read.allow]
paths = ["path:/allowed/**"]
`,
			tool:       "Read",
			filePath:   "/other/file.txt",
			wantAction: "ask",
		},
		{
			name: "default deny when configured",
			config: `
version = "2.0"
[read]
default = "deny"

[read.allow]
paths = ["path:/allowed/**"]
`,
			tool:       "Read",
			filePath:   "/other/file.txt",
			wantAction: "deny",
		},
		{
			name: "write tool separate from read",
			config: `
version = "2.0"
[read.allow]
paths = ["path:/**"]

[write.deny]
paths = ["path:/**"]
`,
			tool:       "Write",
			filePath:   "/project/file.txt",
			wantAction: "deny",
		},
		{
			name: "edit tool allow",
			config: `
version = "2.0"
[edit.allow]
paths = ["path:/project/**"]
`,
			tool:       "Edit",
			filePath:   "/project/src/main.go",
			wantAction: "allow",
		},
		{
			name: "glob pattern .env files",
			config: `
version = "2.0"
[read.deny]
paths = ["path:**/.env*"]
`,
			tool:       "Read",
			filePath:   "/project/.env",
			wantAction: "deny",
		},
		{
			name: "glob pattern nested .env",
			config: `
version = "2.0"
[read.deny]
paths = ["path:**/.env*"]
`,
			tool:       "Read",
			filePath:   "/project/config/.env.local",
			wantAction: "deny",
		},
		{
			name: "regex pattern for extensions",
			config: `
version = "2.0"
[read.deny]
paths = ["re:.*\\.(key|pem|p12)$"]
`,
			tool:       "Read",
			filePath:   "/home/user/.ssh/id_rsa.pem",
			wantAction: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfigWithDefaults(tt.config)
			if err != nil {
				t.Fatalf("ParseConfigWithDefaults failed: %v", err)
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
version = "2.0"
[read]
default = "ask"

[read.allow]
paths = ["path:/**"]
`
	projectConfig := `
version = "2.0"
[read.deny]
paths = ["path:/secrets/**"]
`

	global, err := parseConfig(globalConfig)
	if err != nil {
		t.Fatalf("parseConfig(global) failed: %v", err)
	}
	global.Path = "global"

	project, err := parseConfig(projectConfig)
	if err != nil {
		t.Fatalf("parseConfig(project) failed: %v", err)
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

func TestEvalFileToolMessage(t *testing.T) {
	config := `
version = "2.0"
[write.deny]
paths = ["path:/etc/**"]
message = "Cannot write to system files"
`
	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
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
version = "2.0"
[read.allow]
paths = ["path:**/*.go"]
`,
			wantErr: false,
		},
		{
			name: "valid regex pattern",
			config: `
version = "2.0"
[read.deny]
paths = ["re:.*\\.env$"]
`,
			wantErr: false,
		},
		{
			name: "invalid regex pattern",
			config: `
version = "2.0"
[read.deny]
paths = ["re:[invalid"]
`,
			wantErr: true,
		},
		{
			name: "valid path pattern",
			config: `
version = "2.0"
[write.allow]
paths = ["path:$PROJECT_ROOT/**"]
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfigWithDefaults(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseConfigWithDefaults() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
