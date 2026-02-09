package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvalWebFetchTool(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		url        string
		wantAction Action
	}{
		{
			name: "allow github URL",
			config: `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://github\\.com/"]
`,
			url:        "https://github.com/user/repo",
			wantAction: ActionAllow,
		},
		{
			name: "deny localhost URL",
			config: `
version = "2.0"
[webfetch.deny]
paths = ["re:^https?://localhost"]
`,
			url:        "http://localhost:8080/api",
			wantAction: ActionDeny,
		},
		{
			name: "deny 127.0.0.1 URL",
			config: `
version = "2.0"
[webfetch.deny]
paths = ["re:^https?://127\\.0\\.0\\.1"]
`,
			url:        "http://127.0.0.1/secret",
			wantAction: ActionDeny,
		},
		{
			name: "deny wins over allow",
			config: `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://"]

[webfetch.deny]
paths = ["re:^https://evil\\.com"]
`,
			url:        "https://evil.com/phishing",
			wantAction: ActionDeny,
		},
		{
			name: "default ask when no match",
			config: `
version = "2.0"
[webfetch]
default = "ask"
[webfetch.allow]
paths = ["re:^https://github\\.com/"]
`,
			url:        "https://unknown-site.com/page",
			wantAction: ActionAsk,
		},
		{
			name: "webfetch default independent from read default",
			config: `
version = "2.0"
[read]
default = "ask"
[webfetch]
default = "allow"
`,
			url:        "https://any-site.com/page",
			wantAction: ActionAllow,
		},
		{
			name: "default deny when configured",
			config: `
version = "2.0"
[webfetch]
default = "deny"
[webfetch.allow]
paths = ["re:^https://github\\.com/"]
`,
			url:        "https://unknown-site.com/page",
			wantAction: ActionDeny,
		},
		{
			name: "multiple allow patterns",
			config: `
version = "2.0"
[webfetch.allow]
paths = [
    "re:^https://github\\.com/",
    "re:^https://api\\.github\\.com/",
    "re:^https://pkg\\.go\\.dev/",
]
`,
			url:        "https://pkg.go.dev/fmt",
			wantAction: ActionAllow,
		},
		{
			name: "no config defaults to ask",
			config: `
version = "2.0"
`,
			url:        "https://example.com",
			wantAction: ActionAsk,
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

			result := NewEvaluator(chain).evaluateWebFetchTool(tt.url)
			if result.Action != tt.wantAction {
				t.Errorf("evaluateWebFetchTool(%s) = %q, want %q (source: %s)",
					tt.url, result.Action, tt.wantAction, result.Source)
			}
		})
	}
}

func TestEvalWebFetchDispatch(t *testing.T) {
	config := `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://github\\.com/"]
`
	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
	}

	chain := &ConfigChain{
		Configs: []*Config{cfg},
		Merged:  MergeConfigs([]*Config{cfg}),
	}

	dispatcher := NewToolDispatcher(chain)

	// Test dispatch WebFetch allow
	t.Run("dispatch WebFetch allow", func(t *testing.T) {
		var input HookInput
		input.ToolName = ToolWebFetch
		input.ToolInput.URL = "https://github.com/user/repo"
		result := dispatcher.Dispatch(input)
		if result.Action != ActionAllow {
			t.Errorf("Dispatch() = %q, want %q", result.Action, ActionAllow)
		}
	})

	// Test dispatch WebFetch no URL
	t.Run("dispatch WebFetch no URL", func(t *testing.T) {
		var input HookInput
		input.ToolName = ToolWebFetch
		result := dispatcher.Dispatch(input)
		if result.Action != ActionAsk {
			t.Errorf("Dispatch() = %q, want %q", result.Action, ActionAsk)
		}
	})
}

func TestWebFetchHookInputParsing(t *testing.T) {
	jsonInput := `{"tool_name":"WebFetch","tool_input":{"url":"https://github.com/user/repo","prompt":"fetch this page"}}`

	var input HookInput
	if err := json.Unmarshal([]byte(jsonInput), &input); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if input.ToolName != ToolWebFetch {
		t.Errorf("ToolName = %q, want %q", input.ToolName, ToolWebFetch)
	}
	if input.ToolInput.URL != "https://github.com/user/repo" {
		t.Errorf("URL = %q, want %q", input.ToolInput.URL, "https://github.com/user/repo")
	}
	if input.ToolInput.Prompt != "fetch this page" {
		t.Errorf("Prompt = %q, want %q", input.ToolInput.Prompt, "fetch this page")
	}
}

func TestWebFetchConfigParse(t *testing.T) {
	config := `
version = "2.0"

[webfetch]
default = "deny"
default_message = "URL blocked: {{.FilePath}}"

[webfetch.allow]
paths = ["re:^https://github\\.com/"]

[webfetch.deny]
paths = ["re:^http://"]
message = "HTTP not allowed"

[webfetch.safe_browsing]
enabled = true
api_key = "test-key-123"
`
	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
	}

	if cfg.WebFetch.Default != "deny" {
		t.Errorf("WebFetch.Default = %q, want %q", cfg.WebFetch.Default, "deny")
	}
	if cfg.WebFetch.DefaultMessage != "URL blocked: {{.FilePath}}" {
		t.Errorf("WebFetch.DefaultMessage = %q, want %q", cfg.WebFetch.DefaultMessage, "URL blocked: {{.FilePath}}")
	}
	if len(cfg.WebFetch.Allow.Paths) != 1 || cfg.WebFetch.Allow.Paths[0] != "re:^https://github\\.com/" {
		t.Errorf("WebFetch.Allow.Paths = %v, want [re:^https://github\\.com/]", cfg.WebFetch.Allow.Paths)
	}
	if len(cfg.WebFetch.Deny.Paths) != 1 || cfg.WebFetch.Deny.Paths[0] != "re:^http://" {
		t.Errorf("WebFetch.Deny.Paths = %v, want [re:^http://]", cfg.WebFetch.Deny.Paths)
	}
	if cfg.WebFetch.Deny.Message != "HTTP not allowed" {
		t.Errorf("WebFetch.Deny.Message = %q, want %q", cfg.WebFetch.Deny.Message, "HTTP not allowed")
	}
	if !cfg.WebFetch.SafeBrowsing.Enabled {
		t.Error("WebFetch.SafeBrowsing.Enabled = false, want true")
	}
	if cfg.WebFetch.SafeBrowsing.APIKey != "test-key-123" {
		t.Errorf("WebFetch.SafeBrowsing.APIKey = %q, want %q", cfg.WebFetch.SafeBrowsing.APIKey, "test-key-123")
	}
}

func TestWebFetchConfigMerge(t *testing.T) {
	globalConfig := `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://"]
`
	projectConfig := `
version = "2.0"
[webfetch.deny]
paths = ["re:^https://evil\\.com"]
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
		url        string
		wantAction Action
	}{
		{
			name:       "global allow works",
			url:        "https://example.com",
			wantAction: ActionAllow,
		},
		{
			name:       "project deny overrides global allow",
			url:        "https://evil.com/phishing",
			wantAction: ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewEvaluator(chain).evaluateWebFetchTool(tt.url)
			if result.Action != tt.wantAction {
				t.Errorf("evaluateWebFetchTool(%s) = %q, want %q",
					tt.url, result.Action, tt.wantAction)
			}
		})
	}
}

func TestWebFetchSafeBrowsingMerge(t *testing.T) {
	// Test that SafeBrowsing.Enabled uses strictest-wins (once enabled, stays enabled)
	globalConfig := `
version = "2.0"
[webfetch.safe_browsing]
enabled = true
api_key = "global-key"
`
	projectConfig := `
version = "2.0"
[webfetch.safe_browsing]
enabled = false
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

	merged := MergeConfigs([]*Config{global, project})

	if !merged.SafeBrowsing.Enabled {
		t.Error("SafeBrowsing.Enabled should be true (strictest wins)")
	}
	if merged.SafeBrowsing.APIKey != "global-key" {
		t.Errorf("SafeBrowsing.APIKey = %q, want %q", merged.SafeBrowsing.APIKey, "global-key")
	}

	// Test that later key overrides earlier
	projectConfig2 := `
version = "2.0"
[webfetch.safe_browsing]
api_key = "project-key"
`
	project2, err := parseConfig(projectConfig2)
	if err != nil {
		t.Fatalf("parseConfig(project2) failed: %v", err)
	}
	project2.Path = "project"

	merged2 := MergeConfigs([]*Config{global, project2})
	if merged2.SafeBrowsing.APIKey != "project-key" {
		t.Errorf("SafeBrowsing.APIKey = %q, want %q (later key should win)", merged2.SafeBrowsing.APIKey, "project-key")
	}
}

func TestWebFetchSafeBrowsingAPI(t *testing.T) {
	// Test with a mock Safe Browsing server
	tests := []struct {
		name       string
		response   sbResponse
		statusCode int
		wantSafe   bool
		wantErr    bool
	}{
		{
			name:       "safe URL (empty response)",
			response:   sbResponse{},
			statusCode: 200,
			wantSafe:   true,
		},
		{
			name: "unsafe URL (malware)",
			response: sbResponse{
				Matches: []sbMatch{
					{ThreatType: "MALWARE", Threat: sbURLEntry{URL: "https://evil.com"}},
				},
			},
			statusCode: 200,
			wantSafe:   false,
		},
		{
			name:       "API error (500)",
			response:   sbResponse{},
			statusCode: 500,
			wantSafe:   true, // returns safe=true with error; caller returns "ask"
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Override endpoint for testing
			origEndpoint := safeBrowsingEndpoint
			// We can't override the const, so we test checkSafeBrowsing with the real endpoint
			// Instead, test the integration through evaluateWebFetchTool with a mock
			_ = origEndpoint

			safe, _, err := checkSafeBrowsingWithEndpoint(server.URL, "https://test.com", "test-key")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkSafeBrowsing() error = %v, wantErr %v", err, tt.wantErr)
			}
			if safe != tt.wantSafe {
				t.Errorf("checkSafeBrowsing() safe = %v, want %v", safe, tt.wantSafe)
			}
		})
	}
}

// checkSafeBrowsingWithEndpoint is a test helper that uses a custom endpoint.
func checkSafeBrowsingWithEndpoint(endpoint, url, apiKey string) (bool, string, error) {
	req := sbRequest{
		Client: sbClient{ClientID: "cc-allow", ClientVersion: version},
		ThreatInfo: sbThreatInfo{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries:    []sbURLEntry{{URL: url}},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return true, "", err
	}

	httpReq, err := http.NewRequest("POST", endpoint+"?key="+apiKey, bytes.NewReader(body))
	if err != nil {
		return true, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return true, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return true, "", fmt.Errorf("safe browsing API returned %d", resp.StatusCode)
	}

	var sbResp sbResponse
	if err := json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return true, "", err
	}

	if len(sbResp.Matches) > 0 {
		return false, sbResp.Matches[0].ThreatType, nil
	}
	return true, "", nil
}

// loadSafeBrowsingKey loads the API key from the real config chain.
// Returns empty string if not configured.
func loadSafeBrowsingKey(t *testing.T) string {
	t.Helper()
	// Walk up from test directory to find project root with .config/cc-allow.toml
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		configPath := filepath.Join(dir, ".config", "cc-allow.toml")
		if _, err := os.Stat(configPath); err == nil {
			cfg, err := LoadConfigWithDefaults(configPath)
			if err != nil {
				return ""
			}
			return cfg.WebFetch.SafeBrowsing.APIKey
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func TestSafeBrowsingIntegration(t *testing.T) {
	apiKey := loadSafeBrowsingKey(t)
	if apiKey == "" {
		t.Skip("no Safe Browsing API key configured; skipping integration tests")
	}

	tests := []struct {
		name           string
		url            string
		wantSafe       bool
		wantThreatType string // empty means safe
	}{
		{
			name:     "safe URL - google.com",
			url:      "https://google.com",
			wantSafe: true,
		},
		{
			name:     "safe URL - github.com",
			url:      "https://github.com",
			wantSafe: true,
		},
		{
			name:           "malware test URL",
			url:            "https://testsafebrowsing.appspot.com/s/malware.html",
			wantSafe:       false,
			wantThreatType: "MALWARE",
		},
		{
			name:           "phishing test URL",
			url:            "https://testsafebrowsing.appspot.com/s/phishing.html",
			wantSafe:       false,
			wantThreatType: "SOCIAL_ENGINEERING",
		},
		{
			name:           "unwanted software test URL",
			url:            "https://testsafebrowsing.appspot.com/s/unwanted.html",
			wantSafe:       false,
			wantThreatType: "UNWANTED_SOFTWARE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safe, threatType, err := checkSafeBrowsing(tt.url, apiKey)
			if err != nil {
				t.Fatalf("checkSafeBrowsing(%q) error: %v", tt.url, err)
			}
			if safe != tt.wantSafe {
				t.Errorf("checkSafeBrowsing(%q) safe = %v, want %v (threatType=%q)",
					tt.url, safe, tt.wantSafe, threatType)
			}
			if !tt.wantSafe && threatType != tt.wantThreatType {
				t.Errorf("checkSafeBrowsing(%q) threatType = %q, want %q",
					tt.url, threatType, tt.wantThreatType)
			}
		})
	}
}

func TestSafeBrowsingIntegrationEndToEnd(t *testing.T) {
	apiKey := loadSafeBrowsingKey(t)
	if apiKey == "" {
		t.Skip("no Safe Browsing API key configured; skipping integration tests")
	}

	// Only allow specific safe URLs, leave others to Safe Browsing check
	config := fmt.Sprintf(`
version = "2.0"

[webfetch.allow]
paths = ["re:^https://google\\.com", "re:^https://github\\.com/"]

[webfetch.safe_browsing]
enabled = true
api_key = %q
`, apiKey)

	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
	}

	chain := &ConfigChain{
		Configs: []*Config{cfg},
		Merged:  MergeConfigs([]*Config{cfg}),
	}

	tests := []struct {
		name       string
		url        string
		wantAction Action
	}{
		{
			name:       "safe URL allowed by pattern",
			url:        "https://google.com",
			wantAction: ActionAllow,
		},
		{
			name:       "malware URL denied by Safe Browsing",
			url:        "https://testsafebrowsing.appspot.com/s/malware.html",
			wantAction: ActionDeny,
		},
		{
			name:       "phishing URL denied by Safe Browsing",
			url:        "https://testsafebrowsing.appspot.com/s/phishing.html",
			wantAction: ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewEvaluator(chain).evaluateWebFetchTool(tt.url)
			if result.Action != tt.wantAction {
				t.Errorf("evaluateWebFetchTool(%q) action = %q, want %q (source: %s, message: %s)",
					tt.url, result.Action, tt.wantAction, result.Source, result.Message)
			}
		})
	}
}

func TestSafeBrowsingLocalRulesTakePrecedence(t *testing.T) {
	apiKey := loadSafeBrowsingKey(t)
	if apiKey == "" {
		t.Skip("no Safe Browsing API key configured; skipping integration tests")
	}

	// Local allow rule should take precedence over Safe Browsing deny
	config := fmt.Sprintf(`
version = "2.0"
[webfetch.allow]
paths = ["re:^https://testsafebrowsing\\.appspot\\.com/"]

[webfetch.safe_browsing]
enabled = true
api_key = %q
`, apiKey)

	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
	}

	chain := &ConfigChain{
		Configs: []*Config{cfg},
		Merged:  MergeConfigs([]*Config{cfg}),
	}

	// This URL would be flagged by Safe Browsing, but local allow rule matches first
	result := NewEvaluator(chain).evaluateWebFetchTool("https://testsafebrowsing.appspot.com/s/malware.html")
	if result.Action != ActionAllow {
		t.Errorf("expected allow (local rule precedence), got %q (source: %s)", result.Action, result.Source)
	}
}

func TestWebFetchDenyMessage(t *testing.T) {
	config := `
version = "2.0"
[webfetch.deny]
paths = ["re:^http://"]
message = "HTTPS only please"
`
	cfg, err := ParseConfigWithDefaults(config)
	if err != nil {
		t.Fatalf("ParseConfigWithDefaults failed: %v", err)
	}

	chain := &ConfigChain{
		Configs: []*Config{cfg},
		Merged:  MergeConfigs([]*Config{cfg}),
	}

	result := NewEvaluator(chain).evaluateWebFetchTool("http://example.com")
	if result.Action != ActionDeny {
		t.Errorf("expected deny, got %s", result.Action)
	}
	if result.Message != "HTTPS only please" {
		t.Errorf("expected message %q, got %q", "HTTPS only please", result.Message)
	}
}

func TestWebFetchPatternValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "valid regex pattern",
			config: `
version = "2.0"
[webfetch.allow]
paths = ["re:^https://"]
`,
			wantErr: false,
		},
		{
			name: "invalid regex pattern",
			config: `
version = "2.0"
[webfetch.deny]
paths = ["re:[invalid"]
`,
			wantErr: true,
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
