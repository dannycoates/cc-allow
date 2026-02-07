package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const safeBrowsingEndpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

type sbRequest struct {
	Client     sbClient     `json:"client"`
	ThreatInfo sbThreatInfo `json:"threatInfo"`
}

type sbClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type sbThreatInfo struct {
	ThreatTypes      []string     `json:"threatTypes"`
	PlatformTypes    []string     `json:"platformTypes"`
	ThreatEntryTypes []string     `json:"threatEntryTypes"`
	ThreatEntries    []sbURLEntry `json:"threatEntries"`
}

type sbURLEntry struct {
	URL string `json:"url"`
}

type sbResponse struct {
	Matches []sbMatch `json:"matches"`
}

type sbMatch struct {
	ThreatType string     `json:"threatType"`
	Threat     sbURLEntry `json:"threat"`
}

// checkSafeBrowsing checks a URL against Google Safe Browsing v4 API.
// Returns (isSafe, threatType, error). Caller should handle errors (e.g., return "ask").
func checkSafeBrowsing(url string, apiKey string) (bool, string, error) {
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
		return true, "", fmt.Errorf("marshal request: %w", err)
	}

	endpoint := safeBrowsingEndpoint + "?key=" + apiKey
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return true, "", fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return true, "", fmt.Errorf("safe browsing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return true, "", fmt.Errorf("safe browsing API returned %d", resp.StatusCode)
	}

	var sbResp sbResponse
	if err := json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return true, "", fmt.Errorf("decode response: %w", err)
	}

	if len(sbResp.Matches) > 0 {
		return false, sbResp.Matches[0].ThreatType, nil
	}
	return true, "", nil
}

// getAPIKey returns the Safe Browsing API key from config.
func getAPIKey(cfg SafeBrowsingConfig) string {
	return cfg.APIKey
}
