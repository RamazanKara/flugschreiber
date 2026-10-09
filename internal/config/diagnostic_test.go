package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigErrorLocations(t *testing.T) {
	for _, tc := range []struct {
		name, body, location, detail string
	}{
		{"syntax", "{\n  \"listen\": ]\n}", ":2:13:", "invalid character"},
		{"type", "{\n  \"retention_days\": \"180\"\n}", ":2:21:", "cannot unmarshal"},
		{"unknown", "{\n  \"typo\": true\n}", ":2:3:", "unknown field"},
		{"unknown before invalid duration", "{\n  \"typo\": true,\n  \"request_timeout\": \"later\"\n}", ":2:3:", "unknown field"},
		{"type before invalid duration", "{\n  \"retention_days\": \"180\",\n  \"request_timeout\": \"later\"\n}", ":2:21:", "cannot unmarshal"},
		{"nested unknown", "{\n  \"deployment\": {\n    \"typo\": true\n  }\n}", ":3:5:", "unknown field"},
		{"route unknown", "{\n  \"upstreams\": [{\n    \"name\": \"local\",\n    \"typo\": true\n  }]\n}", ":4:5:", "unknown field"},
		{"duration", "{\n  \"request_timeout\": \"later\"\n}", ":2:22:", "invalid duration"},
		{"truncated", "{\n", ":2:1:", "unexpected EOF"},
		{"empty", "", ":1:1:", "EOF"},
		{"trailing", "{}\n  {}", ":2:3:", "unexpected data"},
		{"trailing comma", "{}\n,", ":2:1:", "unexpected data"},
		{"CRLF", "{\r\n  \"typo\": true\r\n}", ":2:3:", "unknown field"},
		{"escaped key", "{\n  \"typo\\u005fkey\": true\n}", ":2:3:", "typo_key"},
		{"value is not a key", "{\"listen\":\"typo\",\n  \"typo\": true}", ":2:3:", "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			c := Default()
			err := c.LoadFile(path)
			if err == nil || !strings.Contains(err.Error(), path+tc.location) || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("LoadFile = %v, want %s%s and %q", err, path, tc.location, tc.detail)
			}
		})
	}
}
