package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfig(t *testing.T) {
	for _, tc := range []struct {
		name, body, env, wantError string
		flags                      []string
	}{
		{name: "mock", body: `{"mock_upstream":true}`},
		{name: "unreachable upstream", body: `{"upstream":"http://127.0.0.1:1"}`},
		{name: "file", body: `{"mock_upstream":true,"retention_days":30}`, wantError: "below"},
		{name: "environment overrides file", body: `{"mock_upstream":true,"retention_days":30}`, env: "180"},
		{name: "flags override environment", body: `{"mock_upstream":true}`, env: "30", flags: []string{"--retention-days", "180"}},
		{name: "invalid environment", body: `{"mock_upstream":true}`, env: "bad", wantError: "RETENTION_DAYS"},
		{name: "missing upstream", body: `{}`, wantError: "upstream is required"},
		{name: "TLS pair", body: `{"mock_upstream":true,"tls_cert_file":"missing.pem"}`, wantError: "both"},
		{name: "unknown pattern", body: `{"mock_upstream":true,"redact_patterns":["typo"]}`, wantError: "unknown redaction pattern"},
		{name: "invalid regexp", body: `{"mock_upstream":true,"redact_patterns":["label=["]}`, wantError: "custom pattern"},
		{name: "external signer is not executed", body: `{"mock_upstream":true,"signer":"exec:nonexistent-helper","signer_public_key":"missing.pem"}`},
		{name: "nested parse error", body: "{\n\"deployment\": {\"typo\":true}}", wantError: ":2:16:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if strings.HasPrefix(key, "FLUGSCHREIBER_") {
					t.Setenv(key, "")
					if err := os.Unsetenv(key); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.env != "" {
				t.Setenv("FLUGSCHREIBER_RETENTION_DAYS", tc.env)
			}
			root := t.TempDir()
			path := filepath.Join(root, "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "evidence")
			args := append([]string{"--check-config", "--config", path, "--data-dir", dir, "--listen", "invalid address"}, tc.flags...)
			err := Serve(args)
			if tc.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("Serve = %v, want %q", err, tc.wantError)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("preflight touched evidence: %v", err)
			}
		})
	}
}
