package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestDefaultsAreSafe(t *testing.T) {
	c := Default()
	if c.ContentMode != content.DefaultMode {
		t.Errorf("ContentMode = %q, want the minimising default", c.ContentMode)
	}
	if c.RetentionDays != RetentionFloorDays {
		t.Errorf("RetentionDays = %d, want %d", c.RetentionDays, RetentionFloorDays)
	}
}

// Retention below six months is refused rather than accepted quietly, because
// a log that was silently under-retained is discovered at the worst moment.
func TestValidateRefusesRetentionBelowTheFloor(t *testing.T) {
	c := Default()
	c.MockUpstream = true
	c.RetentionDays = 30

	err := c.Validate()
	if err == nil {
		t.Fatal("expected a retention floor violation")
	}
	if !strings.Contains(err.Error(), "Article 19") {
		t.Errorf("error does not explain why: %v", err)
	}
}

func TestValidateRequiresAnUpstream(t *testing.T) {
	c := Default()
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when no upstream and no mock is configured")
	}

	c.MockUpstream = true
	if err := c.Validate(); err != nil {
		t.Errorf("mock upstream should satisfy the requirement: %v", err)
	}
}

func TestValidateRejectsBadUpstreamURLs(t *testing.T) {
	for _, upstream := range []string{"vllm:8000", "ftp://vllm:8000", "http://"} {
		c := Default()
		c.Upstream = upstream
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted upstream %q", upstream)
		}
	}
}

func TestValidateRejectsUnknownContentMode(t *testing.T) {
	c := Default()
	c.MockUpstream = true
	c.ContentMode = "everything"
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for an unknown content mode")
	}
}

func TestValidateRequiresBothTLSFiles(t *testing.T) {
	c := Default()
	c.MockUpstream = true
	c.TLSCertFile = "/tmp/cert.pem"
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error when only one half of the TLS pair is set")
	}
}

func TestValidateFillsDefaultRedactionPatterns(t *testing.T) {
	c := Default()
	c.MockUpstream = true
	c.ContentMode = evidence.ModeRedact

	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.RedactPatterns) == 0 {
		t.Error("redact mode without patterns should fall back to the defaults, not redact nothing")
	}
}

func TestLoadFileRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"listen":":9000","typo_here":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	err := c.LoadFile(path)
	if err == nil {
		t.Fatal("a misspelled config key should be an error, not silently ignored")
	}
	if !strings.Contains(err.Error(), "typo_here") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

func TestLoadFileMergesOverDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{
		"listen": ":9000",
		"upstream": "http://vllm:8000",
		"content_mode": "redact",
		"request_timeout": "30s",
		"deployment": {"organisation": "Muster GmbH", "system_name": "Assistant"}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	if err := c.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9000" || c.Upstream != "http://vllm:8000" {
		t.Errorf("file values not applied: %+v", c)
	}
	if c.RetentionDays != RetentionFloorDays {
		t.Errorf("RetentionDays = %d, want the default to survive a partial file", c.RetentionDays)
	}
	if c.RequestTimeout.Std().Seconds() != 30 {
		t.Errorf("RequestTimeout = %v", c.RequestTimeout.Std())
	}
	if c.Deployment.Organisation != "Muster GmbH" {
		t.Errorf("Deployment = %+v", c.Deployment)
	}
}

func TestApplyEnvOverlays(t *testing.T) {
	t.Setenv(EnvPrefix+"LISTEN", ":7000")
	t.Setenv(EnvPrefix+"UPSTREAM", "http://ollama:11434")
	t.Setenv(EnvPrefix+"CONTENT_MODE", "store")
	t.Setenv(EnvPrefix+"RETENTION_DAYS", "365")
	t.Setenv(EnvPrefix+"REDACT_PATTERNS", "email, iban ")
	t.Setenv(EnvPrefix+"ORGANISATION", "Muster GmbH")

	c := Default()
	if err := c.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":7000" || c.Upstream != "http://ollama:11434" || c.ContentMode != "store" {
		t.Errorf("env not applied: %+v", c)
	}
	if c.RetentionDays != 365 {
		t.Errorf("RetentionDays = %d", c.RetentionDays)
	}
	if len(c.RedactPatterns) != 2 || c.RedactPatterns[1] != "iban" {
		t.Errorf("RedactPatterns = %v, want trimmed entries", c.RedactPatterns)
	}
	if c.Deployment.Organisation != "Muster GmbH" {
		t.Errorf("Deployment.Organisation = %q", c.Deployment.Organisation)
	}
}

func TestApplyEnvReportsBadNumbers(t *testing.T) {
	t.Setenv(EnvPrefix+"RETENTION_DAYS", "six months")
	c := Default()
	if err := c.ApplyEnv(); err == nil {
		t.Fatal("expected an error for an unparseable number")
	}
}

func TestDurationRoundTripsThroughJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"shutdown_timeout": 45}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	if err := c.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if c.ShutdownTimeout.Std().Seconds() != 45 {
		t.Errorf("a bare number should be read as seconds, got %v", c.ShutdownTimeout.Std())
	}
}

func TestUpstreamsRejectUnknownEndpointKind(t *testing.T) {
	c := Default()
	c.Upstream = ""
	c.Upstreams = []UpstreamRoute{
		{Name: "chat", URL: "http://vllm:8000", Endpoints: []string{"chat"}, Default: true},
		// "embeddings" is the plural typo that would silently never match.
		{Name: "embed", URL: "http://tei:8080", Endpoints: []string{"embeddings"}},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("a route with an unknown endpoint kind was accepted")
	}
	if !strings.Contains(err.Error(), "embeddings") {
		t.Errorf("error does not name the offending kind: %v", err)
	}
}

func TestUpstreamsRejectCAAndSkipTogether(t *testing.T) {
	c := Default()
	c.Upstream = ""
	c.Upstreams = []UpstreamRoute{
		{Name: "r", URL: "https://vllm:8000", CAFile: "/ca.pem", TLSSkip: true, Default: true},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("a route setting both a CA file and skip-verify was accepted")
	}
}

// A misconfigured custody setting costs evidence for as long as nobody looks at
// it, so every one of these is refused at startup rather than at first use.
func TestValidateRefusesUnusableCustodySettings(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Config) Config
		wants  string
	}{
		{
			name:   "a signer form this build does not understand",
			mutate: func(c Config) Config { c.Signer = "pkcs11:slot0"; c.SignerPublicKey = "pub.pem"; return c },
			wants:  "exec:",
		},
		{
			name:   "a signer that names no command",
			mutate: func(c Config) Config { c.Signer = "exec:   "; c.SignerPublicKey = "pub.pem"; return c },
			wants:  "names no command",
		},
		{
			name:   "an external signer with no public key to check it against",
			mutate: func(c Config) Config { c.Signer = "exec:/usr/bin/sign"; return c },
			wants:  "signer_public_key",
		},
		{
			name:   "a public key with no signer to use it",
			mutate: func(c Config) Config { c.SignerPublicKey = "pub.pem"; return c },
			wants:  "no signer",
		},
		{
			name: "an external signer while signing is off",
			mutate: func(c Config) Config {
				c.Signer = "exec:/usr/bin/sign"
				c.SignerPublicKey = "pub.pem"
				c.SigningDisabled = true
				return c
			},
			wants: "signing is disabled",
		},
		{
			name:   "an anchoring URL that is not one",
			mutate: func(c Config) Config { c.TSAURL = "tsa.example.com"; return c },
			wants:  "tsa_url",
		},
		{
			name:   "anchoring while signing is off, so there is nothing to anchor",
			mutate: func(c Config) Config { c.TSAURL = "https://tsa.example"; c.SigningDisabled = true; return c },
			wants:  "signing is disabled",
		},
		{
			name:   "an anchoring interval with no authority",
			mutate: func(c Config) Config { c.TSAInterval = Duration(time.Hour); return c },
			wants:  "no timestamping authority",
		},
		{
			name:   "a negative size cap",
			mutate: func(c Config) Config { c.RetentionMaxBytes = -1; return c },
			wants:  "retention_max_bytes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.mutate(base())

			err := c.Validate()
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error does not say what is wrong: %v", err)
			}
		})
	}
}

// base is a configuration that validates, so that each case below fails for the
// one reason it is about.
func base() Config {
	c := Default()
	c.MockUpstream = true
	return c
}

func TestValidateAcceptsAFullyConfiguredCustodySetup(t *testing.T) {
	c := base()
	c.Signer = "exec:/usr/bin/pkcs11-sign --slot 0"
	c.SignerPublicKey = "/etc/flugschreiber/helper-public-key.pem"
	c.TSAURL = "https://freetsa.org/tsr"
	c.TSAInterval = Duration(30 * time.Minute)
	c.RetentionMaxBytes = 50 << 30

	if err := c.Validate(); err != nil {
		t.Fatalf("a valid custody setup was refused: %v", err)
	}
}

func TestApplyEnvOverlaysCustodySettings(t *testing.T) {
	t.Setenv(EnvPrefix+"SIGNER", "exec:/usr/bin/sign")
	t.Setenv(EnvPrefix+"SIGNER_PUBLIC_KEY", "/keys/pub.pem")
	t.Setenv(EnvPrefix+"TSA_URL", "https://tsa.example/tsr")
	t.Setenv(EnvPrefix+"TSA_INTERVAL", "45m")
	t.Setenv(EnvPrefix+"RETENTION_MAX_BYTES", "1073741824")
	t.Setenv(EnvPrefix+"CONTENT_ENCRYPTION", "true")

	c := Default()
	if err := c.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if c.Signer != "exec:/usr/bin/sign" || c.SignerPublicKey != "/keys/pub.pem" {
		t.Errorf("signer settings not applied: %q, %q", c.Signer, c.SignerPublicKey)
	}
	if c.TSAURL != "https://tsa.example/tsr" || c.TSAInterval.Std() != 45*time.Minute {
		t.Errorf("anchoring settings not applied: %q, %s", c.TSAURL, c.TSAInterval.Std())
	}
	if c.RetentionMaxBytes != 1<<30 {
		t.Errorf("RetentionMaxBytes = %d", c.RetentionMaxBytes)
	}
	if !c.ContentEncryption {
		t.Error("ContentEncryption was not applied")
	}
}
