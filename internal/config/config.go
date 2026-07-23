// Package config assembles the proxy's settings from defaults, an optional
// JSON file, and the environment. Flags are bound by the CLI and take
// precedence over all of these.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// EnvPrefix namespaces every environment variable this tool reads.
const EnvPrefix = "FLUGSCHREIBER_"

// RetentionFloorDays is the minimum retention Flugschreiber will accept.
// Article 19 of the AI Act requires providers to keep automatically generated
// logs for at least six months where the logs are under their control. 180
// days is that floor expressed in days; operators may configure more, and the
// tool refuses to configure less rather than silently under-retaining.
const RetentionFloorDays = 180

// Config is the full runtime configuration.
type Config struct {
	Listen       string `json:"listen"`
	Upstream     string `json:"upstream"`
	MockUpstream bool   `json:"mock_upstream"`

	// UpstreamAPIKey is injected as a bearer token when the client did not
	// send one. Client credentials are otherwise passed through untouched.
	UpstreamAPIKey string `json:"upstream_api_key"`

	// EventsToken guards the oversight events endpoint. While it is empty the
	// endpoint stays disabled, because an unauthenticated writer to the
	// evidence log would let anyone fabricate a human-oversight record.
	EventsToken string `json:"events_token"`

	DataDir         string   `json:"data_dir"`
	ContentMode     string   `json:"content_mode"`
	RedactPatterns  []string `json:"redact_patterns"`
	SegmentMaxBytes int64    `json:"segment_max_bytes"`
	RetentionDays   int      `json:"retention_days"`

	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`

	// UpstreamCAFile adds a PEM bundle to the roots trusted for the upstream
	// connection, for model servers behind an internal certificate authority.
	// The system pool stays trusted alongside it.
	UpstreamCAFile string `json:"upstream_ca_file"`

	// UpstreamTLSSkipVerify disables verification of the upstream certificate.
	// The evidence then attests to bytes from whoever answered the socket, so
	// serve logs a warning on every start with this set.
	UpstreamTLSSkipVerify bool `json:"upstream_tls_skip_verify"`

	RequestTimeout  Duration `json:"request_timeout"`
	ShutdownTimeout Duration `json:"shutdown_timeout"`

	// CheckpointInterval is how often the chain head is signed while the log is
	// being written to.
	CheckpointInterval Duration `json:"checkpoint_interval"`

	// SigningDisabled turns off checkpoint signing. Signing is on by default
	// because a chain without checkpoints proves internal consistency only, and
	// an operator who wants that weaker property should choose it deliberately.
	SigningDisabled bool `json:"signing_disabled"`

	LogLevel string `json:"log_level"`

	// MetricsEnabled exposes /metrics. Samples are collected either way; this
	// only controls whether the endpoint is served, because an operator may
	// want the counters without opening another route.
	MetricsEnabled bool `json:"metrics_enabled"`

	// Upstreams routes traffic to more than one model server from one instance,
	// by model name and endpoint kind. It is an alternative to the single
	// Upstream string above; setting both is an error. When it is used, one
	// route must be marked default.
	Upstreams []UpstreamRoute `json:"upstreams,omitempty"`

	// Signer selects how checkpoints are signed. Empty means the built-in
	// file-based Ed25519 key. "exec:/path/to/helper" delegates signing to an
	// external process, which is how key custody moves off the host; that form
	// needs SignerPublicKey, because the proxy has to know which key the helper
	// is supposed to be holding in order to notice when it is holding another.
	Signer          string `json:"signer,omitempty"`
	SignerPublicKey string `json:"signer_public_key,omitempty"`

	// RetentionMaxBytes caps the evidence directory size. Beyond-retention
	// segments are deleted oldest-first until under it. It never overrides the
	// retention floor: if the directory is over the cap but everything is
	// within retention, enforcement refuses and says so. Zero disables it.
	RetentionMaxBytes int64 `json:"retention_max_bytes,omitempty"`

	// TSAURL is an RFC 3161 timestamping authority. When set, each checkpoint
	// is anchored to a signed timestamp token, upgrading its time from a
	// host-clock claim to third-party evidence. TSAInterval bounds how often.
	TSAURL      string   `json:"tsa_url,omitempty"`
	TSAInterval Duration `json:"tsa_interval,omitempty"`

	// ContentEncryption encrypts stored content at rest so that an Article 17
	// erasure can destroy the key rather than the chain. It only affects the
	// store and redact modes; hash mode retains no text to encrypt.
	ContentEncryption bool `json:"content_encryption,omitempty"`

	// Archive ships sealed segments to a second location. It is archival and
	// never the write path: object stores cannot append, so the local segment
	// is always primary and only a rotated, closed segment is uploaded.
	Archive Archive `json:"archive"`

	// Deployment describes the system this proxy sits in front of. It is used
	// only to pre-fill the generated documentation; nothing here changes proxy
	// behaviour.
	Deployment Deployment `json:"deployment"`
}

// UpstreamRoute directs traffic by model name and endpoint kind to one model
// server. It carries its own TLS settings so that servers behind different
// certificate authorities can coexist in one instance.
type UpstreamRoute struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	APIKey  string `json:"api_key,omitempty"`
	CAFile  string `json:"ca_file,omitempty"`
	TLSSkip bool   `json:"tls_skip_verify,omitempty"`
	Default bool   `json:"default,omitempty"`

	// Models is a list of glob patterns matched against the requested model.
	// Empty matches nothing unless the route is the default.
	Models []string `json:"models,omitempty"`

	// Endpoints restricts the route to endpoint kinds (chat, completion,
	// embedding, responses). Empty matches every kind.
	Endpoints []string `json:"endpoints,omitempty"`
}

// Archive backends.
const (
	ArchiveNone = "none"
	ArchiveDir  = "dir"
	ArchiveS3   = "s3"
)

// Archive configures replication of sealed evidence to a second location.
type Archive struct {
	// Backend is none, dir or s3. Empty means none.
	Backend string `json:"backend"`

	// Dir is the destination for the dir backend, which is useful for a second
	// mounted volume with different credentials.
	Dir string `json:"dir"`

	// Prefix is prepended to every object key so one bucket can hold the
	// evidence of several deployments. It is applied by the evidence store, not
	// by the backend, so that it is never applied twice.
	Prefix string `json:"prefix"`

	Bucket     string `json:"bucket"`
	Region     string `json:"region"`
	Endpoint   string `json:"endpoint"`
	Addressing string `json:"addressing"`

	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`

	StorageClass string `json:"storage_class"`
	SSE          string `json:"sse"`
	SSEKMSKeyID  string `json:"sse_kms_key_id"`

	// ObjectLockMode and ObjectLockRetainFor put uploaded evidence under a
	// bucket retention period. This is the control that closes the gap the hash
	// chain leaves open, because it stops the writer altering what it already
	// wrote.
	ObjectLockMode      string   `json:"object_lock_mode"`
	ObjectLockRetainFor Duration `json:"object_lock_retain_for"`
}

// Deployment holds the organisational context a technical documentation file
// needs and traffic cannot supply.
type Deployment struct {
	Organisation string `json:"organisation"`
	SystemName   string `json:"system_name"`
	Purpose      string `json:"purpose"`
	Contact      string `json:"contact"`
	Role         string `json:"role"`
	Environment  string `json:"environment"`
}

// Duration is a time.Duration that round-trips through JSON as a string.
type Duration time.Duration

// MarshalJSON renders the duration in the same "15s" form the file accepts.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts either a Go duration string or a bare number of
// seconds, because both shapes exist in the wild.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(time.Duration(n) * time.Second)
	return nil
}

// Std converts to the standard library's type.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Default returns the configuration used when nothing is specified.
func Default() Config {
	return Config{
		Listen:             ":8080",
		DataDir:            "/var/lib/flugschreiber",
		ContentMode:        content.DefaultMode,
		SegmentMaxBytes:    evidence.DefaultSegmentMaxBytes,
		RetentionDays:      RetentionFloorDays,
		RequestTimeout:     Duration(10 * time.Minute),
		ShutdownTimeout:    Duration(15 * time.Second),
		CheckpointInterval: Duration(evidence.DefaultCheckpointInterval),
		LogLevel:           "info",
		MetricsEnabled:     true,
		Deployment:         Deployment{Role: "deployer", Environment: "production"},
	}
}

// LoadFile merges a JSON configuration file into c.
func (c *Config) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

// ApplyEnv overlays FLUGSCHREIBER_* environment variables.
func (c *Config) ApplyEnv() error {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(EnvPrefix + key); ok {
			*dst = v
		}
	}
	str("LISTEN", &c.Listen)
	// A single default upstream is expressible through UPSTREAM for back-compat.
	// The multi-route Upstreams list has no environment form: it is a structured
	// list with per-route TLS and glob settings, so it is config-file only.
	str("UPSTREAM", &c.Upstream)
	str("UPSTREAM_API_KEY", &c.UpstreamAPIKey)
	str("EVENTS_TOKEN", &c.EventsToken)
	str("ARCHIVE_BACKEND", &c.Archive.Backend)
	str("ARCHIVE_DIR", &c.Archive.Dir)
	str("ARCHIVE_PREFIX", &c.Archive.Prefix)
	str("ARCHIVE_BUCKET", &c.Archive.Bucket)
	str("ARCHIVE_REGION", &c.Archive.Region)
	str("ARCHIVE_ENDPOINT", &c.Archive.Endpoint)
	str("ARCHIVE_ADDRESSING", &c.Archive.Addressing)
	str("ARCHIVE_ACCESS_KEY_ID", &c.Archive.AccessKeyID)
	str("ARCHIVE_SECRET_ACCESS_KEY", &c.Archive.SecretAccessKey)
	str("ARCHIVE_SESSION_TOKEN", &c.Archive.SessionToken)
	str("ARCHIVE_OBJECT_LOCK_MODE", &c.Archive.ObjectLockMode)
	str("DATA_DIR", &c.DataDir)
	str("CONTENT_MODE", &c.ContentMode)
	str("UPSTREAM_CA_FILE", &c.UpstreamCAFile)
	str("TLS_CERT_FILE", &c.TLSCertFile)
	str("TLS_KEY_FILE", &c.TLSKeyFile)
	str("LOG_LEVEL", &c.LogLevel)
	str("SIGNER", &c.Signer)
	str("SIGNER_PUBLIC_KEY", &c.SignerPublicKey)
	str("TSA_URL", &c.TSAURL)
	str("ORGANISATION", &c.Deployment.Organisation)
	str("SYSTEM_NAME", &c.Deployment.SystemName)
	str("PURPOSE", &c.Deployment.Purpose)
	str("CONTACT", &c.Deployment.Contact)
	str("ROLE", &c.Deployment.Role)
	str("ENVIRONMENT", &c.Deployment.Environment)

	if v, ok := os.LookupEnv(EnvPrefix + "REDACT_PATTERNS"); ok {
		c.RedactPatterns = splitList(v)
	}
	if v, ok := os.LookupEnv(EnvPrefix + "MOCK_UPSTREAM"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sMOCK_UPSTREAM: %w", EnvPrefix, err)
		}
		c.MockUpstream = b
	}
	if v, ok := os.LookupEnv(EnvPrefix + "RETENTION_DAYS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("config: %sRETENTION_DAYS: %w", EnvPrefix, err)
		}
		c.RetentionDays = n
	}
	if v, ok := os.LookupEnv(EnvPrefix + "METRICS_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sMETRICS_ENABLED: %w", EnvPrefix, err)
		}
		c.MetricsEnabled = b
	}
	if v, ok := os.LookupEnv(EnvPrefix + "UPSTREAM_TLS_SKIP_VERIFY"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sUPSTREAM_TLS_SKIP_VERIFY: %w", EnvPrefix, err)
		}
		c.UpstreamTLSSkipVerify = b
	}
	if v, ok := os.LookupEnv(EnvPrefix + "SIGNING_DISABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sSIGNING_DISABLED: %w", EnvPrefix, err)
		}
		c.SigningDisabled = b
	}
	if v, ok := os.LookupEnv(EnvPrefix + "CONTENT_ENCRYPTION"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sCONTENT_ENCRYPTION: %w", EnvPrefix, err)
		}
		c.ContentEncryption = b
	}
	if v, ok := os.LookupEnv(EnvPrefix + "RETENTION_MAX_BYTES"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("config: %sRETENTION_MAX_BYTES: %w", EnvPrefix, err)
		}
		c.RetentionMaxBytes = n
	}
	if v, ok := os.LookupEnv(EnvPrefix + "TSA_INTERVAL"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: %sTSA_INTERVAL: %w", EnvPrefix, err)
		}
		c.TSAInterval = Duration(d)
	}
	if v, ok := os.LookupEnv(EnvPrefix + "SEGMENT_MAX_BYTES"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("config: %sSEGMENT_MAX_BYTES: %w", EnvPrefix, err)
		}
		c.SegmentMaxBytes = n
	}
	return nil
}

// Validate checks the configuration is internally consistent and safe to run.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: listen address is required")
	}
	if c.DataDir == "" {
		return errors.New("config: data directory is required")
	}
	switch {
	case len(c.Upstreams) > 0:
		// The single upstream and the routes list are two ways to say the same
		// thing, so setting both is ambiguous rather than additive.
		if c.Upstream != "" {
			return errors.New("config: set either upstream or upstreams, not both")
		}
		if err := validateUpstreams(c.Upstreams); err != nil {
			return err
		}
	case !c.MockUpstream:
		if c.Upstream == "" {
			return errors.New("config: an upstream is required (or use --mock-upstream)")
		}
		if err := validateHTTPURL("upstream", c.Upstream); err != nil {
			return err
		}
	}
	if !content.ValidMode(c.ContentMode) {
		return fmt.Errorf("config: content mode %q must be one of store, hash, redact", c.ContentMode)
	}
	if c.RetentionDays < RetentionFloorDays {
		return fmt.Errorf(
			"config: retention of %d days is below the %d-day floor; AI Act Article 19 expects at least six months of logs",
			c.RetentionDays, RetentionFloorDays)
	}
	switch c.Archive.Backend {
	case "", ArchiveNone:
	case ArchiveDir:
		if c.Archive.Dir == "" {
			return fmt.Errorf("config: archive backend %q needs archive.dir", ArchiveDir)
		}
	case ArchiveS3:
		if c.Archive.Bucket == "" {
			return fmt.Errorf("config: archive backend %q needs archive.bucket", ArchiveS3)
		}
	default:
		return fmt.Errorf("config: archive backend %q must be one of %s, %s or %s",
			c.Archive.Backend, ArchiveNone, ArchiveDir, ArchiveS3)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("config: TLS needs both a certificate and a key")
	}
	if c.ContentMode == evidence.ModeRedact && len(c.RedactPatterns) == 0 {
		c.RedactPatterns = content.DefaultPatternNames
	}
	if err := c.validateCustody(); err != nil {
		return err
	}
	return nil
}

// SignerExecPrefix marks a signer string as an external command. Everything
// after it is the command line, split on whitespace.
const SignerExecPrefix = "exec:"

// validateCustody checks the signing, anchoring and size-cap settings.
//
// These are checked at startup rather than at first use on purpose. A signing
// helper that turns out to be missing, or an anchoring URL that turns out to be
// a typo, costs evidence quietly for as long as nobody looks; a refusal to
// start costs a restart.
func (c *Config) validateCustody() error {
	if c.Signer != "" {
		if !strings.HasPrefix(c.Signer, SignerExecPrefix) {
			return fmt.Errorf(
				"config: signer %q is not a form this build understands; use %s<command> to sign through an external helper",
				c.Signer, SignerExecPrefix)
		}
		if strings.TrimSpace(strings.TrimPrefix(c.Signer, SignerExecPrefix)) == "" {
			return fmt.Errorf("config: signer %q names no command", c.Signer)
		}
		if c.SignerPublicKey == "" {
			return errors.New(
				"config: an external signer needs signer_public_key, the PEM of the key the helper holds; " +
					"without it a helper signing with the wrong key would go unnoticed")
		}
		if c.SigningDisabled {
			return errors.New("config: signing is disabled, so the external signer would never be used")
		}
	}
	if c.SignerPublicKey != "" && c.Signer == "" {
		return errors.New("config: signer_public_key is set but no signer is; the built-in key writes its own public half")
	}
	if c.TSAURL != "" {
		if err := validateHTTPURL("tsa_url", c.TSAURL); err != nil {
			return err
		}
		if c.SigningDisabled {
			return errors.New("config: signing is disabled, so there would be no checkpoints to anchor")
		}
		if c.TSAInterval < 0 {
			return errors.New("config: tsa_interval cannot be negative")
		}
	}
	if c.TSAInterval != 0 && c.TSAURL == "" {
		return errors.New("config: tsa_interval is set but no timestamping authority is")
	}
	if c.RetentionMaxBytes < 0 {
		return errors.New("config: retention_max_bytes cannot be negative")
	}
	return nil
}

// validateUpstreams checks a routes list: every route needs a name and a valid
// http or https URL, and exactly one route must be marked default so there is
// always a fallback for a model no route claims. Per-route CA and skip-verify
// settings follow the same rules as the single upstream's, which place no
// constraint on the pair (skip-verify simply wins when both are set), so nothing
// more is checked here.
// routeEndpointKinds are the endpoint kinds a route may restrict itself to.
// They mirror the openai package's classification. A route that names a kind
// outside this set (the classic mistake is the plural "embeddings") would match
// nothing and silently send traffic to the default route, so it is rejected at
// startup rather than discovered as a coverage gap.
var routeEndpointKinds = map[string]bool{
	"chat": true, "completion": true, "embedding": true, "responses": true,
}

func validateUpstreams(routes []UpstreamRoute) error {
	defaults := 0
	for i := range routes {
		r := routes[i]
		if r.Name == "" {
			return fmt.Errorf("config: upstreams[%d] needs a name", i)
		}
		if err := validateHTTPURL(fmt.Sprintf("upstreams[%s] url", r.Name), r.URL); err != nil {
			return err
		}
		for _, kind := range r.Endpoints {
			if !routeEndpointKinds[kind] {
				return fmt.Errorf(
					"config: upstreams[%s] endpoint %q is not a known kind (chat, completion, embedding, responses)",
					r.Name, kind)
			}
		}
		if r.TLSSkip && r.CAFile != "" {
			return fmt.Errorf("config: upstreams[%s] sets both a CA file and tls_skip_verify; use one", r.Name)
		}
		if r.Default {
			defaults++
		}
	}
	if defaults != 1 {
		return fmt.Errorf("config: upstreams needs exactly one default route, found %d", defaults)
	}
	return nil
}

// validateHTTPURL rejects anything that is not an absolute http or https URL
// with a host, naming the setting so the error points at what to fix.
func validateHTTPURL(label, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config: %s %q: %w", label, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("config: %s %q must be an http or https URL", label, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("config: %s %q has no host", label, raw)
	}
	return nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
