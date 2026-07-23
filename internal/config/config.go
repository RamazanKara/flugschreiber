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

	"github.com/flugschreiber/flugschreiber/internal/content"
	"github.com/flugschreiber/flugschreiber/internal/evidence"
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

	// Archive ships sealed segments to a second location. It is archival and
	// never the write path: object stores cannot append, so the local segment
	// is always primary and only a rotated, closed segment is uploaded.
	Archive Archive `json:"archive"`

	// Deployment describes the system this proxy sits in front of. It is used
	// only to pre-fill the generated documentation; nothing here changes proxy
	// behaviour.
	Deployment Deployment `json:"deployment"`
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

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

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
	str("TLS_CERT_FILE", &c.TLSCertFile)
	str("TLS_KEY_FILE", &c.TLSKeyFile)
	str("LOG_LEVEL", &c.LogLevel)
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
	if v, ok := os.LookupEnv(EnvPrefix + "SIGNING_DISABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %sSIGNING_DISABLED: %w", EnvPrefix, err)
		}
		c.SigningDisabled = b
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
	if !c.MockUpstream {
		if c.Upstream == "" {
			return errors.New("config: an upstream is required (or use --mock-upstream)")
		}
		u, err := url.Parse(c.Upstream)
		if err != nil {
			return fmt.Errorf("config: upstream %q: %w", c.Upstream, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("config: upstream %q must be an http or https URL", c.Upstream)
		}
		if u.Host == "" {
			return fmt.Errorf("config: upstream %q has no host", c.Upstream)
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
