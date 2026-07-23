package archive

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Addressing styles. Virtual-hosted puts the bucket in the hostname, which is
// what AWS wants; path-style puts it in the path, which is what a MinIO or
// Ceph deployment on an IP address or a wildcard-less certificate needs.
const (
	AddressingAuto    = "auto"
	AddressingVirtual = "virtual"
	AddressingPath    = "path"
)

// Object lock retention modes. GOVERNANCE can be bypassed by a principal
// holding s3:BypassGovernanceRetention; COMPLIANCE cannot be bypassed or
// shortened by anyone, including the account root, until the retention period
// expires. COMPLIANCE is the mode that makes an evidence bucket meaningful,
// and the mode that will keep charging for objects nobody can delete.
const (
	ObjectLockGovernance = "GOVERNANCE"
	ObjectLockCompliance = "COMPLIANCE"
)

// Defaults for the retry policy. Four attempts over roughly ten seconds
// absorbs a rolling restart of a MinIO node without holding a segment upload
// long enough to matter.
const (
	DefaultMaxAttempts    = 4
	DefaultBaseBackoff    = 250 * time.Millisecond
	DefaultMaxBackoff     = 10 * time.Second
	DefaultMaxBufferBytes = 32 << 20
	defaultRegion         = "us-east-1"
)

// Config describes an S3-compatible bucket.
type Config struct {
	// Bucket is required.
	Bucket string

	// Region defaults to us-east-1, which is also what MinIO and Ceph accept
	// when they do not implement regions at all. It is part of the signature,
	// so a wrong region is a 403 and not a redirect.
	Region string

	// Endpoint overrides the AWS endpoint, for example
	// https://minio.internal:9000. A path on the endpoint is kept as a prefix
	// on every request, for gateways that mount the store below the root.
	Endpoint string

	// Addressing is AddressingAuto (the default), AddressingVirtual or
	// AddressingPath.
	Addressing string

	// Prefix is prepended to every key, so that one bucket can hold the
	// evidence of several deployments.
	Prefix string

	// Credentials, when incomplete, fall back to the AWS environment
	// variables.
	Credentials Credentials

	// StorageClass, SSE and SSEKMSKeyID are passed through when set.
	StorageClass string
	SSE          string
	SSEKMSKeyID  string

	// ObjectLockMode and ObjectLockRetainFor put every uploaded object under a
	// retention period computed at upload time. A bucket must have object lock
	// enabled at creation for these to be accepted; it cannot be turned on
	// later.
	ObjectLockMode      string
	ObjectLockRetainFor time.Duration

	// ObjectLockLegalHold applies an indefinite hold that survives the
	// retention period and is released by hand.
	ObjectLockLegalHold bool

	// UnsignedPayload skips hashing the body. It saves one pass over each
	// segment at the cost of the signature no longer covering the bytes, so it
	// is off by default and refused over plain HTTP.
	UnsignedPayload bool

	// MaxAttempts counts the first try. One means no retries.
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration

	// MaxBufferBytes caps how much of a non-seekable body is held in memory so
	// that it can be replayed for a retry. Files are seekable, so this only
	// applies to a caller passing a pipe or a network stream.
	MaxBufferBytes int64

	// HTTPClient, Now and Jitter are injection points for tests. Jitter must
	// return a duration in [0, d]; the default picks uniformly, which is the
	// full-jitter strategy that keeps a fleet of proxies from retrying in
	// lockstep after a shared outage.
	HTTPClient *http.Client
	Now        func() time.Time
	Jitter     func(time.Duration) time.Duration
}

// Client is an S3-compatible Archiver built on net/http and crypto/*. There is
// no SDK behind it, which is decision D1: every dependency is a party that can
// change what ends up in an evidence file.
type Client struct {
	cfg       Config
	creds     Credentials
	scheme    string
	host      string
	basePath  string
	pathStyle bool
	http      *http.Client
	now       func() time.Time
	jitter    func(time.Duration) time.Duration

	// bucketSeen records that the bucket answered at least once, so the check
	// behind Exists costs one request per process rather than one per object
	// that is not there yet.
	bucketSeen atomic.Bool
}

// NewS3 validates cfg and resolves credentials, endpoint and addressing style
// once, so that a misconfiguration is reported at startup rather than at the
// first segment rotation hours later.
func NewS3(cfg Config) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("archive: s3 needs a bucket name")
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.MaxBufferBytes <= 0 {
		cfg.MaxBufferBytes = DefaultMaxBufferBytes
	}
	switch cfg.ObjectLockMode {
	case "", ObjectLockGovernance, ObjectLockCompliance:
	default:
		return nil, fmt.Errorf("archive: object lock mode %q must be %s or %s",
			cfg.ObjectLockMode, ObjectLockGovernance, ObjectLockCompliance)
	}
	if cfg.ObjectLockMode != "" && cfg.ObjectLockRetainFor <= 0 {
		return nil, errors.New("archive: object lock mode is set but the retention period is not; nothing would be locked")
	}
	if cfg.Prefix != "" {
		if _, err := CleanKey(JoinKey(cfg.Prefix, "probe")); err != nil {
			return nil, fmt.Errorf("archive: key prefix %q is not usable: %w", cfg.Prefix, err)
		}
	}

	creds := cfg.Credentials
	if !creds.Complete() {
		creds = CredentialsFromEnv()
	}
	if !creds.Complete() {
		return nil, errors.New("archive: no S3 credentials; set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY or configure them explicitly")
	}

	c := &Client{
		cfg:    cfg,
		creds:  creds,
		http:   cfg.HTTPClient,
		now:    cfg.Now,
		jitter: cfg.Jitter,
	}
	if c.http == nil {
		c.http = defaultHTTPClient()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.jitter == nil {
		c.jitter = fullJitter
	}
	if err := c.resolveEndpoint(); err != nil {
		return nil, err
	}
	if cfg.UnsignedPayload && c.scheme != "https" {
		return nil, errors.New("archive: an unsigned payload is only safe over https; either use a TLS endpoint or sign the payload")
	}
	return c, nil
}

func (c *Client) resolveEndpoint() error {
	if c.cfg.Endpoint == "" {
		c.scheme = "https"
		c.host = "s3." + c.cfg.Region + ".amazonaws.com"
		c.pathStyle = c.cfg.Addressing == AddressingPath || !dnsCompatibleBucket(c.cfg.Bucket)
		if c.cfg.Addressing == AddressingVirtual && !dnsCompatibleBucket(c.cfg.Bucket) {
			return fmt.Errorf("archive: bucket %q cannot be addressed virtual-hosted; use path-style addressing", c.cfg.Bucket)
		}
		return nil
	}

	u, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("archive: endpoint %q: %w", c.cfg.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("archive: endpoint %q must be an http or https URL", c.cfg.Endpoint)
	}
	if u.Host == "" {
		return fmt.Errorf("archive: endpoint %q has no host", c.cfg.Endpoint)
	}
	c.scheme = u.Scheme
	c.host = u.Host
	c.basePath = strings.TrimSuffix(u.Path, "/")

	switch c.cfg.Addressing {
	case AddressingVirtual:
		c.pathStyle = false
	case AddressingPath:
		c.pathStyle = true
	default:
		// A custom endpoint is nearly always a self-hosted store reached by IP
		// or by a single hostname, where a bucket subdomain does not resolve
		// and the certificate does not cover it. Path-style is the addressing
		// that works there; AWS is the case that needs virtual-hosted.
		c.pathStyle = true
	}
	return nil
}

// Name returns the backend kind.
func (c *Client) Name() string { return "s3" }

// Target names the bucket and endpoint, for log lines. It never contains a
// credential.
func (c *Client) Target() string {
	return c.scheme + "://" + c.host + "/" + c.cfg.Bucket
}

// Put uploads body under key as a single signed request.
//
// The body is hashed before anything is sent, because SigV4 needs the payload
// hash in the signature and because a retry has to replay the same bytes. A
// body that cannot be rewound is buffered up to Config.MaxBufferBytes.
func (c *Client) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	objectKey, err := c.objectKey(key)
	if err != nil {
		return err
	}
	rs, start, err := rewindable(body, size, c.cfg.MaxBufferBytes)
	if err != nil {
		return err
	}
	if size < 0 {
		if size, err = remaining(rs, start); err != nil {
			return err
		}
	}

	payloadHash := UnsignedPayload
	contentMD5 := ""
	if !c.cfg.UnsignedPayload || c.cfg.ObjectLockMode != "" {
		// S3 requires Content-MD5 on any upload that carries object lock
		// headers, so when a WORM bucket is the target the body is read
		// through anyway and the payload may as well be signed.
		sum, md5sum, err := digest(rs, start)
		if err != nil {
			return err
		}
		if !c.cfg.UnsignedPayload {
			payloadHash = sum
		}
		if c.cfg.ObjectLockMode != "" {
			contentMD5 = md5sum
		}
	}

	build := func() (*http.Request, error) {
		if _, err := rs.Seek(start, io.SeekStart); err != nil {
			return nil, fmt.Errorf("archive: rewind body for %s: %w", objectKey, err)
		}
		req, err := c.newRequest(ctx, http.MethodPut, objectKey, io.NopCloser(rs))
		if err != nil {
			return nil, err
		}
		req.ContentLength = size
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if contentMD5 != "" {
			req.Header.Set("Content-Md5", contentMD5)
		}
		if c.cfg.StorageClass != "" {
			req.Header.Set("X-Amz-Storage-Class", c.cfg.StorageClass)
		}
		if c.cfg.SSE != "" {
			req.Header.Set("X-Amz-Server-Side-Encryption", c.cfg.SSE)
			if c.cfg.SSEKMSKeyID != "" {
				req.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", c.cfg.SSEKMSKeyID)
			}
		}
		if c.cfg.ObjectLockMode != "" {
			req.Header.Set("X-Amz-Object-Lock-Mode", c.cfg.ObjectLockMode)
			retain := c.now().UTC().Add(c.cfg.ObjectLockRetainFor)
			req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", retain.Format(time.RFC3339))
		}
		if c.cfg.ObjectLockLegalHold {
			req.Header.Set("X-Amz-Object-Lock-Legal-Hold", "ON")
		}
		return req, SignRequest(req, c.creds, c.cfg.Region, "s3", payloadHash, c.now())
	}

	resp, err := c.do(ctx, "put", objectKey, build)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// Exists reports whether the object is already in the bucket, so that a
// restart does not re-upload segments the store already holds.
//
// A HEAD carries no body, so a 404 from a store that does not name the reason
// in a header says only "not found". Reading that as "the segment is not
// archived yet" would turn a wrong bucket name into an archive that stays
// empty while every upload reports success, so an absence is believed only once
// the bucket itself has answered.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	objectKey, err := c.objectKey(key)
	if err != nil {
		return false, err
	}
	build := func() (*http.Request, error) {
		req, err := c.newRequest(ctx, http.MethodHead, objectKey, nil)
		if err != nil {
			return nil, err
		}
		return req, SignRequest(req, c.creds, c.cfg.Region, "s3", EmptyPayloadSHA256, c.now())
	}

	resp, err := c.do(ctx, "head", objectKey, build)
	if err != nil {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
			return false, err
		}
		switch apiErr.Code {
		case "NoSuchKey", "NotFound":
			return false, nil
		case "":
			if bucketErr := c.confirmBucket(ctx); bucketErr != nil {
				return false, bucketErr
			}
			return false, nil
		}
		// NoSuchBucket, and anything else the store chose to call it, is a
		// configuration error and not an empty archive.
		return false, err
	}
	drain(resp)
	return true, nil
}

// confirmBucket checks that the bucket is there, so that a 404 with no reason
// in it can be read as an absent object.
//
// A success is remembered for the life of the client. The check exists to catch
// a bucket that was never right, which is settled on the first miss; paying for
// it again on every unarchived segment would double the requests of a restart
// with a large backlog.
func (c *Client) confirmBucket(ctx context.Context) error {
	if c.bucketSeen.Load() {
		return nil
	}
	build := func() (*http.Request, error) {
		req, err := c.newRequest(ctx, http.MethodHead, "", nil)
		if err != nil {
			return nil, err
		}
		return req, SignRequest(req, c.creds, c.cfg.Region, "s3", EmptyPayloadSHA256, c.now())
	}

	resp, err := c.do(ctx, "head-bucket", c.cfg.Bucket, build)
	if err != nil {
		var apiErr *Error
		// A policy that grants object access but not s3:ListBucket is a normal
		// configuration, and a refusal still proves something is there to
		// refuse.
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
			c.bucketSeen.Store(true)
			return nil
		}
		return fmt.Errorf("archive: s3 bucket %s did not answer, so an object that is not there cannot be told from a bucket that is not there: %w", c.cfg.Bucket, err)
	}
	drain(resp)
	c.bucketSeen.Store(true)
	return nil
}

func (c *Client) objectKey(key string) (string, error) {
	return CleanKey(JoinKey(c.cfg.Prefix, key))
}

func (c *Client) newRequest(ctx context.Context, method, objectKey string, body io.ReadCloser) (*http.Request, error) {
	// An empty object key addresses the bucket itself, which is what the
	// existence check needs.
	u := &url.URL{Scheme: c.scheme, Host: c.host}
	if c.pathStyle {
		u.Path = c.basePath + "/" + c.cfg.Bucket
	} else {
		u.Host = c.cfg.Bucket + "." + c.host
		u.Path = c.basePath
	}
	if objectKey != "" {
		u.Path += "/" + objectKey
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("archive: build %s request for %s: %w", method, objectKey, err)
	}
	// http.NewRequestWithContext re-parses the URL, which re-escapes the path
	// with Go's rules. Restore the exact path so that the signer sees what the
	// caller meant rather than a round trip through two escaping schemes.
	req.URL.Path = u.Path
	req.URL.RawPath = ""
	return req, nil
}

// do runs the request, retrying the failures that are worth retrying. build is
// called again for every attempt because each attempt needs its own body,
// timestamp and signature.
func (c *Client) do(ctx context.Context, op, key string, build func() (*http.Request, error)) (*http.Response, error) {
	var last error
	for attempt := 1; ; attempt++ {
		req, err := build()
		if err != nil {
			return nil, err
		}

		resp, err := c.http.Do(req)
		if err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return resp, nil
			}
			apiErr := errorFromResponse(op, key, resp, attempt)
			drain(resp)
			last = apiErr
			if !retryableStatus(resp.StatusCode, apiErr.Code) || attempt >= c.cfg.MaxAttempts {
				return nil, last
			}
			if err := c.wait(ctx, attempt, retryAfter(resp)); err != nil {
				return nil, errors.Join(last, err)
			}
			continue
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("archive: s3 %s %s: %w", op, key, ctxErr)
		}
		last = fmt.Errorf("archive: s3 %s %s: %w", op, key, err)
		// A PUT of a whole object is idempotent, so a transport error can be
		// retried without risking a partial or duplicated upload.
		if !retryableTransportError(err) || attempt >= c.cfg.MaxAttempts {
			return nil, last
		}
		if err := c.wait(ctx, attempt, 0); err != nil {
			return nil, errors.Join(last, err)
		}
	}
}

// wait sleeps for the backoff of the given attempt, or returns as soon as the
// context is done. Evidence uploads must not outlive a shutdown.
func (c *Client) wait(ctx context.Context, attempt int, serverHint time.Duration) error {
	d := c.backoff(attempt)
	if serverHint > 0 {
		// Honour Retry-After, but jittered and not past the cap. A store that
		// asks for ten minutes should not be able to pin an upload open that
		// long, and the hint is the one delay every client of an overloaded
		// store receives at the same instant, so obeying it to the millisecond
		// is what brings the whole fleet back together. Taking the larger of
		// the two keeps a hint from shortening a backoff that has already
		// grown past it.
		d = max(d, c.jitter(min(serverHint, c.cfg.MaxBackoff)))
	}
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	d := c.cfg.BaseBackoff
	for i := 1; i < attempt && d < c.cfg.MaxBackoff; i++ {
		d *= 2
	}
	d = min(d, c.cfg.MaxBackoff)
	return c.jitter(d)
}

func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

// retryableStatus decides from the status code and the S3 error code. Anything
// the bucket has decided about (403 denied, 404 missing, 400 malformed, and a
// retention rule refusing an overwrite) is a decision, not a hiccup, and
// retrying it only turns one clear failure into four.
func retryableStatus(status int, code string) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusRequestTimeout:
		return true
	case http.StatusNotImplemented:
		return false
	}
	if status >= 500 {
		return true
	}
	switch code {
	case "SlowDown", "RequestTimeout":
		return true
	}
	// RequestTimeTooSkewed is deliberately absent. This client does not learn
	// the store's clock offset, so retrying a skew error four times only
	// delays the moment an operator finds out their clock is wrong.
	return false
}

// retryableTransportError separates a connection that might work on the next
// attempt from one that has already been settled by configuration. A
// certificate that does not verify will not verify four times, and every
// repeat pushes the moment the operator sees the real cause further away while
// making the log look like a flaky network.
func retryableTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// A name that does not exist will not start existing within ten seconds,
	// and the operator needs to see the misconfiguration rather than four
	// copies of it.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	// The certificate chain is a property of the endpoint and of this
	// process's trust store, neither of which another attempt changes. The
	// x509 types are checked as well as the tls wrapper, because a custom
	// VerifyPeerCertificate returns them unwrapped.
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var wrongHost x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &wrongHost) || errors.As(err, &invalidCert) {
		return false
	}
	// A plaintext server answering on a TLS port means the endpoint is wrong,
	// not that the network hiccuped.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return false
	}
	// The transport refused the request before it reached the network. Go
	// reports these as a *url.Error carrying an unexported error, so the
	// message is the only thing left to match on. Each one is a fault in how
	// the request was built and none of them change between attempts.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		msg := urlErr.Err.Error()
		for _, settled := range []string{
			"unsupported protocol scheme",
			"no Host in request URL",
			"server gave HTTP response to HTTPS client",
		} {
			if strings.Contains(msg, settled) {
				return false
			}
		}
	}
	return true
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// Error is a non-2xx response from the object store.
type Error struct {
	Op        string
	Key       string
	Status    int
	Code      string
	Message   string
	RequestID string
	Attempts  int
}

// Error renders the status, the store's own error code and the request id,
// which are between them what a bucket operator needs to look the failure up
// on their side.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "archive: s3 %s %s failed with HTTP %d", e.Op, e.Key, e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " (%s)", e.Code)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " [request %s]", e.RequestID)
	}
	if e.Attempts > 1 {
		fmt.Fprintf(&b, " after %d attempts", e.Attempts)
	}
	return b.String()
}

type s3ErrorBody struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

// errorFromResponse reads the S3 error document. A store that returns HTML, an
// empty body, or nothing recognisable still produces a usable error, because
// the status code and the request id header are enough to act on.
func errorFromResponse(op, key string, resp *http.Response, attempt int) *Error {
	e := &Error{
		Op:        op,
		Key:       key,
		Status:    resp.StatusCode,
		Code:      resp.Header.Get("X-Amz-Error-Code"),
		Message:   resp.Header.Get("X-Amz-Error-Message"),
		RequestID: resp.Header.Get("X-Amz-Request-Id"),
		Attempts:  attempt,
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if err == nil && len(body) > 0 {
		var parsed s3ErrorBody
		if xml.Unmarshal(body, &parsed) == nil && parsed.Code != "" {
			e.Code = parsed.Code
			e.Message = parsed.Message
			if parsed.RequestID != "" {
				e.RequestID = parsed.RequestID
			}
		}
	}
	// The code is deliberately left empty when the store did not give one. A
	// HEAD carries no body, so filling in NoSuchKey there would state that the
	// object is missing when what is missing might be the bucket.
	return e
}

// drain reads the tail of a response so the connection can be reused, and
// closes it. Leaking a connection per upload would eventually stall the proxy
// it is attached to.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// rewindable returns a reader that can be replayed for each attempt, together
// with the offset to rewind to. An already-seekable body is used where it is,
// rather than from its start, so that a caller archiving part of a file gets
// the part it asked for.
func rewindable(body io.Reader, size, limit int64) (io.ReadSeeker, int64, error) {
	if rs, ok := body.(io.ReadSeeker); ok {
		start, err := rs.Seek(0, io.SeekCurrent)
		if err == nil {
			return rs, start, nil
		}
	}
	if size > limit {
		return nil, 0, fmt.Errorf("archive: a %d byte body that cannot be rewound exceeds the %d byte buffer limit; archive from a file", size, limit)
	}
	buf, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("archive: read body: %w", err)
	}
	if int64(len(buf)) > limit {
		return nil, 0, fmt.Errorf("archive: a body that cannot be rewound exceeds the %d byte buffer limit; archive from a file", limit)
	}
	return bytes.NewReader(buf), 0, nil
}

func remaining(rs io.ReadSeeker, start int64) (int64, error) {
	end, err := rs.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("archive: measure body: %w", err)
	}
	if _, err := rs.Seek(start, io.SeekStart); err != nil {
		return 0, fmt.Errorf("archive: rewind body: %w", err)
	}
	return end - start, nil
}

// digest hashes the body once for both checksums and leaves it rewound. MD5 is
// used only because S3 requires Content-MD5 on an object lock upload; it
// carries no security claim here, and the SHA-256 next to it is what the
// signature covers.
func digest(rs io.ReadSeeker, start int64) (shaHex, md5B64 string, err error) {
	if _, err := rs.Seek(start, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("archive: rewind body: %w", err)
	}
	sh := sha256.New()
	mh := md5.New()
	if _, err := io.Copy(io.MultiWriter(sh, mh), rs); err != nil {
		return "", "", fmt.Errorf("archive: hash body: %w", err)
	}
	if _, err := rs.Seek(start, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("archive: rewind body: %w", err)
	}
	return hex.EncodeToString(sh.Sum(nil)), base64.StdEncoding.EncodeToString(mh.Sum(nil)), nil
}

// dnsCompatibleBucket reports whether the bucket can appear as a hostname
// label. A bucket with a dot in it breaks TLS verification against the AWS
// wildcard certificate, so those are addressed path-style.
func dnsCompatibleBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 {
		return false
	}
	if strings.Contains(b, ".") {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if c == '-' && i != 0 && i != len(b)-1 {
			continue
		}
		return false
	}
	return true
}

func defaultHTTPClient() *http.Client {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{}
	}
	tr := t.Clone()
	// No overall client timeout: a segment can be tens of megabytes and the
	// archive may be a long way away. Bound the parts that should never take
	// long instead, so a black-holed endpoint still fails rather than hanging.
	tr.ResponseHeaderTimeout = 60 * time.Second
	tr.TLSHandshakeTimeout = 15 * time.Second
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}
