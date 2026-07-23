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
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var _ Archiver = (*Client)(nil)

const (
	testBucket    = "flugschreiber-evidence"
	testRegion    = "eu-central-1"
	testAccessKey = "AKIAEXAMPLETESTKEY00"
	testSecret    = "0123456789abcdef0123456789abcdef01234567"
)

func fixedNow() func() time.Time {
	t := time.Date(2026, 7, 23, 9, 30, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newTestS3(t *testing.T, endpoint string, client *http.Client, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		Bucket:      testBucket,
		Region:      testRegion,
		Endpoint:    endpoint,
		Credentials: Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		HTTPClient:  client,
		BaseBackoff: time.Millisecond,
		Now:         fixedNow(),
		// A fixed jitter keeps the retry tests fast and deterministic. The
		// production default is random, which is the point of the injection.
		Jitter: func(time.Duration) time.Duration { return 0 },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewS3(cfg)
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	return c
}

// verifySignature recomputes the signature the way an object store does: from
// the request as it arrived, over exactly the headers the Authorization header
// says were signed. It fails the test if the bytes on the wire are not the
// bytes that were signed.
func verifySignature(t *testing.T, r *http.Request, payloadHash string) {
	t.Helper()

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, Algorithm+" ") {
		t.Errorf("Authorization = %q, want it to start with %s", auth, Algorithm)
		return
	}
	var credential, signedHeaders, signature string
	for _, part := range strings.Split(strings.TrimPrefix(auth, Algorithm+" "), ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			t.Errorf("Authorization part %q is not name=value", part)
			return
		}
		switch name {
		case "Credential":
			credential = value
		case "SignedHeaders":
			signedHeaders = value
		case "Signature":
			signature = value
		}
	}

	scopeParts := strings.SplitN(credential, "/", 2)
	if len(scopeParts) != 2 {
		t.Errorf("credential %q has no scope", credential)
		return
	}
	if scopeParts[0] != testAccessKey {
		t.Errorf("credential names %q, want %q", scopeParts[0], testAccessKey)
	}
	if want := "/" + testRegion + "/s3/aws4_request"; !strings.HasSuffix(scopeParts[1], want) {
		t.Errorf("scope = %q, want it to end with %q", scopeParts[1], want)
	}

	ts, err := time.Parse(amzDateFormat, r.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Errorf("X-Amz-Date %q: %v", r.Header.Get("X-Amz-Date"), err)
		return
	}
	if got := r.Header.Get("X-Amz-Content-Sha256"); got != payloadHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", got, payloadHash)
	}

	// S3 signs the path exactly as it appears in the request line, so a wire
	// encoding that merely decodes to the same key is still a 403.
	rawPath, _, _ := strings.Cut(r.RequestURI, "?")
	if want := uriEncode(r.URL.Path, false); rawPath != want {
		t.Errorf("request line path = %q, want the SigV4 encoding %q", rawPath, want)
	}

	canonical := canonicalRequest(r, payloadHash, "s3", strings.Split(signedHeaders, ";"))
	sts := stringToSign(ts, scopeParts[1], canonical)
	want := hex.EncodeToString(hmacSHA256(signingKey(testSecret, ts, testRegion, "s3"), sts))
	if signature != want {
		t.Errorf("signature does not verify\n     got: %s\nrecomputed: %s\ncanonical request the store saw:\n%s",
			signature, want, canonical)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestPutSendsARequestTheStoreCanVerify is the end-to-end claim: what
// Flugschreiber sends is a correctly signed S3 PUT of the exact bytes it was
// given.
func TestPutSendsARequestTheStoreCanVerify(t *testing.T) {
	body := []byte(strings.Repeat(`{"seq":1,"record_hash":"abc"}`+"\n", 100))

	var seen struct {
		method, path, contentType string
		body                      []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		verifySignature(t, r, sha256Hex(got))
		seen.method = r.Method
		seen.path = r.URL.EscapedPath()
		seen.contentType = r.Header.Get("Content-Type")
		seen.body = got
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), nil)
	err := c.Put(context.Background(), "seg-00000001.jsonl", bytes.NewReader(body), int64(len(body)), ContentTypeJSONL)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if seen.method != http.MethodPut {
		t.Errorf("method = %s, want PUT", seen.method)
	}
	if want := "/" + testBucket + "/seg-00000001.jsonl"; seen.path != want {
		t.Errorf("path = %q, want %q", seen.path, want)
	}
	if seen.contentType != ContentTypeJSONL {
		t.Errorf("content type = %q, want %q", seen.contentType, ContentTypeJSONL)
	}
	if !bytes.Equal(seen.body, body) {
		t.Error("the uploaded bytes are not the bytes that were passed in")
	}
}

// A key that needs escaping is where a signing implementation usually breaks,
// because Go and SigV4 disagree about which characters are safe in a path.
func TestAKeyThatNeedsEscapingIsSentAndSignedIdentically(t *testing.T) {
	const key = "prod 2026/seg+00000001$a.jsonl"

	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		verifySignature(t, r, sha256Hex(got))
		path = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), nil)
	if err := c.Put(context.Background(), key, strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if want := "/" + testBucket + "/prod%202026/seg%2B00000001%24a.jsonl"; path != want {
		t.Errorf("escaped path = %q, want %q", path, want)
	}
}

func TestAddressingStyleBuildsTheExpectedURL(t *testing.T) {
	tests := []struct {
		name       string
		bucket     string
		endpoint   string
		addressing string
		wantURL    string
	}{
		{
			name:    "aws defaults to virtual-hosted",
			bucket:  "evidence",
			wantURL: "https://evidence.s3.eu-central-1.amazonaws.com/seg-00000001.jsonl",
		},
		{
			name:       "aws path-style on request",
			bucket:     "evidence",
			addressing: AddressingPath,
			wantURL:    "https://s3.eu-central-1.amazonaws.com/evidence/seg-00000001.jsonl",
		},
		{
			name:    "a bucket with a dot cannot be a hostname label",
			bucket:  "evidence.example.com",
			wantURL: "https://s3.eu-central-1.amazonaws.com/evidence.example.com/seg-00000001.jsonl",
		},
		{
			name:     "a custom endpoint defaults to path-style",
			bucket:   "evidence",
			endpoint: "https://minio.internal:9000",
			wantURL:  "https://minio.internal:9000/evidence/seg-00000001.jsonl",
		},
		{
			name:       "a custom endpoint can be virtual-hosted",
			bucket:     "evidence",
			endpoint:   "https://s3.example.com",
			addressing: AddressingVirtual,
			wantURL:    "https://evidence.s3.example.com/seg-00000001.jsonl",
		},
		{
			name:     "a gateway path is kept in front of the bucket",
			bucket:   "evidence",
			endpoint: "https://gw.example.com/storage/",
			wantURL:  "https://gw.example.com/storage/evidence/seg-00000001.jsonl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewS3(Config{
				Bucket:      tt.bucket,
				Region:      testRegion,
				Endpoint:    tt.endpoint,
				Addressing:  tt.addressing,
				Credentials: Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
			})
			if err != nil {
				t.Fatalf("NewS3: %v", err)
			}
			req, err := c.newRequest(context.Background(), http.MethodPut, "seg-00000001.jsonl", nil)
			if err != nil {
				t.Fatalf("newRequest: %v", err)
			}
			if got := req.URL.String(); got != tt.wantURL {
				t.Errorf("URL = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

// A 503 is the object store being briefly unavailable and is worth another
// attempt. A 403 is the bucket having decided, and retrying it turns one clear
// failure into four identical ones.
func TestTransientFailuresAreRetriedAndDecisionsAreNot(t *testing.T) {
	tests := []struct {
		name         string
		statuses     []int
		wantAttempts int32
		wantErr      bool
	}{
		{name: "service unavailable then success", statuses: []int{503, 200}, wantAttempts: 2},
		{name: "internal error then success", statuses: []int{500, 200}, wantAttempts: 2},
		{name: "slow down then success", statuses: []int{429, 200}, wantAttempts: 2},
		{name: "gateway timeout exhausts the attempts", statuses: []int{504, 504, 504, 504, 504}, wantAttempts: 4, wantErr: true},
		{name: "forbidden is final", statuses: []int{403, 200}, wantAttempts: 1, wantErr: true},
		{name: "bad request is final", statuses: []int{400, 200}, wantAttempts: 1, wantErr: true},
		{name: "not implemented is final", statuses: []int{501, 200}, wantAttempts: 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := attempts.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				status := tt.statuses[len(tt.statuses)-1]
				if int(n) <= len(tt.statuses) {
					status = tt.statuses[n-1]
				}
				w.WriteHeader(status)
			}))
			defer srv.Close()

			c := newTestS3(t, srv.URL, srv.Client(), nil)
			err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("evidence"), 8, ContentTypeJSONL)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Put: %v", err)
			}
			if got := attempts.Load(); got != tt.wantAttempts {
				t.Errorf("%d attempts, want %d", got, tt.wantAttempts)
			}
		})
	}
}

// Some stores signal backpressure with an S3 error code on a status that would
// otherwise be final, so the code is consulted as well as the status.
func TestRetryDecisionAlsoReadsTheS3ErrorCode(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   bool
	}{
		{name: "slow down on a 400", status: 400, code: "SlowDown", want: true},
		{name: "request timeout code", status: 400, code: "RequestTimeout", want: true},
		{name: "a clock this client cannot correct is not retried", status: 403, code: "RequestTimeTooSkewed"},
		{name: "an object too large for a single put is not retried", status: 400, code: "EntityTooLarge"},
		{name: "a retention rule refusing an overwrite is not retried", status: 403, code: "AccessDenied"},
		{name: "not implemented is not retried even though it is 5xx", status: 501, code: "NotImplemented"},
		{name: "bad gateway with no code", status: 502, want: true},
		{name: "insufficient storage", status: 507, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableStatus(tt.status, tt.code); got != tt.want {
				t.Errorf("retryableStatus(%d, %q) = %v, want %v", tt.status, tt.code, got, tt.want)
			}
		})
	}
}

// A connection that fails before a response arrives is worth another attempt,
// because a whole-object PUT is idempotent. A hostname that does not resolve is
// not, because it will not start resolving within the retry budget.
func TestTransportFailuresAreRetriedButAnUnresolvableNameIsNot(t *testing.T) {
	dnsMiss := &url.Error{
		Op:  "Put",
		URL: "https://nowhere.invalid/evidence/seg-00000001.jsonl",
		Err: &net.DNSError{Err: "no such host", Name: "nowhere.invalid", IsNotFound: true},
	}
	if retryableTransportError(dnsMiss) {
		t.Error("a name that does not exist must be reported once, not four times")
	}
	if retryableTransportError(&url.Error{Op: "Put", Err: io.ErrUnexpectedEOF}) != true {
		t.Error("a connection dropped mid-request must be retried")
	}
	if retryableTransportError(context.Canceled) {
		t.Error("a cancelled upload must not be retried")
	}
	if retryableTransportError(context.DeadlineExceeded) {
		t.Error("an expired deadline must not be retried")
	}

	var attempts atomic.Int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			return nil, &url.Error{Op: "Put", URL: r.URL.String(), Err: io.ErrUnexpectedEOF}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     http.Header{},
			Request:    r,
		}, nil
	})
	c := newTestS3(t, "https://minio.internal:9000", &http.Client{Transport: rt}, nil)
	if err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("evidence"), 8, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("%d attempts, want the dropped connection to be retried once", got)
	}
}

// A failure the endpoint's configuration has already settled is not transient.
// Retrying it four times only delays the moment the operator sees the cause,
// and fills the log with what looks like a flaky network.
func TestSettledTransportFailuresAreReportedOnceRatherThanRetried(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "certificate signed by an unknown authority",
			err:  &url.Error{Op: "Put", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}},
		},
		{
			name: "certificate for the wrong hostname",
			err:  &url.Error{Op: "Put", Err: x509.HostnameError{Host: "minio.internal"}},
		},
		{
			name: "certificate outside its validity period",
			err:  &url.Error{Op: "Put", Err: x509.CertificateInvalidError{Reason: x509.Expired}},
		},
		{
			name: "a plaintext server on a TLS port",
			err:  &url.Error{Op: "Put", Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}},
		},
		{
			name: "a scheme no transport implements",
			err:  &url.Error{Op: "Put", Err: errors.New(`unsupported protocol scheme "ftp"`)},
		},
		{
			name: "a request with no host",
			err:  &url.Error{Op: "Put", Err: errors.New("http: no Host in request URL")},
		},
		{
			name: "a TLS endpoint that answers in plaintext",
			err:  &url.Error{Op: "Put", Err: errors.New("http: server gave HTTP response to HTTPS client")},
		},
		{
			name: "a connection reset is still worth another attempt",
			err:  &url.Error{Op: "Put", Err: syscall.ECONNRESET},
			want: true,
		},
		{
			name: "a timeout is still worth another attempt",
			err:  &url.Error{Op: "Put", Err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableTransportError(tt.err); got != tt.want {
				t.Errorf("retryableTransportError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// The classification has to hold for the error the standard library actually
// produces, not only for one assembled in a test.
func TestABadCertificateIsAttemptedOnce(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	// The default trust store, which does not hold the certificate authority
	// httptest invented for this server.
	c := newTestS3(t, srv.URL, &http.Client{Transport: &http.Transport{}}, nil)
	err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL)
	if err == nil {
		t.Fatal("an untrusted certificate must fail the upload")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error %q does not name the certificate as the cause", err)
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("a certificate that does not verify was tried %d times", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRetriesStopWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) {
		// Long enough that a backoff which ignored the context would hang the
		// test rather than pass it.
		cfg.BaseBackoff = 30 * time.Second
		cfg.MaxBackoff = 30 * time.Second
		cfg.Jitter = func(d time.Duration) time.Duration { return d }
	})

	done := make(chan error, 1)
	go func() {
		done <- c.Put(ctx, "seg-00000001.jsonl", strings.NewReader("evidence"), 8, ContentTypeJSONL)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Put = %v, want it to report the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Put ignored the cancelled context and slept through the backoff")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("%d attempts after cancellation, want 1", got)
	}
}

// Object lock is what makes a bucket usable for evidence: the retention is
// attached at upload time, because that is the only moment the object can be
// written at all.
func TestObjectLockHeadersAreSentAndSigned(t *testing.T) {
	body := []byte("sealed segment")
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		verifySignature(t, r, sha256Hex(got))
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) {
		cfg.ObjectLockMode = ObjectLockCompliance
		cfg.ObjectLockRetainFor = 180 * 24 * time.Hour
		cfg.ObjectLockLegalHold = true
	})
	if err := c.Put(context.Background(), "seg-00000001.jsonl", bytes.NewReader(body), int64(len(body)), ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if got := seen.Get("X-Amz-Object-Lock-Mode"); got != ObjectLockCompliance {
		t.Errorf("object lock mode = %q, want %q", got, ObjectLockCompliance)
	}
	if got := seen.Get("X-Amz-Object-Lock-Legal-Hold"); got != "ON" {
		t.Errorf("legal hold = %q, want ON", got)
	}
	retain, err := time.Parse(time.RFC3339, seen.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	if err != nil {
		t.Fatalf("retain-until %q: %v", seen.Get("X-Amz-Object-Lock-Retain-Until-Date"), err)
	}
	if want := fixedNow()().Add(180 * 24 * time.Hour); !retain.Equal(want) {
		t.Errorf("retain-until = %s, want %s", retain, want)
	}

	// S3 rejects an object lock upload that carries no Content-MD5.
	sum := md5.Sum(body)
	if want := base64.StdEncoding.EncodeToString(sum[:]); seen.Get("Content-Md5") != want {
		t.Errorf("Content-MD5 = %q, want %q", seen.Get("Content-Md5"), want)
	}
	if !strings.Contains(seen.Get("Authorization"), "content-md5;") {
		t.Error("Content-MD5 must be covered by the signature")
	}
	for _, name := range []string{"x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date", "x-amz-object-lock-legal-hold"} {
		if !strings.Contains(seen.Get("Authorization"), name) {
			t.Errorf("%s must be covered by the signature", name)
		}
	}
}

func TestObjectLockNeedsARetentionPeriod(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		retain  time.Duration
		wantErr bool
	}{
		{name: "no object lock", mode: "", retain: 0},
		{name: "governance with a period", mode: ObjectLockGovernance, retain: time.Hour},
		{name: "compliance without a period", mode: ObjectLockCompliance, wantErr: true},
		{name: "unknown mode", mode: "WORM", retain: time.Hour, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewS3(Config{
				Bucket:              testBucket,
				Region:              testRegion,
				Credentials:         Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
				ObjectLockMode:      tt.mode,
				ObjectLockRetainFor: tt.retain,
			})
			if tt.wantErr != (err != nil) {
				t.Fatalf("NewS3 error = %v, want an error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestExistsUsesHeadAndReportsAMissingObjectAsFalse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		want    bool
		wantErr bool
	}{
		{name: "present", status: http.StatusOK, want: true},
		{name: "absent", status: http.StatusNotFound, want: false},
		{name: "denied is unknown, not absent", status: http.StatusForbidden, wantErr: true},
	}

	bucketPath := "/" + testBucket
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead {
					t.Errorf("method = %s, want HEAD", r.Method)
				}
				verifySignature(t, r, EmptyPayloadSHA256)
				// The bucket is there; only the object may be missing.
				if r.URL.Path == bucketPath {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			c := newTestS3(t, srv.URL, srv.Client(), nil)
			got, err := c.Exists(context.Background(), "seg-00000001.jsonl")
			if tt.wantErr != (err != nil) {
				t.Fatalf("Exists error = %v, want an error: %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Exists = %v, want %v", got, tt.want)
			}
		})
	}
}

// A HEAD carries no body, so a bodyless 404 says only "not found". Reporting a
// bucket that is not there as an object that is not there would make every
// segment look unarchived, and the uploads that follow would fail one by one
// while the archive silently stayed empty.
func TestExistsDoesNotReportAMissingBucketAsAnAbsentObject(t *testing.T) {
	bucketPath := "/" + testBucket
	tests := []struct {
		name         string
		bucketStatus int
		errorCode    string
		want         bool
		wantErr      string
	}{
		{
			name:         "the bucket answers, so the object really is absent",
			bucketStatus: http.StatusOK,
			want:         false,
		},
		{
			name:         "the bucket is not there either",
			bucketStatus: http.StatusNotFound,
			wantErr:      testBucket,
		},
		{
			name:         "a bucket that refuses the check still proves it exists",
			bucketStatus: http.StatusForbidden,
			want:         false,
		},
		{
			name:      "a store that names the reason needs no second request",
			errorCode: "NoSuchBucket",
			wantErr:   "NoSuchBucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bucketChecks atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == bucketPath {
					bucketChecks.Add(1)
					w.WriteHeader(tt.bucketStatus)
					return
				}
				if tt.errorCode != "" {
					w.Header().Set("X-Amz-Error-Code", tt.errorCode)
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			c := newTestS3(t, srv.URL, srv.Client(), nil)
			got, err := c.Exists(context.Background(), "seg-00000001.jsonl")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Exists: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Exists = %v, nil; a missing bucket must not be reported as an absent object", got)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error %q does not name %q", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Exists = %v, want %v", got, tt.want)
			}
			if tt.errorCode != "" && bucketChecks.Load() != 0 {
				t.Errorf("the store named the reason, so the extra bucket request was not needed")
			}
		})
	}
}

// The check exists to catch a bucket that was never right, which is settled the
// first time it answers. Paying for it again on every unarchived segment would
// double the requests of a restart with a backlog.
func TestTheBucketIsOnlyConfirmedOnce(t *testing.T) {
	bucketPath := "/" + testBucket
	var bucketChecks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == bucketPath {
			bucketChecks.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), nil)
	for i := 0; i < 5; i++ {
		if ok, err := c.Exists(context.Background(), "seg-00000001.jsonl"); err != nil || ok {
			t.Fatalf("Exists = %v, %v; want false, nil", ok, err)
		}
	}
	if got := bucketChecks.Load(); got != 1 {
		t.Errorf("the bucket was checked %d times over five misses, want 1", got)
	}
}

func TestPrefixIsAppliedToEveryKey(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		path = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) { cfg.Prefix = "prod/flugschreiber/" })
	if err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if want := "/" + testBucket + "/prod/flugschreiber/seg-00000001.jsonl"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}

// A retry has to send the same bytes as the attempt before it, including when
// the caller handed over something that cannot be rewound.
func TestABodyThatCannotBeRewoundIsStillRetriedCorrectly(t *testing.T) {
	body := "one sealed segment"
	var attempts atomic.Int32
	var second []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		verifySignature(t, r, sha256Hex(got))
		second = got
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), nil)
	// A bare io.Reader, so the client cannot seek it.
	opaque := struct{ io.Reader }{strings.NewReader(body)}
	if err := c.Put(context.Background(), "seg-00000001.jsonl", opaque, int64(len(body)), ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if string(second) != body {
		t.Errorf("retry sent %q, want %q", second, body)
	}
}

func TestABodyTooLargeToBufferIsRefusedRatherThanSentUnretryably(t *testing.T) {
	c := newTestS3(t, "https://minio.internal:9000", http.DefaultClient, func(cfg *Config) {
		cfg.MaxBufferBytes = 16
	})
	opaque := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 64))}
	err := c.Put(context.Background(), "seg-00000001.jsonl", opaque, 64, ContentTypeJSONL)
	if err == nil {
		t.Fatal("expected the oversized unrewindable body to be refused")
	}
	if !strings.Contains(err.Error(), "archive from a file") {
		t.Errorf("error should say what to do instead, got: %v", err)
	}
}

func TestErrorReportsTheStoresOwnDiagnosis(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>4442587FB7D0A2F9</RequestId></Error>`)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), nil)
	err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL)

	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("Put error = %v, want an *archive.Error", err)
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != "AccessDenied" || apiErr.RequestID != "4442587FB7D0A2F9" {
		t.Errorf("error fields = %+v", apiErr)
	}
	for _, want := range []string{"AccessDenied", "Access Denied", "4442587FB7D0A2F9", "seg-00000001.jsonl"} {
		if !strings.Contains(apiErr.Error(), want) {
			t.Errorf("error message %q should contain %q", apiErr.Error(), want)
		}
	}
	if strings.Contains(apiErr.Error(), testSecret) {
		t.Error("an error must never carry the secret access key")
	}
}

func TestAnErrorFromAStoreThatSpeaksNoXMLIsStillUsable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Error(w, "<html>502 Bad Gateway</html>", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) { cfg.MaxAttempts = 1 })
	err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should name the status, got %v", err)
	}
}

func TestCredentialsFallBackToTheEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDFROMENVIRONMENT0")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-environment")
	t.Setenv("AWS_SESSION_TOKEN", "")

	c, err := NewS3(Config{Bucket: testBucket, Region: testRegion})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if c.creds.AccessKeyID != "AKIDFROMENVIRONMENT0" {
		t.Errorf("access key = %q, want the one from the environment", c.creds.AccessKeyID)
	}
}

func TestMissingCredentialsAreRefusedAtStartupWithAnActionableError(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	_, err := NewS3(Config{Bucket: testBucket, Region: testRegion})
	if err == nil {
		t.Fatal("expected a client with no credentials to be refused")
	}
	if !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID") {
		t.Errorf("error should name the variables to set, got %v", err)
	}
}

func TestConfigurationIsCheckedBeforeTheFirstUpload(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "no bucket", cfg: Config{Region: testRegion}},
		{name: "endpoint with no scheme", cfg: Config{Bucket: testBucket, Endpoint: "minio.internal:9000"}},
		{name: "endpoint with no host", cfg: Config{Bucket: testBucket, Endpoint: "https://"}},
		{name: "unsigned payload over plain http", cfg: Config{Bucket: testBucket, Endpoint: "http://minio.internal:9000", UnsignedPayload: true}},
		{name: "prefix that escapes the bucket", cfg: Config{Bucket: testBucket, Prefix: ".."}},
		{name: "virtual-hosted addressing of a bucket with a dot", cfg: Config{Bucket: "a.b.c", Addressing: AddressingVirtual}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Credentials = Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecret}
			if _, err := NewS3(cfg); err == nil {
				t.Fatal("expected the configuration to be refused")
			}
		})
	}
}

func TestUnsignedPayloadIsDeclaredAsSuch(t *testing.T) {
	var seen string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		seen = r.Header.Get("X-Amz-Content-Sha256")
		verifySignature(t, r, UnsignedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) { cfg.UnsignedPayload = true })
	if err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if seen != UnsignedPayload {
		t.Errorf("x-amz-content-sha256 = %q, want %q", seen, UnsignedPayload)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	c := newTestS3(t, "https://minio.internal:9000", http.DefaultClient, func(cfg *Config) {
		cfg.BaseBackoff = 100 * time.Millisecond
		cfg.MaxBackoff = 400 * time.Millisecond
		cfg.Jitter = func(d time.Duration) time.Duration { return d }
	})

	want := []time.Duration{100, 200, 400, 400, 400}
	for i, w := range want {
		if got := c.backoff(i + 1); got != w*time.Millisecond {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got, w*time.Millisecond)
		}
	}
}

func TestFullJitterStaysWithinTheBackoff(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := fullJitter(100 * time.Millisecond)
		if d < 0 || d > 100*time.Millisecond {
			t.Fatalf("jitter produced %v, want it within [0, 100ms]", d)
		}
	}
}

func TestRetryAfterIsHonouredButCapped(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "600")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) {
		cfg.MaxBackoff = 20 * time.Millisecond
	})

	start := time.Now()
	if err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a Retry-After of ten minutes pinned the upload open for %v", elapsed)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("%d attempts, want 2", got)
	}
}

// Retry-After is the one delay every client of an overloaded store receives at
// the same instant. Sleeping exactly as long as it says is what brings the
// whole fleet back together, so the hint goes through the same jitter as an
// ordinary backoff.
func TestRetryAfterIsJitteredLikeAnyOtherBackoff(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var jittered []time.Duration
	c := newTestS3(t, srv.URL, srv.Client(), func(cfg *Config) {
		cfg.MaxBackoff = 30 * time.Second
		// A jitter that always picks the bottom of the range. A hint taken
		// literally would ignore it and sleep the full five seconds.
		cfg.Jitter = func(d time.Duration) time.Duration {
			jittered = append(jittered, d)
			return 0
		}
	})

	start := time.Now()
	if err := c.Put(context.Background(), "seg-00000001.jsonl", strings.NewReader("x"), 1, ContentTypeJSONL); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the retry waited %v, so the five second hint was used without jitter", elapsed)
	}
	if !slices.Contains(jittered, 5*time.Second) {
		t.Errorf("the jitter was offered %v, never the five second hint", jittered)
	}
}
