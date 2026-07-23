// Package proxy is the recording reverse proxy. It sits in front of any
// OpenAI-compatible endpoint and writes one evidence record per interaction
// without the calling application knowing it is there.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
	"github.com/RamazanKara/flugschreiber/internal/metrics"
	"github.com/RamazanKara/flugschreiber/internal/openai"
	"github.com/RamazanKara/flugschreiber/internal/version"
)

// prefixBytes is how much of each body is retained for parsing. Metadata such
// as the model name and streaming flag sits at the top of a request object, so
// this is generous even for large multimodal payloads.
const prefixBytes = 8 << 20

// SessionHeader lets a caller group related requests into one session without
// changing anything else about the request.
const SessionHeader = "X-Flugschreiber-Session"

// Server is the recording proxy.
type Server struct {
	cfg      config.Config
	store    *evidence.Store
	capturer *content.Capturer

	// encryptor seals stored content before the append, and is nil unless
	// content encryption is configured. Hash mode never has one: there is no
	// text at rest to encrypt.
	encryptor *content.Encryptor

	salt    []byte
	router  *router
	log     *slog.Logger
	metrics *metrics.Metrics

	// collect refreshes gauges the proxy cannot observe from a request, such as
	// the size of the evidence directory. It runs at scrape time so a gauge is
	// never staler than the scrape that reads it.
	collect func()

	captureErrors atomic.Uint64
}

type captureKey struct{}

// capture is the per-request recording state, threaded through the proxy on
// the request context.
type capture struct {
	requestID string
	sessionID string
	clientID  string
	endpoint  string
	kind      string
	method    string
	start     time.Time

	// upstream names the route that served the request, recorded verbatim in the
	// evidence record. It is empty when no route matched.
	upstream string

	// modelPeekTruncated is set when the model could not be found within the
	// bounded body peek, so the record is marked truncated rather than silently
	// routed on an empty model.
	modelPeekTruncated bool

	reqTap  *tap
	respTap *tap

	status int
	ttfb   time.Duration

	finished atomic.Bool
}

// New builds a Server. The evidence store is owned by the caller; the proxy
// only appends to it.
func New(cfg config.Config, store *evidence.Store, log *slog.Logger) (*Server, error) {
	redactor, err := content.NewRedactor(cfg.RedactPatterns)
	if err != nil {
		return nil, err
	}
	salt, err := loadOrCreateSalt(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	// The keystore is opened here rather than lazily on the first record,
	// because a keystore that cannot be created is a configuration the operator
	// has to fix before any traffic arrives, not a surprise on the first
	// request that carries a prompt.
	var encryptor *content.Encryptor
	if cfg.ContentEncryption && cfg.ContentMode == evidence.ModeHash {
		// Silently doing nothing here would leave an operator believing content
		// is protected when there is no content. Saying so is cheap; the
		// combination is a misunderstanding, not a misconfiguration, so it is a
		// warning rather than a refusal.
		log.Warn("content encryption has no effect in hash mode, which retains no text to encrypt")
	}
	if cfg.ContentEncryption && cfg.ContentMode != evidence.ModeHash {
		keys, keyErr := evidence.OpenContentKeystore(evidence.ContentKeystorePath(cfg.DataDir))
		if keyErr != nil {
			return nil, keyErr
		}
		encryptor = content.NewEncryptor(keys)
		log.Info("stored content is encrypted at rest",
			slog.String("keystore", keys.Path()),
			slog.String("master_key_id", keys.MasterKeyID()))
	}

	s := &Server{
		cfg:       cfg,
		store:     store,
		capturer:  &content.Capturer{Mode: cfg.ContentMode, Redactor: redactor},
		encryptor: encryptor,
		salt:      salt,
		log:       log,
		metrics: metrics.New(metrics.BuildInfo{
			Version:     version.Version,
			Commit:      version.Commit,
			ContentMode: cfg.ContentMode,
		}),
	}

	router, err := newRouter(s, cfg)
	if err != nil {
		return nil, err
	}
	s.router = router
	return s, nil
}

// buildReverseProxy wires one route's reverse proxy. Rewrite is per route so
// each honours its own URL and API key; ModifyResponse and ErrorHandler are the
// shared capture hooks, keyed off the request context, so recording is
// identical whichever route served the request.
func (s *Server) buildReverseProxy(r *route, transport http.RoundTripper) *httputil.ReverseProxy {
	upstream, apiKey := r.upstream, r.apiKey
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			pr.SetXForwarded()
			if apiKey != "" && pr.In.Header.Get("Authorization") == "" {
				pr.Out.Header.Set("Authorization", "Bearer "+apiKey)
			}
			// Ask the upstream not to compress, matching the transport setting,
			// so the recorded bytes stay readable.
			pr.Out.Header.Set("Accept-Encoding", "identity")
		},
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
		// A negative flush interval flushes each write immediately, which is
		// what makes server-sent events arrive as they are produced instead of
		// being buffered until the response ends.
		FlushInterval: -1,
		Transport:     transport,
		ErrorLog:      slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// newTransport builds the HTTP transport for one route, honouring that route's
// own CA bundle and skip-verify setting so upstreams behind different
// certificate authorities coexist.
func newTransport(cfg config.Config, caFile string, tlsSkip bool) (http.RoundTripper, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	t.ResponseHeaderTimeout = cfg.RequestTimeout.Std()
	// Compression is disabled so that the bytes recorded are the bytes the
	// upstream produced, and so that SSE frames are not held back by a
	// decompressor waiting for a block boundary.
	t.DisableCompression = true

	if caFile != "" || tlsSkip {
		tlsCfg := &tls.Config{}
		if caFile != "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			pemBytes, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("proxy: read upstream CA %s: %w", caFile, err)
			}
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("proxy: %s contains no usable PEM certificates", caFile)
			}
			tlsCfg.RootCAs = pool
		}
		// Verification off means the evidence attests to bytes from whoever
		// answered the socket. The caller has been warned at startup; the
		// setting still has to work, because the alternative operators reach
		// for is plaintext.
		tlsCfg.InsecureSkipVerify = tlsSkip
		t.TLSClientConfig = tlsCfg
	}
	return t, nil
}

// Metrics exposes the metric set so the process can update gauges the proxy
// itself cannot observe, such as the size of the evidence directory.
func (s *Server) Metrics() *metrics.Metrics { return s.metrics }

// SetMetricsCollector registers a function to run immediately before each
// metrics scrape. Prometheus semantics expect a gauge to be current when it is
// read, and the alternative, a background ticker, reports whatever the last
// tick saw.
func (s *Server) SetMetricsCollector(fn func()) { s.collect = fn }

// Handler returns the full HTTP surface: health, metrics, the oversight
// events endpoint, and everything else proxied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.cfg.MetricsEnabled {
		inner := s.metrics.Handler()
		mux.Handle("GET /metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.collect != nil {
				s.collect()
			}
			inner.ServeHTTP(w, r)
		}))
	} else {
		// Without this the path falls through to the proxy and is forwarded
		// upstream, so a Prometheus scrape of Flugschreiber would silently
		// return the model server's own metrics. Claiming this route and
		// refusing it is the only honest answer.
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics are disabled on this instance", http.StatusNotFound)
		})
	}
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	mux.HandleFunc("POST "+EventsPath, s.handleEvents)
	mux.Handle("/", http.HandlerFunc(s.handleProxy))
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Err(); err != nil {
		http.Error(w, "evidence store unhealthy: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"status\":\"ok\",\"records\":%d}\n", s.store.Appended())
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	kind := openai.ClassifyPath(r.URL.Path)
	if kind == openai.EndpointOther || r.Method != http.MethodPost {
		// Traffic the proxy does not record (model lists, non-POST calls) carries
		// no model to route on, so it goes to the default upstream.
		s.router.def.rp.ServeHTTP(w, r)
		return
	}

	c := &capture{
		requestID: newID(),
		sessionID: r.Header.Get(SessionHeader),
		clientID:  content.ClientHash(s.salt, credential(r)),
		endpoint:  r.URL.Path,
		kind:      kind,
		method:    r.Method,
		start:     time.Now(),
		reqTap:    newTap(prefixBytes),
		respTap:   newTap(prefixBytes),
	}

	// Routing needs the model, which lives in the request body, before we can
	// dial. Peek a bounded prefix to read it, then rebuild the body so what the
	// upstream receives, and any stream that follows, is byte-for-byte the
	// original. See modelPeekCap and DECISIONS D33.
	model, peekTrunc, prefix, body := peekModel(r.Body)
	r.Body = body
	c.modelPeekTruncated = peekTrunc

	rt := s.router.selectRoute(model, kind)
	if rt == nil {
		// No route matched and no default is configured. The attempt is still
		// evidence: record it, then answer 502 like any other upstream failure.
		c.status = http.StatusBadGateway
		if len(prefix) > 0 {
			// Feed the peeked prefix through the tap so the record still names the
			// model that had no route, even though nothing forwarded the body.
			_, _ = c.reqTap.Write(prefix)
		}
		w.Header().Set("X-Flugschreiber-Request-Id", c.requestID)
		s.finish(c, nil, noRouteError(model, kind))
		http.Error(w, "no upstream route matched the request", http.StatusBadGateway)
		return
	}
	c.upstream = rt.label

	if r.Body != nil {
		r.Body = &teeReadCloser{rc: r.Body, w: c.reqTap}
	}

	w.Header().Set("X-Flugschreiber-Request-Id", c.requestID)
	rt.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), captureKey{}, c)))
}

// noRouteError describes an interaction that reached no upstream, for the
// evidence record's Error field.
func noRouteError(model, kind string) error {
	if model == "" {
		return fmt.Errorf("no upstream route for the %s endpoint (request carried no model)", kind)
	}
	return fmt.Errorf("no upstream route for model %q on the %s endpoint", model, kind)
}

func (s *Server) modifyResponse(resp *http.Response) error {
	c, ok := resp.Request.Context().Value(captureKey{}).(*capture)
	if !ok {
		return nil
	}
	c.status = resp.StatusCode
	c.ttfb = time.Since(c.start)

	resp.Body = &teeReadCloser{
		rc:      resp.Body,
		w:       c.respTap,
		onClose: func(readErr error) { s.finish(c, resp, readErr) },
	}
	return nil
}

func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, context.Canceled) {
		// The client hung up. Nothing to send, but the attempt is still
		// evidence and is recorded below.
		status = 499
	}

	if c, ok := r.Context().Value(captureKey{}).(*capture); ok {
		c.status = status
		s.finish(c, nil, err)
	}

	s.log.Warn("upstream request failed",
		slog.String("path", r.URL.Path),
		slog.String("error", err.Error()))

	if status != 499 {
		http.Error(w, "upstream request failed: "+err.Error(), status)
	}
}

// finish assembles and appends the evidence record. It runs after the response
// body has been fully relayed to the client, so nothing it does is on the
// client's critical path.
func (s *Server) finish(c *capture, resp *http.Response, streamErr error) {
	if !c.finished.CompareAndSwap(false, true) {
		return
	}

	reqSum, reqBytes, reqPrefix, reqTrunc := c.reqTap.snapshot()
	respSum, respBytes, respPrefix, respTrunc := c.respTap.snapshot()

	parsedReq := openai.ParseRequest(c.kind, reqPrefix)

	streamed := parsedReq.Stream
	if resp != nil && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		streamed = true
	}

	var parsedResp *openai.Response
	switch {
	case resp == nil || c.status >= 400:
		parsedResp = &openai.Response{}
	case streamed:
		parsedResp = openai.ParseStream(c.kind, respPrefix)
	default:
		parsedResp = openai.ParseResponse(c.kind, respPrefix)
	}

	ev := &evidence.Event{
		SchemaVersion:      evidence.SchemaVersion,
		EventType:          evidence.EventInference,
		RequestID:          c.requestID,
		SessionID:          c.sessionID,
		ClientHash:         c.clientID,
		Endpoint:           c.endpoint,
		Method:             c.method,
		Upstream:           c.upstream,
		ModelRequested:     parsedReq.Model,
		ModelServed:        parsedResp.Model,
		UpstreamRespID:     parsedResp.ID,
		UpstreamPreviousID: parsedReq.PreviousID,
		Params:             parsedReq.Params,
		Usage:              parsedResp.Usage,
		Stream:             streamed,
		FinishReasons:      parsedResp.FinishReasons,
		Status:             c.status,
		LatencyMS:          msSince(c.start),
	}
	if c.ttfb > 0 {
		ev.TTFBMS = float64(c.ttfb.Microseconds()) / 1000
	}
	if streamErr != nil {
		ev.Error = streamErr.Error()
	}
	if parsedResp.Vectors > 0 {
		ev.Note = fmt.Sprintf("%d embedding vectors of %d dimensions", parsedResp.Vectors, parsedResp.Dimensions)
	}

	for _, tc := range parsedResp.ToolCalls {
		args, digest := s.capturer.ToolArguments(tc.Arguments)
		ev.ToolCalls = append(ev.ToolCalls, evidence.ToolCall{
			ID:            tc.ID,
			Index:         tc.Index,
			Name:          tc.Name,
			Arguments:     args,
			ArgumentsHash: digest,
		})
	}

	// Tool results the caller sent back are as sensitive as prompts, so they
	// take the same content mode: a digest and byte count always, the text only
	// when the mode stores content.
	for _, tr := range parsedReq.ToolResults {
		ev.ToolResults = append(ev.ToolResults, s.capturer.ToolResultPayload(tr.CallID, tr.Content))
	}

	input := s.capturer.Payload(reqPrefix, parsedReq.Text, parsedReq.Messages)
	input.SHA256, input.Bytes = reqSum, int(reqBytes)
	input.Truncated = reqTrunc || input.Truncated || c.modelPeekTruncated
	output := s.capturer.Payload(respPrefix, parsedResp.Text, nil)
	output.SHA256, output.Bytes, output.Truncated = respSum, int(respBytes), respTrunc || output.Truncated

	ev.Content = &evidence.Content{
		Mode:   s.cfg.ContentMode,
		Input:  input,
		Output: output,
	}

	// Encryption has to happen here, between capture and the append, because
	// the chain hashes the record as written and nothing afterwards may rewrite
	// it. EncryptEvent fails closed: on any error the text is gone from the
	// event anyway, so the record is still worth appending and appending it is
	// still the right thing to do. Losing the record would cost the evidence
	// that the interaction happened at all, which is strictly worse than losing
	// the ability to read its content.
	if s.encryptor != nil {
		if err := s.encryptor.EncryptEvent(ev); err != nil {
			s.captureErrors.Add(1)
			s.metrics.CaptureError(metrics.CaptureErrorEncryptFailed)
			s.log.Error("could not encrypt stored content; the record is appended without it",
				slog.String("request_id", c.requestID),
				slog.String("error", err.Error()))
		}
	}

	s.metrics.ObserveRequest(metrics.RequestObservation{
		Endpoint: metrics.EndpointFor(c.kind),
		Method:   c.method,
		Status:   c.status,
		Stream:   streamed,
		Duration: time.Since(c.start),
		TTFB:     c.ttfb,
	})
	if ev.Usage != nil {
		s.metrics.AddTokens(ev.ModelServed, ev.Usage.PromptTokens, ev.Usage.CompletionTokens)
	}

	if err := s.store.Append(ev); err != nil {
		s.captureErrors.Add(1)
		s.metrics.CaptureError(metrics.CaptureErrorAppendFailed)
		s.log.Error("failed to append evidence record",
			slog.String("request_id", c.requestID),
			slog.String("error", err.Error()))
		return
	}
	s.metrics.EventAppended()
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000
}

// credential returns the caller's credential material for identity hashing. It
// is hashed immediately and never stored.
func credential(r *http.Request) string {
	if v := r.Header.Get("Authorization"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Api-Key"); v != "" {
		return v
	}
	return ""
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any supported platform; if it somehow
		// does, a timestamp-derived id is still better than dropping the
		// record on the floor.
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// loadOrCreateSalt returns the per-installation salt used for client identity
// hashing, creating it on first run. It is kept out of the evidence directory's
// exported bundle so that identifiers cannot be reversed by anyone who
// receives the logs.
func loadOrCreateSalt(dir string) ([]byte, error) {
	path := filepath.Join(dir, "client-salt")
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("proxy: read client salt: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("proxy: generate client salt: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return nil, fmt.Errorf("proxy: write client salt: %w", err)
	}
	return salt, nil
}
