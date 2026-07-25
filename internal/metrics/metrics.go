// Package metrics implements the Prometheus text exposition format (version
// 0.0.4) and the metric set Flugschreiber exports, using only the standard
// library.
//
// There is no client library here because there is no dependency budget for
// one (DECISIONS.md, D1). The scope is therefore deliberately small: counters,
// gauges and histograms, rendered deterministically so that a scrape can be
// diffed and asserted on.
//
// Every label value that originates outside this process is mapped onto a
// closed set before it reaches a metric. A prompt, a client hash or a session
// id in a label would be two problems at once: unbounded cardinality in every
// Prometheus that scrapes this endpoint, and disclosure of personal data
// through an endpoint that is usually less protected than the evidence
// directory. The typed API below offers no way to write one, which is a
// stronger guarantee than a warning in a comment.
//
// A nil *Metrics is usable and does nothing, so a caller that has metrics
// disabled needs no branches at the call sites.
package metrics

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Metric names, exactly as specified for this tool.
const (
	nameBuildInfo      = "flugschreiber_build_info"
	nameRequests       = "flugschreiber_requests_total"
	nameDuration       = "flugschreiber_request_duration_seconds"
	nameTTFB           = "flugschreiber_upstream_ttfb_seconds"
	nameTokens         = "flugschreiber_tokens_total"
	nameEventsAppended = "flugschreiber_events_appended_total"
	nameRecords        = "flugschreiber_evidence_records"
	nameCaptureErrors  = "flugschreiber_capture_errors_total"
	nameCheckpoints    = "flugschreiber_checkpoints_total"
	nameArchiveUploads = "flugschreiber_archive_uploads_total"
	nameEvidenceBytes  = "flugschreiber_evidence_bytes"
	nameEvidenceOver   = "flugschreiber_evidence_bytes_over_cap"
	nameTimestamps     = "flugschreiber_timestamps_total"
)

// Placeholders used when a value is missing or would push a label past its
// cardinality budget.
const (
	labelOther   = "other"
	labelUnknown = "unknown"
)

// maxModelLabels caps how many distinct model names may appear on
// flugschreiber_tokens_total. Model names come from the upstream rather than
// from the caller, so the cap is a backstop rather than the first line of
// defence, and 64 is far more models than a single deployment serves.
const maxModelLabels = 64

// maxBackendLabels caps distinct archive backend names. Backends are named in
// the operator's own configuration, so this only bounds a misconfiguration.
const maxBackendLabels = 16

// maxLabelValueBytes truncates any value before it becomes a label, so that a
// long string from a request or an upstream cannot bloat a scrape.
const maxLabelValueBytes = 128

// Endpoint is the endpoint class a request was routed to. It is a closed set:
// the request path itself is caller-controlled and unbounded, so it never
// becomes a label.
type Endpoint string

// The endpoint classes, matching the kinds internal/openai classifies paths
// into.
const (
	EndpointChat       Endpoint = "chat"
	EndpointCompletion Endpoint = "completion"
	EndpointEmbedding  Endpoint = "embedding"
	EndpointResponses  Endpoint = "responses"
	EndpointOther      Endpoint = "other"
)

// EndpointFor maps an endpoint kind to the label value used for it. Anything
// unrecognised becomes EndpointOther, so a value converted from a raw path can
// never create a new time series.
func EndpointFor(kind string) Endpoint {
	switch Endpoint(kind) {
	case EndpointChat, EndpointCompletion, EndpointEmbedding, EndpointResponses:
		return Endpoint(kind)
	}
	return EndpointOther
}

// CaptureErrorReason says why an interaction was not fully recorded. The set
// is closed because a reason derived from an error string would carry
// arbitrary text, including text from a request, into a label.
type CaptureErrorReason string

// The capture failure reasons.
const (
	// CaptureErrorAppendFailed means the evidence store rejected the record.
	CaptureErrorAppendFailed CaptureErrorReason = "append_failed"
	// CaptureErrorBodyRead means a request or response body could not be read
	// to the end, so the digest covers less than the full exchange.
	CaptureErrorBodyRead CaptureErrorReason = "body_read_failed"
	// CaptureErrorUpstreamFailed means no response was received to record.
	CaptureErrorUpstreamFailed CaptureErrorReason = "upstream_failed"
	// CaptureErrorAbandoned means the proxy stopped while the interaction was
	// still being relayed, so the record holds what had been captured by then.
	CaptureErrorAbandoned CaptureErrorReason = "abandoned_at_shutdown"
	// CaptureErrorEncryptFailed means stored content could not be sealed. The
	// record is still appended, without the text, because the evidence that the
	// interaction happened is worth more than its content.
	CaptureErrorEncryptFailed CaptureErrorReason = "encrypt_failed"
	// CaptureErrorUnknown is the fallback for anything not classified above.
	CaptureErrorUnknown CaptureErrorReason = "unknown"
)

// ArchiveResult is the outcome of an archive upload.
type ArchiveResult string

// The archive upload outcomes.
const (
	ArchiveSuccess ArchiveResult = "success"
	ArchiveFailure ArchiveResult = "failure"
	ArchiveSkipped ArchiveResult = "skipped"
)

// TokenKind distinguishes the two halves of an interaction's token usage.
type TokenKind string

// The token kinds reported by OpenAI-compatible upstreams.
const (
	TokensPrompt     TokenKind = "prompt"
	TokensCompletion TokenKind = "completion"
)

// RequestDurationBuckets returns the default buckets for
// flugschreiber_request_duration_seconds, in seconds.
//
// This measures a whole model interaction, not a web request. An embedding
// call finishes in tens of milliseconds and a streamed completion legitimately
// runs for minutes, so the buckets span four decades. The top edge is 600s
// because that is the default upstream request timeout: a run of observations
// in the last bucket then means requests are dying on the timeout rather than
// merely being slow.
func RequestDurationBuckets() []float64 {
	return []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}
}

// TTFBBuckets returns the default buckets for
// flugschreiber_upstream_ttfb_seconds, in seconds.
//
// Time to first byte is the upstream's prefill plus this proxy's own overhead,
// and the two live in different decades. Against a GPU doing prefill on a long
// prompt it is hundreds of milliseconds to seconds; against a model server on
// the same host, or the built-in mock, it is a few hundred microseconds and is
// dominated by the proxy itself. The usual net/http bucket set starts at 5ms,
// which collapses that entire second case into one bucket and makes the proxy's
// own latency, the one number this tool is responsible for, unmeasurable. So
// the ladder starts at 500us and still reaches 30s for a cold model.
func TTFBBuckets() []float64 {
	return []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
}

// BuildInfo is the build identity exported as flugschreiber_build_info, so
// that a scrape says which binary and which capture policy produced the
// evidence being written at that time.
type BuildInfo struct {
	Version     string
	Commit      string
	ContentMode string
}

// Metrics is the metric set this tool exports. Its methods are the only way to
// write a sample, and each one constrains its label values to a bounded set.
type Metrics struct {
	reg *Registry

	buildInfo      *GaugeVec
	requests       *CounterVec
	duration       *HistogramVec
	ttfb           *HistogramVec
	tokens         *CounterVec
	eventsAppended *Counter
	records        *Gauge
	captureErrors  *CounterVec
	checkpoints    *Counter
	archiveUploads *CounterVec
	evidenceBytes  *Gauge
	evidenceOver   *Gauge
	timestamps     *CounterVec

	models   *boundedSet
	backends *boundedSet
}

// New builds the metric set and registers it. Every family exists from the
// start, including those that have seen no traffic, so an absent series always
// means zero and never means "not wired up".
func New(b BuildInfo) *Metrics {
	m := &Metrics{
		reg: NewRegistry(),

		buildInfo: NewGaugeVec(nameBuildInfo,
			"Build identity and capture policy of the running binary, always 1.",
			"version", "commit", "content_mode"),
		requests: NewCounterVec(nameRequests,
			"Model interactions proxied, by endpoint class and outcome.",
			"endpoint", "method", "status_class", "stream"),
		duration: NewHistogramVec(nameDuration,
			"End to end duration of a proxied interaction in seconds.",
			RequestDurationBuckets(), "endpoint"),
		ttfb: NewHistogramVec(nameTTFB,
			"Seconds from receiving a request to the upstream's first response byte.",
			TTFBBuckets(), "endpoint"),
		tokens: NewCounterVec(nameTokens,
			"Tokens reported by the upstream, by model and kind.",
			"model", "kind"),
		eventsAppended: NewCounter(nameEventsAppended,
			"Evidence records appended to the chain by this process."),
		records: NewGauge(nameRecords,
			"Evidence records present in the log, including those written by earlier runs."),
		captureErrors: NewCounterVec(nameCaptureErrors,
			"Interactions that could not be fully recorded, by reason.", "reason"),
		checkpoints: NewCounter(nameCheckpoints,
			"Signed checkpoints written."),
		archiveUploads: NewCounterVec(nameArchiveUploads,
			"Evidence archive uploads attempted, by backend and outcome.",
			"backend", "result"),
		evidenceBytes: NewGauge(nameEvidenceBytes,
			"Total size in bytes of the evidence segments on disk."),
		evidenceOver: NewGauge(nameEvidenceOver,
			"Bytes by which the evidence segments exceed the configured size cap, or 0. "+
				"A positive value is a disk problem and never a signal to delete: the retention floor still holds."),
		timestamps: NewCounterVec(nameTimestamps,
			"RFC 3161 anchoring attempts for signed checkpoints, by outcome.", "result"),

		models:   newBoundedSet(maxModelLabels),
		backends: newBoundedSet(maxBackendLabels),
	}

	for _, c := range []Collector{
		m.buildInfo, m.requests, m.duration, m.ttfb, m.tokens,
		m.eventsAppended, m.records, m.captureErrors, m.checkpoints,
		m.archiveUploads, m.evidenceBytes, m.evidenceOver, m.timestamps,
	} {
		m.reg.MustRegister(c)
	}

	m.buildInfo.WithLabelValues(
		sanitizeLabelValue(b.Version),
		sanitizeLabelValue(b.Commit),
		sanitizeLabelValue(b.ContentMode),
	).Set(1)

	return m
}

// Registry returns the underlying registry, for a component that needs to add
// a family of its own.
func (m *Metrics) Registry() *Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// Handler serves the metric set. See Registry.Handler for why it belongs on a
// listener of its own.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return m.reg.Handler()
}

// RequestObservation describes one proxied interaction. Nothing in it is free
// text: Endpoint is a closed set, Method and Status are normalised, and no
// field can carry a request path, a credential or a session id.
type RequestObservation struct {
	// Endpoint is the endpoint class. A value outside the closed set is
	// recorded as EndpointOther.
	Endpoint Endpoint
	// Method is the HTTP method. Anything outside the standard set is recorded
	// as "other", because a client may send an arbitrary method token.
	Method string
	// Status is the HTTP status returned to the client. It is exported as a
	// class (2xx, 4xx, ...) rather than a code, and a zero means no response
	// was produced.
	Status int
	// Stream reports whether the response was a stream of server-sent events.
	Stream bool
	// Duration is the whole interaction. Zero or negative is not observed.
	Duration time.Duration
	// TTFB is the wait for the upstream's first response byte. Zero or negative
	// is not observed, which is the case when the upstream never responded.
	TTFB time.Duration
}

// ObserveRequest records one proxied interaction.
func (m *Metrics) ObserveRequest(o RequestObservation) {
	if m == nil {
		return
	}
	endpoint := string(EndpointFor(string(o.Endpoint)))

	m.requests.WithLabelValues(
		endpoint,
		normalizeMethod(o.Method),
		statusClass(o.Status),
		strconv.FormatBool(o.Stream),
	).Inc()

	if o.Duration > 0 {
		m.duration.WithLabelValues(endpoint).Observe(o.Duration.Seconds())
	}
	if o.TTFB > 0 {
		m.ttfb.WithLabelValues(endpoint).Observe(o.TTFB.Seconds())
	}
}

// AddTokens records token usage for one interaction.
//
// Pass the model the upstream reported serving, not the one the request asked
// for. The served name comes from the upstream and is bounded by how many
// models it hosts; the requested name is caller-controlled and would let a
// client mint time series by asking for models that do not exist. Beyond
// maxModelLabels distinct names the label folds into "other" regardless.
func (m *Metrics) AddTokens(servedModel string, prompt, completion int) {
	if m == nil {
		return
	}
	model := m.models.value(servedModel)
	if prompt > 0 {
		m.tokens.WithLabelValues(model, string(TokensPrompt)).Add(uint64(prompt))
	}
	if completion > 0 {
		m.tokens.WithLabelValues(model, string(TokensCompletion)).Add(uint64(completion))
	}
}

// EventAppended records one evidence record written by this process. It is a
// counter and therefore resets when the process does, which is why
// SetEvidenceRecords exists alongside it for the total on disk.
func (m *Metrics) EventAppended() {
	if m == nil {
		return
	}
	m.eventsAppended.Inc()
}

// CaptureError records an interaction that could not be fully recorded.
func (m *Metrics) CaptureError(reason CaptureErrorReason) {
	if m == nil {
		return
	}
	m.captureErrors.WithLabelValues(string(normalizeReason(reason))).Inc()
}

// CheckpointWritten records one signed checkpoint.
func (m *Metrics) CheckpointWritten() {
	if m == nil {
		return
	}
	m.checkpoints.Inc()
}

// ArchiveUpload records one upload attempt. The backend name comes from the
// operator's configuration rather than from traffic, so it is passed as a
// string, though it is still sanitised and capped.
func (m *Metrics) ArchiveUpload(backend string, result ArchiveResult) {
	if m == nil {
		return
	}
	m.archiveUploads.WithLabelValues(m.backends.value(backend), string(normalizeArchiveResult(result))).Inc()
}

// SetEvidenceRecords publishes how many records the log holds.
func (m *Metrics) SetEvidenceRecords(n uint64) {
	if m == nil {
		return
	}
	m.records.Set(float64(n))
}

// SetEvidenceBytes publishes the size of the evidence segments on disk.
func (m *Metrics) SetEvidenceBytes(n int64) {
	if m == nil {
		return
	}
	m.evidenceBytes.Set(float64(n))
}

// SetEvidenceBytesOverCap publishes how far the evidence directory is over its
// configured size cap.
//
// It is deliberately a gauge of the overshoot rather than a boolean, because
// the useful alert is "this has been over for a while and is growing", and
// because a tool that is over its cap has not misbehaved: the size cap never
// overrides the retention floor, so being over it means an operator has to add
// storage or record less. Zero when there is no cap or the directory is under it.
func (m *Metrics) SetEvidenceBytesOverCap(n int64) {
	if m == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	m.evidenceOver.Set(float64(n))
}

// TimestampAnchored records one anchoring attempt against a timestamping
// authority. Failures are counted separately from checkpoint writes because an
// authority being down costs anchors and never records.
func (m *Metrics) TimestampAnchored(ok bool) {
	if m == nil {
		return
	}
	result := "failure"
	if ok {
		result = "success"
	}
	m.timestamps.WithLabelValues(result).Inc()
}

// WriteTo renders the metric set, so that *Metrics is an io.WriterTo and can be
// dumped without going through HTTP.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, nil
	}
	return m.reg.WriteTo(w)
}

// statusClass reduces a status code to its class. A zero means the exchange
// ended before a status existed, which is a distinct outcome from a 5xx and is
// reported as such.
func statusClass(code int) string {
	switch {
	case code == 0:
		return "none"
	case code >= 100 && code < 600:
		return strconv.Itoa(code/100) + "xx"
	default:
		return labelOther
	}
}

// normalizeMethod folds anything outside the standard methods into "other". Go's
// server accepts any token as a method, so this label is caller-controlled
// until it is closed here.
func normalizeMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions,
		http.MethodTrace, http.MethodConnect:
		return strings.ToUpper(method)
	}
	return labelOther
}

func normalizeReason(r CaptureErrorReason) CaptureErrorReason {
	switch r {
	case CaptureErrorAppendFailed, CaptureErrorBodyRead, CaptureErrorUpstreamFailed,
		CaptureErrorEncryptFailed, CaptureErrorAbandoned:
		return r
	}
	return CaptureErrorUnknown
}

func normalizeArchiveResult(r ArchiveResult) ArchiveResult {
	switch r {
	case ArchiveSuccess, ArchiveSkipped:
		return r
	}
	return ArchiveFailure
}

// boundedSet caps how many distinct values a label may take.
type boundedSet struct {
	max int

	mu   sync.Mutex
	seen map[string]struct{}
}

func newBoundedSet(max int) *boundedSet {
	return &boundedSet{max: max, seen: make(map[string]struct{})}
}

// value returns v when it is already known or when the set has room, and the
// overflow placeholder otherwise. Every distinct label value is a time series
// that costs memory in this process and in every Prometheus that scrapes it,
// so the number of them any other party can create has to be finite.
func (b *boundedSet) value(v string) string {
	v = sanitizeLabelValue(v)
	if v == "" {
		return labelUnknown
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.seen[v]; ok {
		return v
	}
	if len(b.seen) >= b.max {
		return labelOther
	}
	b.seen[v] = struct{}{}
	return v
}

// sanitizeLabelValue bounds the length of a label value and strips control
// characters and invalid UTF-8. The renderer escapes these correctly either
// way; removing them here keeps a scrape readable and keeps a value that
// arrived over the wire from carrying anything that looks like structure.
func sanitizeLabelValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxLabelValueBytes {
		v = v[:maxLabelValueBytes]
		// Only a rune the cut itself split is dropped, at most UTFMax-1 bytes.
		// Testing the whole string for validity here would instead discard
		// everything after the first bad byte that was already in the value,
		// which collapses distinct names onto a shared prefix.
		for i := 0; i < utf8.UTFMax-1 && len(v) > 0; i++ {
			if r, size := utf8.DecodeLastRuneInString(v); r != utf8.RuneError || size > 1 {
				break
			}
			v = v[:len(v)-1]
		}
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, v)
}
