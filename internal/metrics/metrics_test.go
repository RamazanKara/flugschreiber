package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestMetrics() *Metrics {
	return New(BuildInfo{Version: "1.2.3", Commit: "abc123", ContentMode: "hash"})
}

func body(t *testing.T, m *Metrics) string {
	t.Helper()
	var b strings.Builder
	if _, err := m.WriteTo(&b); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return b.String()
}

func TestEveryContractedMetricExistsFromTheStart(t *testing.T) {
	// A missing family and a family at zero look identical to a dashboard
	// unless every family is registered up front, so this pins the whole set.
	want := map[string]string{
		"flugschreiber_build_info":               "gauge",
		"flugschreiber_requests_total":           "counter",
		"flugschreiber_request_duration_seconds": "histogram",
		"flugschreiber_upstream_ttfb_seconds":    "histogram",
		"flugschreiber_tokens_total":             "counter",
		"flugschreiber_events_appended_total":    "counter",
		"flugschreiber_evidence_records":         "gauge",
		"flugschreiber_capture_errors_total":     "counter",
		"flugschreiber_checkpoints_total":        "counter",
		"flugschreiber_archive_uploads_total":    "counter",
		"flugschreiber_evidence_bytes":           "gauge",
	}

	got := make(map[string]string)
	for _, line := range strings.Split(body(t, newTestMetrics()), "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		parts := strings.Fields(line)
		got[parts[2]] = parts[3]
	}

	for name, typ := range want {
		if got[name] != typ {
			t.Errorf("%s is %q, want %q", name, got[name], typ)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s is exported but is not in the agreed metric set", name)
		}
	}
}

func TestBuildInfoIsOneAndCarriesTheCapturePolicy(t *testing.T) {
	m := New(BuildInfo{Version: "1.2.3", Commit: "deadbeef", ContentMode: "redact"})
	want := `flugschreiber_build_info{version="1.2.3",commit="deadbeef",content_mode="redact"} 1` + "\n"
	if got := body(t, m); !strings.Contains(got, want) {
		t.Errorf("got:\n%s\nwant a line: %s", got, want)
	}
}

func TestCallerControlledValuesCannotCreateNewSeries(t *testing.T) {
	tests := []struct {
		name         string
		observation  RequestObservation
		wantEndpoint string
		wantMethod   string
		wantStatus   string
	}{
		{
			name:         "a known endpoint and method pass through",
			observation:  RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 200},
			wantEndpoint: "chat", wantMethod: "POST", wantStatus: "2xx",
		},
		{
			name:         "a request path cast to an Endpoint collapses to other",
			observation:  RequestObservation{Endpoint: Endpoint("/v1/chat/completions?x=1"), Method: "POST", Status: 200},
			wantEndpoint: "other", wantMethod: "POST", wantStatus: "2xx",
		},
		{
			name:         "an arbitrary method token collapses to other",
			observation:  RequestObservation{Endpoint: EndpointChat, Method: "FROBNICATE", Status: 500},
			wantEndpoint: "chat", wantMethod: "other", wantStatus: "5xx",
		},
		{
			name:         "a method carrying exposition syntax collapses to other",
			observation:  RequestObservation{Endpoint: EndpointEmbedding, Method: "P\"OST\n", Status: 404},
			wantEndpoint: "embedding", wantMethod: "other", wantStatus: "4xx",
		},
		{
			name:         "a lowercase method is normalised rather than duplicated",
			observation:  RequestObservation{Endpoint: EndpointCompletion, Method: "post", Status: 200},
			wantEndpoint: "completion", wantMethod: "POST", wantStatus: "2xx",
		},
		{
			name:         "no response at all is its own status class",
			observation:  RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 0},
			wantEndpoint: "chat", wantMethod: "POST", wantStatus: "none",
		},
		{
			name:         "the client-hangup code is a 4xx",
			observation:  RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 499},
			wantEndpoint: "chat", wantMethod: "POST", wantStatus: "4xx",
		},
		{
			name:         "a status outside the defined ranges collapses to other",
			observation:  RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 9000},
			wantEndpoint: "chat", wantMethod: "POST", wantStatus: "other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMetrics()
			m.ObserveRequest(tt.observation)

			want := "flugschreiber_requests_total{endpoint=\"" + tt.wantEndpoint +
				"\",method=\"" + tt.wantMethod +
				"\",status_class=\"" + tt.wantStatus +
				"\",stream=\"false\"} 1\n"
			if got := body(t, m); !strings.Contains(got, want) {
				t.Errorf("want a line: %s\ngot:\n%s", want, got)
			}
		})
	}
}

func TestRequestSeriesCountIsBoundedByTheClosedLabelSets(t *testing.T) {
	m := newTestMetrics()
	for i := range 2000 {
		m.ObserveRequest(RequestObservation{
			Endpoint: Endpoint("/v1/chat/" + strconv.Itoa(i)),
			Method:   "METHOD" + strconv.Itoa(i),
			Status:   200,
			Stream:   i%2 == 0,
		})
	}

	var series int
	for _, line := range strings.Split(body(t, m), "\n") {
		if strings.HasPrefix(line, "flugschreiber_requests_total{") {
			series++
		}
	}
	// endpoint x method x status_class x stream, all closed, so 2000 distinct
	// paths and methods produce two series and not two thousand.
	if series != 2 {
		t.Errorf("2000 distinct paths and methods produced %d series, want 2", series)
	}
}

func TestDurationsAreObservedAndZeroTTFBIsNot(t *testing.T) {
	m := newTestMetrics()
	m.ObserveRequest(RequestObservation{
		Endpoint: EndpointChat, Method: "POST", Status: 200,
		Duration: 1500 * time.Millisecond, TTFB: 800 * time.Microsecond,
	})
	// An upstream that never answered has no time to first byte to report,
	// and a zero would drag the histogram's low buckets down.
	m.ObserveRequest(RequestObservation{
		Endpoint: EndpointChat, Method: "POST", Status: 0,
		Duration: 2 * time.Second,
	})

	got := samples(t, body(t, m))
	if got[`flugschreiber_request_duration_seconds_count{endpoint="chat"}`] != "2" {
		t.Errorf("duration count = %q, want 2", got[`flugschreiber_request_duration_seconds_count{endpoint="chat"}`])
	}
	if got[`flugschreiber_upstream_ttfb_seconds_count{endpoint="chat"}`] != "1" {
		t.Errorf("ttfb count = %q, want 1", got[`flugschreiber_upstream_ttfb_seconds_count{endpoint="chat"}`])
	}
	// 0.8ms belongs in the second TTFB bucket, which is the resolution this
	// bucket set exists to provide.
	if got[`flugschreiber_upstream_ttfb_seconds_bucket{endpoint="chat",le="0.0005"}`] != "0" {
		t.Errorf("0.8ms fell into the 0.5ms bucket")
	}
	if got[`flugschreiber_upstream_ttfb_seconds_bucket{endpoint="chat",le="0.001"}`] != "1" {
		t.Errorf("0.8ms is not in the 1ms bucket: %v", got[`flugschreiber_upstream_ttfb_seconds_bucket{endpoint="chat",le="0.001"}`])
	}
}

func TestTTFBBucketsResolveSubMillisecondAndMultiSecondUpstreams(t *testing.T) {
	b := TTFBBuckets()
	if b[0] > 0.001 {
		t.Errorf("lowest TTFB bucket is %v, too coarse for a loopback upstream where TTFB is the proxy's own overhead", b[0])
	}
	if b[len(b)-1] < 10 {
		t.Errorf("highest TTFB bucket is %v, too low for a cold model doing prefill", b[len(b)-1])
	}

	d := RequestDurationBuckets()
	if d[len(d)-1] < 600 {
		t.Errorf("highest duration bucket is %v, below the default upstream request timeout", d[len(d)-1])
	}

	// Returning a copy keeps a caller from reordering the package defaults
	// under a histogram that has already been built.
	TTFBBuckets()[0] = 99
	if TTFBBuckets()[0] == 99 {
		t.Error("TTFBBuckets returns a shared slice")
	}
}

func TestTokensAreCountedPerModelAndKind(t *testing.T) {
	m := newTestMetrics()
	m.AddTokens("llama-3.1-8b", 100, 250)
	m.AddTokens("llama-3.1-8b", 10, 0)

	got := samples(t, body(t, m))
	if got[`flugschreiber_tokens_total{model="llama-3.1-8b",kind="prompt"}`] != "110" {
		t.Errorf("prompt tokens = %q, want 110", got[`flugschreiber_tokens_total{model="llama-3.1-8b",kind="prompt"}`])
	}
	if got[`flugschreiber_tokens_total{model="llama-3.1-8b",kind="completion"}`] != "250" {
		t.Errorf("completion tokens = %q, want 250", got[`flugschreiber_tokens_total{model="llama-3.1-8b",kind="completion"}`])
	}
}

func TestModelLabelIsCappedAndSanitised(t *testing.T) {
	m := newTestMetrics()
	for i := range maxModelLabels + 50 {
		m.AddTokens("model-"+strconv.Itoa(i), 1, 1)
	}
	m.AddTokens("", 1, 1)
	m.AddTokens(strings.Repeat("x", 4096), 1, 1)

	out := body(t, m)
	var series int
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "flugschreiber_tokens_total{") {
			series++
		}
	}
	// Two kinds per model, plus the overflow and unknown placeholders.
	if want := 2 * (maxModelLabels + 2); series != want {
		t.Errorf("%d token series, want %d (the model label must stop growing at %d values)", series, want, maxModelLabels)
	}
	if !strings.Contains(out, `model="other"`) {
		t.Error("models past the cap should fold into other")
	}
	if !strings.Contains(out, `model="unknown"`) {
		t.Error("an empty model name should be recorded as unknown")
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 512 {
			t.Errorf("a single sample line is %d bytes, label values are not being truncated", len(line))
		}
	}
}

func TestCaptureErrorReasonsStayWithinTheClosedSet(t *testing.T) {
	tests := []struct {
		name   string
		reason CaptureErrorReason
		want   string
	}{
		{"append failure", CaptureErrorAppendFailed, "append_failed"},
		{"body read failure", CaptureErrorBodyRead, "body_read_failed"},
		{"upstream failure", CaptureErrorUpstreamFailed, "upstream_failed"},
		{"an error string cast to a reason", CaptureErrorReason("dial tcp 10.0.0.1:8000: refused"), "unknown"},
		{"the empty reason", CaptureErrorReason(""), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMetrics()
			m.CaptureError(tt.reason)

			want := `flugschreiber_capture_errors_total{reason="` + tt.want + `"} 1` + "\n"
			if got := body(t, m); !strings.Contains(got, want) {
				t.Errorf("want a line: %s\ngot:\n%s", want, got)
			}
		})
	}
}

func TestArchiveResultsStayWithinTheClosedSet(t *testing.T) {
	tests := []struct {
		name    string
		backend string
		result  ArchiveResult
		want    string
	}{
		{"success", "s3", ArchiveSuccess, `flugschreiber_archive_uploads_total{backend="s3",result="success"} 1`},
		{"skipped", "filesystem", ArchiveSkipped, `flugschreiber_archive_uploads_total{backend="filesystem",result="skipped"} 1`},
		{"an unknown result is a failure, never a success", "s3", ArchiveResult("weird"), `flugschreiber_archive_uploads_total{backend="s3",result="failure"} 1`},
		{"an unnamed backend", "", ArchiveFailure, `flugschreiber_archive_uploads_total{backend="unknown",result="failure"} 1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMetrics()
			m.ArchiveUpload(tt.backend, tt.result)
			if got := body(t, m); !strings.Contains(got, tt.want+"\n") {
				t.Errorf("want a line: %s\ngot:\n%s", tt.want, got)
			}
		})
	}
}

func TestEndpointForRejectsAnythingUnrecognised(t *testing.T) {
	tests := []struct {
		in   string
		want Endpoint
	}{
		{"chat", EndpointChat},
		{"completion", EndpointCompletion},
		{"embedding", EndpointEmbedding},
		{"responses", EndpointResponses},
		{"other", EndpointOther},
		{"/v1/chat/completions", EndpointOther},
		{"", EndpointOther},
		{"CHAT", EndpointOther},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := EndpointFor(tt.in); got != tt.want {
				t.Errorf("EndpointFor(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// The Responses API is its own endpoint class, so its traffic must land on a
// distinct series rather than collapsing into "other".
func TestResponsesIsADistinctEndpointSeries(t *testing.T) {
	m := newTestMetrics()
	m.ObserveRequest(RequestObservation{Endpoint: EndpointResponses, Method: "POST", Status: 200})
	m.ObserveRequest(RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 200})

	got := body(t, m)
	responses := "flugschreiber_requests_total{endpoint=\"responses\",method=\"POST\",status_class=\"2xx\",stream=\"false\"} 1\n"
	if !strings.Contains(got, responses) {
		t.Errorf("want a responses series line: %s\ngot:\n%s", responses, got)
	}
	if strings.Contains(got, "endpoint=\"other\"") {
		t.Errorf("responses traffic collapsed into the other series:\n%s", got)
	}
}

func TestGaugesReportTheStateOfTheEvidenceDirectory(t *testing.T) {
	m := newTestMetrics()
	m.SetEvidenceRecords(12345)
	m.SetEvidenceBytes(67108864)
	m.EventAppended()
	m.EventAppended()
	m.CheckpointWritten()

	got := samples(t, body(t, m))
	for series, want := range map[string]string{
		"flugschreiber_evidence_records":      "12345",
		"flugschreiber_evidence_bytes":        "67108864",
		"flugschreiber_events_appended_total": "2",
		"flugschreiber_checkpoints_total":     "1",
	} {
		if got[series] != want {
			t.Errorf("%s = %q, want %q", series, got[series], want)
		}
	}
}

func TestSanitizeLabelValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "llama-3.1-8b", "llama-3.1-8b"},
		{"surrounding space is trimmed", "  gpt-4o  ", "gpt-4o"},
		{"a newline becomes an underscore", "a\nb", "a_b"},
		{"a tab becomes an underscore", "a\tb", "a_b"},
		{"invalid utf-8 becomes an underscore", "a\xffb", "a_b"},
		{"non-ascii text survives", "modell-f\u00fcr-deutsch", "modell-f\u00fcr-deutsch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeLabelValue(tt.in); got != tt.want {
				t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	long := sanitizeLabelValue(strings.Repeat("\u00e4", 400))
	if len(long) > maxLabelValueBytes {
		t.Errorf("truncated value is %d bytes, want at most %d", len(long), maxLabelValueBytes)
	}
	if strings.Contains(long, "_") {
		t.Error("truncation split a multi-byte rune and left a replacement behind")
	}
}

func TestTruncationKeepsDistinctLongValuesDistinct(t *testing.T) {
	// A bad byte early in a long value must not take the rest of the value with
	// it: two models that share a corrupt prefix would otherwise collapse onto
	// one series and their token counts would be added together.
	a := sanitizeLabelValue("mo\xffdel-a-" + strings.Repeat("x", 200))
	b := sanitizeLabelValue("mo\xffdel-b-" + strings.Repeat("y", 200))

	for _, got := range []string{a, b} {
		if len(got) > maxLabelValueBytes {
			t.Errorf("value is %d bytes, want at most %d", len(got), maxLabelValueBytes)
		}
		if !strings.HasPrefix(got, "mo_del-") {
			t.Errorf("sanitised value is %q, want the text after the invalid byte preserved", got)
		}
	}
	if a == b {
		t.Errorf("two distinct model names both sanitised to %q", a)
	}
}

func TestNilMetricsIsSafeToCall(t *testing.T) {
	// The CLI can then pass nil when metrics are switched off, and the proxy
	// needs no branch at any call site.
	var m *Metrics
	m.ObserveRequest(RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 200, Duration: time.Second})
	m.AddTokens("m", 1, 1)
	m.EventAppended()
	m.CaptureError(CaptureErrorAppendFailed)
	m.CheckpointWritten()
	m.ArchiveUpload("s3", ArchiveSuccess)
	m.SetEvidenceRecords(1)
	m.SetEvidenceBytes(1)
	if m.Registry() != nil {
		t.Error("a nil Metrics should have no registry")
	}

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("handler of a nil Metrics returned %d, want 404", rec.Code)
	}
}

func TestExportedSetIsStableAcrossScrapes(t *testing.T) {
	m := newTestMetrics()
	m.ObserveRequest(RequestObservation{Endpoint: EndpointChat, Method: "POST", Status: 200, Stream: true, Duration: time.Second, TTFB: time.Millisecond})
	m.AddTokens("llama", 5, 7)

	if first, second := body(t, m), body(t, m); first != second {
		t.Errorf("two scrapes of the same state differ:\n%s\n%s", first, second)
	}
}
