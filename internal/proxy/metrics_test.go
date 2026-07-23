package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
)

func scrape(t *testing.T, h *harness) string {
	t.Helper()
	resp, err := http.Get(h.proxy.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// hasSeries reports whether the scrape contains a sample line for name whose
// label set contains every fragment given.
func hasSeries(scrape, name string, fragments ...string) bool {
	for _, line := range strings.Split(scrape, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		ok := true
		for _, f := range fragments {
			if !strings.Contains(line, f) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestMetricsEndpointReportsProxiedTraffic(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	h.postAndDrain("/v1/chat/completions",
		`{"model":"llama-3.1-8b","messages":[{"role":"user","content":"hi"}]}`, nil)
	h.postAndDrain("/v1/chat/completions",
		`{"model":"llama-3.1-8b","stream":true,"stream_options":{"include_usage":true},"messages":[]}`, nil)
	h.postAndDrain("/v1/embeddings", `{"model":"bge-m3","input":["a"]}`, nil)

	out := scrape(t, h)

	if !hasSeries(out, "flugschreiber_build_info", `content_mode="hash"`) {
		t.Errorf("build info missing or does not carry the content mode:\n%s", out)
	}
	if !hasSeries(out, "flugschreiber_requests_total", `endpoint="chat"`, `status_class="2xx"`, `stream="false"`) {
		t.Error("no series for the non-streamed chat request")
	}
	if !hasSeries(out, "flugschreiber_requests_total", `endpoint="chat"`, `stream="true"`) {
		t.Error("no series for the streamed chat request")
	}
	if !hasSeries(out, "flugschreiber_requests_total", `endpoint="embedding"`) {
		t.Error("no series for the embeddings request")
	}
	for _, name := range []string{
		"flugschreiber_request_duration_seconds_bucket",
		"flugschreiber_request_duration_seconds_count",
		"flugschreiber_upstream_ttfb_seconds_bucket",
		"flugschreiber_tokens_total",
		"flugschreiber_events_appended_total",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("scrape is missing %s", name)
		}
	}
	if !hasSeries(out, "flugschreiber_tokens_total", `kind="prompt"`) ||
		!hasSeries(out, "flugschreiber_tokens_total", `kind="completion"`) {
		t.Errorf("token accounting is not split by kind:\n%s", out)
	}
}

// Labels must never carry anything a caller controls without bound. A prompt,
// a session id or a client hash in a label is both a cardinality explosion and
// a data-protection problem.
func TestMetricsNeverLeakCallerControlledValues(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	const secret = "patient-12345-has-a-rare-condition"
	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"`+secret+`"}]}`,
		map[string]string{
			"Authorization": "Bearer sk-super-secret",
			SessionHeader:   "sess-" + secret,
		})

	out := scrape(t, h)
	for _, forbidden := range []string{secret, "sk-super-secret", "sess-"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("caller-controlled value %q reached a metric label:\n%s", forbidden, out)
		}
	}
}

func TestMetricsRecordUpstreamFailures(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.Upstream = "http://127.0.0.1:1"
	})

	resp := h.post("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	out := scrape(t, h)
	if !hasSeries(out, "flugschreiber_requests_total", `status_class="5xx"`) {
		t.Errorf("an unreachable upstream produced no 5xx series:\n%s", out)
	}
}

func TestMetricsEndpointCanBeDisabled(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.MetricsEnabled = false
	})

	resp, err := http.Get(h.proxy.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// The route must still be claimed. If it fell through to the proxy, a
	// Prometheus scrape would be forwarded upstream and would return the model
	// server's own metrics under Flugschreiber's name.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics = %d with metrics disabled, want 404: %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "flugschreiber_requests_total") {
		t.Errorf("metrics were served with the endpoint disabled:\n%s", body)
	}
	if strings.Contains(string(body), "mock upstream") {
		t.Errorf("the scrape was forwarded to the upstream:\n%s", body)
	}
}

// Two scrapes of unchanged state must be byte-identical, or the output is
// unusable in a diff and the exporter is hiding non-determinism.
func TestScrapeIsStable(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	for i := 0; i < 5; i++ {
		h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
	}

	first := scrape(t, h)
	second := scrape(t, h)
	if first != second {
		t.Error("two scrapes of unchanged state differ")
	}
}

func TestOversightEventsAreCountedAsAppended(t *testing.T) {
	h := eventsHarness(t)

	before := scrape(t, h)
	resp := h.postEvent(`{"event_type":"human_intervention","actor":"a","decision":"approve"}`, testToken)
	drain(t, resp)
	after := scrape(t, h)

	if before == after {
		t.Error("recording an oversight event changed no metric")
	}
	if !strings.Contains(after, "flugschreiber_events_appended_total") {
		t.Error("events_appended_total is absent")
	}
}
