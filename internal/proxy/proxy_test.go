package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/config"
	"github.com/flugschreiber/flugschreiber/internal/evidence"
	"github.com/flugschreiber/flugschreiber/internal/mockupstream"
)

type harness struct {
	t       *testing.T
	proxy   *httptest.Server
	dataDir string
	store   *evidence.Store
}

func newHarness(t *testing.T, upstream http.Handler, tune func(*config.Config)) *harness {
	t.Helper()

	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	dir := t.TempDir()
	cfg := config.Default()
	cfg.Upstream = up.URL
	cfg.DataDir = dir
	cfg.ContentMode = evidence.ModeHash
	if tune != nil {
		tune(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	srv, err := New(cfg, store, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	ps := httptest.NewServer(srv.Handler())
	t.Cleanup(ps.Close)

	return &harness{t: t, proxy: ps, dataDir: dir, store: store}
}

func (h *harness) post(path, body string, headers map[string]string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.proxy.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

// postAndDrain sends a request and fully consumes the response, which is what
// makes the evidence record final.
func (h *harness) postAndDrain(path, body string, headers map[string]string) string {
	h.t.Helper()
	resp := h.post(path, body, headers)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

// events returns everything recorded, in chain order.
//
// The record for a request is appended after the response body has been fully
// relayed, which is after the client's read returns. Closing the test server
// first waits for outstanding handlers, so the log is complete before it is
// read — no sleeps, no flakes.
func (h *harness) events() []evidence.Event {
	h.t.Helper()
	h.proxy.Close()
	if err := h.store.Close(); err != nil {
		h.t.Fatalf("close store: %v", err)
	}
	var out []evidence.Event
	if err := evidence.Walk(h.dataDir, func(e evidence.Entry) error {
		out = append(out, e.Event)
		return nil
	}); err != nil {
		h.t.Fatalf("walk: %v", err)
	}
	return out
}

func mockHandler() http.Handler {
	return mockupstream.Handler(mockupstream.Options{})
}

func TestNonStreamedChatIsRecorded(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	body := `{"model":"llama-3.1-8b","temperature":0.3,"messages":[{"role":"user","content":"hello"}]}`
	out := h.postAndDrain("/v1/chat/completions", body, map[string]string{
		"Authorization": "Bearer secret-key",
	})
	if !strings.Contains(out, "mock upstream") {
		t.Fatalf("upstream response not relayed: %s", out)
	}

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if e.EventType != evidence.EventInference {
		t.Errorf("EventType = %q", e.EventType)
	}
	if e.ModelRequested != "llama-3.1-8b" {
		t.Errorf("ModelRequested = %q", e.ModelRequested)
	}
	if e.ModelServed != mockupstream.ModelName {
		t.Errorf("ModelServed = %q", e.ModelServed)
	}
	if e.Status != 200 {
		t.Errorf("Status = %d", e.Status)
	}
	if e.Stream {
		t.Error("Stream = true for a non-streamed request")
	}
	if e.Usage == nil || e.Usage.TotalTokens == 0 {
		t.Errorf("Usage = %+v, want token accounting", e.Usage)
	}
	if len(e.FinishReasons) != 1 || e.FinishReasons[0] != "stop" {
		t.Errorf("FinishReasons = %v", e.FinishReasons)
	}
	if e.LatencyMS <= 0 {
		t.Errorf("LatencyMS = %v", e.LatencyMS)
	}
	if e.RequestID == "" {
		t.Error("RequestID is empty")
	}
}

func TestStreamedChatIsRecordedAndReassembled(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.ContentMode = evidence.ModeStore
	})

	body := `{"model":"m","stream":true,"stream_options":{"include_usage":true},` +
		`"messages":[{"role":"user","content":"summarise this"}]}`
	raw := h.postAndDrain("/v1/chat/completions", body, nil)

	if !strings.Contains(raw, "data: ") || !strings.Contains(raw, "[DONE]") {
		t.Fatalf("client did not receive an SSE stream: %q", raw)
	}

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if !e.Stream {
		t.Error("Stream = false for a streamed request")
	}
	if len(e.FinishReasons) != 1 || e.FinishReasons[0] != "stop" {
		t.Errorf("FinishReasons = %v", e.FinishReasons)
	}
	if e.Usage == nil || e.Usage.CompletionTokens == 0 {
		t.Errorf("Usage = %+v, want usage from the final chunk", e.Usage)
	}

	// The recorded output must be the assembled message, not the frames.
	got := e.Content.Output.Text
	if strings.Contains(got, "data:") || strings.Contains(got, "chat.completion.chunk") {
		t.Errorf("output was recorded as raw frames, not reassembled: %q", got)
	}
	if !strings.Contains(got, "summarise this") {
		t.Errorf("assembled output does not contain the expected reply: %q", got)
	}
}

// Streaming must reach the client incrementally. If the proxy buffered the
// response, a chat UI would sit blank until generation finished.
func TestStreamingIsNotBuffered(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `data: {"id":"c","choices":[{"index":0,"delta":{"content":"first"}}]}`+"\n\n")
		f.Flush()
		<-release
		io.WriteString(w, `data: {"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
		f.Flush()
	})

	h := newHarness(t, upstream, nil)
	resp := h.post("/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`, nil)
	defer resp.Body.Close()

	first := make([]byte, 64)
	done := make(chan int, 1)
	go func() {
		n, _ := resp.Body.Read(first)
		done <- n
	}()

	select {
	case n := <-done:
		if n == 0 {
			t.Fatal("read returned no bytes before the upstream finished")
		}
		if !bytes.Contains(first[:n], []byte("first")) {
			t.Errorf("first flush not relayed: %q", first[:n])
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("no bytes reached the client before the upstream finished: the proxy is buffering the stream")
	}
	close(release)
	io.Copy(io.Discard, resp.Body)
}

// hash mode is the default and must never write prompt or completion text to
// disk. This is the data-protection promise the README makes.
func TestHashModeStoresNoText(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	const secret = "patient identifier 12345 has a rare condition"
	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"`+secret+`"}]}`, nil)

	events := h.events()
	e := events[0]
	if e.Content.Mode != evidence.ModeHash {
		t.Fatalf("Mode = %q, want hash by default", e.Content.Mode)
	}
	if e.Content.Input.Text != "" || len(e.Content.Input.Messages) != 0 {
		t.Errorf("hash mode retained input text: %+v", e.Content.Input)
	}
	if e.Content.Output.Text != "" {
		t.Errorf("hash mode retained output text: %q", e.Content.Output.Text)
	}
	if len(e.Content.Input.SHA256) != 64 || len(e.Content.Output.SHA256) != 64 {
		t.Errorf("expected SHA-256 digests, got %+v", e.Content)
	}
	if e.Content.Input.Bytes == 0 {
		t.Error("input byte count not recorded")
	}

	// Belt and braces: the secret must not appear anywhere in the segment.
	assertNotOnDisk(t, h.dataDir, secret)
}

func TestStoreModeRetainsMessages(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.ContentMode = evidence.ModeStore
	})

	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"why?"}]}`, nil)

	e := h.events()[0]
	if len(e.Content.Input.Messages) != 2 {
		t.Fatalf("Messages = %+v, want both messages retained", e.Content.Input.Messages)
	}
	if e.Content.Input.Messages[0].Role != "system" || e.Content.Input.Messages[1].Content != "why?" {
		t.Errorf("Messages = %+v", e.Content.Input.Messages)
	}
}

func TestRedactModeReplacesMatchesAndCounts(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.ContentMode = evidence.ModeRedact
		c.RedactPatterns = []string{"email"}
	})

	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"write to anna@example.com and bo@example.org"}]}`, nil)

	e := h.events()[0]
	got := e.Content.Input.Messages[0].Content
	if strings.Contains(got, "@example.com") || strings.Contains(got, "@example.org") {
		t.Errorf("email addresses survived redaction: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:email]") {
		t.Errorf("no redaction marker in %q", got)
	}
	if e.Content.Input.Redactions["email"] != 2 {
		t.Errorf("Redactions = %v, want two email hits", e.Content.Input.Redactions)
	}
	assertNotOnDisk(t, h.dataDir, "anna@example.com")
}

// The digest must cover the wire bytes in every mode, so a transcript held
// elsewhere can be checked against a log that stores no text.
func TestDigestIsOverWireBytesInEveryMode(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"stable input"}]}`

	digests := map[string]string{}
	for _, mode := range []string{evidence.ModeHash, evidence.ModeStore, evidence.ModeRedact} {
		h := newHarness(t, mockHandler(), func(c *config.Config) { c.ContentMode = mode })
		h.postAndDrain("/v1/chat/completions", body, nil)
		digests[mode] = h.events()[0].Content.Input.SHA256
	}

	if digests[evidence.ModeHash] != digests[evidence.ModeStore] ||
		digests[evidence.ModeHash] != digests[evidence.ModeRedact] {
		t.Errorf("input digest differs by content mode: %v", digests)
	}
}

func TestClientIdentityIsHashedNotStored(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	const key = "sk-super-secret-key-value"
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`,
		map[string]string{"Authorization": "Bearer " + key})

	e := h.events()[0]
	if e.ClientHash == "" {
		t.Fatal("ClientHash is empty; traffic cannot be attributed")
	}
	if strings.Contains(e.ClientHash, key) {
		t.Error("the API key leaked into the client hash")
	}
	assertNotOnDisk(t, h.dataDir, key)
}

// The same credential must produce the same identifier, or per-caller
// attribution across a log is meaningless.
func TestClientHashIsStableAcrossRequests(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	headers := map[string]string{"Authorization": "Bearer same-key"}
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, headers)
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, headers)
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`,
		map[string]string{"Authorization": "Bearer other-key"})

	events := h.events()
	if events[0].ClientHash != events[1].ClientHash {
		t.Error("the same credential produced different identifiers")
	}
	if events[0].ClientHash == events[2].ClientHash {
		t.Error("different credentials produced the same identifier")
	}
}

func TestSessionHeaderGroupsRequests(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`,
		map[string]string{SessionHeader: "sess-7"})

	if got := h.events()[0].SessionID; got != "sess-7" {
		t.Errorf("SessionID = %q, want sess-7", got)
	}
}

func TestUpstreamErrorIsRecorded(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"model not found"}}`, http.StatusNotFound)
	})
	h := newHarness(t, upstream, nil)

	resp := h.post("/v1/chat/completions", `{"model":"nope","messages":[]}`, nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	e := h.events()[0]
	if e.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want 404", e.Status)
	}
	if e.ModelRequested != "nope" {
		t.Errorf("ModelRequested = %q; a failed request is still evidence", e.ModelRequested)
	}
}

func TestUnreachableUpstreamIsRecorded(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		// A port nothing is listening on.
		c.Upstream = "http://127.0.0.1:1"
	})

	resp := h.post("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want the failed attempt to be recorded", len(events))
	}
	if events[0].Error == "" {
		t.Error("Error is empty for an unreachable upstream")
	}
	if events[0].Status != http.StatusBadGateway {
		t.Errorf("Status = %d, want 502", events[0].Status)
	}
}

// Endpoints the proxy does not record must still work, or dropping the proxy
// in front of an existing app would break it.
func TestUnrecordedEndpointsPassThrough(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	resp, err := http.Get(h.proxy.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), mockupstream.ModelName) {
		t.Fatalf("GET /v1/models = %d %s", resp.StatusCode, body)
	}

	if events := h.events(); len(events) != 0 {
		t.Errorf("recorded %d events for a non-inference endpoint, want 0", len(events))
	}
}

func TestEmbeddingsAreRecordedWithoutVectors(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) {
		c.ContentMode = evidence.ModeStore
	})

	h.postAndDrain("/v1/embeddings", `{"model":"bge-m3","input":["one","two"]}`, nil)

	e := h.events()[0]
	if e.Endpoint != "/v1/embeddings" {
		t.Errorf("Endpoint = %q", e.Endpoint)
	}
	if !strings.Contains(e.Note, "2 embedding vectors") {
		t.Errorf("Note = %q, want the vector count", e.Note)
	}
	if strings.Contains(e.Content.Output.Text, "0.") {
		t.Errorf("embedding vectors were written into the transcript: %q", e.Content.Output.Text)
	}
}

func TestToolCallsAreRecorded(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant",
			"tool_calls":[{"id":"call_1","type":"function","function":{"name":"refund","arguments":"{\"order\":7}"}}]},
			"finish_reason":"tool_calls"}]}`)
	})

	h := newHarness(t, upstream, func(c *config.Config) { c.ContentMode = evidence.ModeStore })
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)

	e := h.events()[0]
	if len(e.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v", e.ToolCalls)
	}
	tc := e.ToolCalls[0]
	if tc.Name != "refund" || tc.Arguments != `{"order":7}` {
		t.Errorf("ToolCall = %+v", tc)
	}
	if len(tc.ArgumentsHash) != 64 {
		t.Errorf("ArgumentsHash = %q, want a SHA-256", tc.ArgumentsHash)
	}
}

// In hash mode tool arguments are as sensitive as prompts and must not be
// written out verbatim.
func TestToolArgumentsAreHashedInHashMode(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant",
			"tool_calls":[{"id":"call_1","type":"function","function":{"name":"refund","arguments":"{\"iban\":\"DE89370400440532013000\"}"}}]},
			"finish_reason":"tool_calls"}]}`)
	})

	h := newHarness(t, upstream, nil)
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)

	e := h.events()[0]
	if e.ToolCalls[0].Arguments != "" {
		t.Errorf("hash mode retained tool arguments: %q", e.ToolCalls[0].Arguments)
	}
	if e.ToolCalls[0].ArgumentsHash == "" {
		t.Error("tool arguments were not hashed")
	}
	assertNotOnDisk(t, h.dataDir, "DE89370400440532013000")
}

func TestChainVerifiesAfterProxyTraffic(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	for i := 0; i < 5; i++ {
		h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	}
	h.postAndDrain("/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`, nil)
	h.events()

	res, err := evidence.Verify(h.dataDir)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("chain broken after proxy traffic: %v", res.Problems)
	}
	if res.Records != 6 {
		t.Errorf("Records = %d, want 6", res.Records)
	}
}

func TestHealthEndpointReportsRecordCount(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	h.postAndDrain("/v1/chat/completions", `{"model":"m","messages":[]}`, nil)

	// The count is eventually consistent: the record is appended once the
	// handler finishes relaying the response, which can be marginally after
	// the client's last read returns.
	deadline := time.Now().Add(2 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := http.Get(h.proxy.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz = %d: %s", resp.StatusCode, body)
		}
		if strings.Contains(string(body), `"records":1`) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("healthz never reported the record: %s", body)
}

func assertNotOnDisk(t *testing.T, dir, needle string) {
	t.Helper()
	segs, err := evidence.Segments(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, seg := range segs {
		raw, err := readFile(seg.Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, needle) {
			t.Fatalf("%q was written to %s", needle, seg.Path)
		}
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
