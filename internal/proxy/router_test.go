package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"llama-3.1-8b", "llama-3.1-8b", true},
		{"llama-3.1-8b", "llama-3.1-70b", false},
		{"llama-*", "llama-3.1-8b", true},
		{"llama-*", "mistral-7b", false},
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"gpt-4?", "gpt-4o", true},
		{"gpt-4?", "gpt-4", false},
		{"*-8b", "meta/llama-3.1-8b", true},
		{"*llama*", "meta/llama-3.1-8b", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.name); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestSelectRoute(t *testing.T) {
	chat := &route{name: "chat", models: []string{"llama-*"}, endpoints: map[string]bool{"chat": true}}
	embed := &route{name: "embed", models: []string{"bge-*"}, endpoints: map[string]bool{"embedding": true}}
	def := &route{name: "fallback", isDefault: true}
	rt := &router{routes: []*route{chat, embed, def}, def: def}

	cases := []struct {
		name, model, kind, want string
	}{
		{"model glob and endpoint match", "llama-3.1-8b", "chat", "chat"},
		{"the other route", "bge-m3", "embedding", "embed"},
		{"right model wrong endpoint falls to default", "llama-3.1-8b", "embedding", "fallback"},
		{"unknown model falls to default", "unknown", "chat", "fallback"},
		{"embed model on chat endpoint falls to default", "bge-m3", "chat", "fallback"},
	}
	for _, tc := range cases {
		got := rt.selectRoute(tc.model, tc.kind)
		name := "<nil>"
		if got != nil {
			name = got.name
		}
		if name != tc.want {
			t.Errorf("%s: selectRoute(%q, %q) = %q, want %q", tc.name, tc.model, tc.kind, name, tc.want)
		}
	}
}

// A route whose Endpoints list does not include the request's kind never serves
// it, even when a model glob matches.
func TestEndpointRestrictionExcludesAMatchingModel(t *testing.T) {
	chatOnly := &route{name: "chat", models: []string{"*"}, endpoints: map[string]bool{"chat": true}}
	if chatOnly.matches("any-model", "embedding") {
		t.Error("a chat-only route matched an embedding request")
	}
	if !chatOnly.matches("any-model", "chat") {
		t.Error("a chat-only route did not match a chat request whose model glob matched")
	}
}

func TestSelectRouteReturnsNilWithoutADefault(t *testing.T) {
	chat := &route{name: "chat", models: []string{"llama-*"}, endpoints: map[string]bool{"chat": true}}
	rt := &router{routes: []*route{chat}}
	if got := rt.selectRoute("mistral-7b", "chat"); got != nil {
		t.Errorf("selectRoute matched %q with no default configured", got.name)
	}
}

// newRoutingHarness builds a proxy from a config the test fully controls,
// without a single Upstream, so it can exercise the multi-upstream routes list.
// It does not call Validate, so tests may build states (such as no default) that
// Validate would refuse, to prove the runtime handles them.
func newRoutingHarness(t *testing.T, tune func(*config.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.ContentMode = evidence.ModeHash
	if tune != nil {
		tune(&cfg)
	}
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv, err := New(cfg, store, discardLogger())
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	ps := httptest.NewServer(srv.Handler())
	t.Cleanup(ps.Close)
	return &harness{t: t, proxy: ps, dataDir: dir, store: store}
}

func TestChatAndEmbeddingsRouteToDistinctUpstreams(t *testing.T) {
	chatUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chat-1","model":"llama-A","choices":[{"index":0,`+
			`"message":{"content":"answer from A"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer chatUp.Close()
	embedUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"embed-1","model":"bge-B","data":[{"embedding":[0.1,0.2,0.3]}],`+
			`"usage":{"prompt_tokens":2,"completion_tokens":0,"total_tokens":2}}`)
	}))
	defer embedUp.Close()

	h := newRoutingHarness(t, func(c *config.Config) {
		c.Upstreams = []config.UpstreamRoute{
			{Name: "chat", URL: chatUp.URL, Endpoints: []string{"chat"}, Models: []string{"*"}, Default: true},
			{Name: "embed", URL: embedUp.URL, Endpoints: []string{"embedding"}, Models: []string{"*"}},
		}
	})

	h.postAndDrain("/v1/chat/completions", `{"model":"llama-A","messages":[{"role":"user","content":"hi"}]}`, nil)
	h.postAndDrain("/v1/embeddings", `{"model":"bge-B","input":["one","two"]}`, nil)

	byEndpoint := map[string]evidence.Event{}
	for _, e := range h.events() {
		byEndpoint[e.Endpoint] = e
	}
	if len(byEndpoint) != 2 {
		t.Fatalf("recorded endpoints = %v, want chat and embeddings", byEndpoint)
	}

	chat := byEndpoint["/v1/chat/completions"]
	if chat.Upstream != chatUp.URL {
		t.Errorf("chat record Upstream = %q, want the chat upstream %q", chat.Upstream, chatUp.URL)
	}
	if chat.ModelServed != "llama-A" {
		t.Errorf("chat ModelServed = %q, want llama-A from the chat upstream", chat.ModelServed)
	}

	embed := byEndpoint["/v1/embeddings"]
	if embed.Upstream != embedUp.URL {
		t.Errorf("embeddings record Upstream = %q, want the embeddings upstream %q", embed.Upstream, embedUp.URL)
	}
	if embed.ModelServed != "bge-B" {
		t.Errorf("embeddings ModelServed = %q, want bge-B from the embeddings upstream", embed.ModelServed)
	}
	if !strings.Contains(embed.Note, "embedding vectors") {
		t.Errorf("embeddings Note = %q, want the vector count", embed.Note)
	}
}

// When no route matches and no default is configured (a state Validate normally
// refuses), the unroutable request is answered 502 and recorded as evidence,
// exactly like any other upstream failure.
func TestNoRouteAndNoDefaultRecords502(t *testing.T) {
	up := httptest.NewServer(mockHandler())
	defer up.Close()

	h := newRoutingHarness(t, func(c *config.Config) {
		c.Upstreams = []config.UpstreamRoute{
			{Name: "chat", URL: up.URL, Endpoints: []string{"chat"}, Models: []string{"llama-*"}},
		}
	})

	resp := h.post("/v1/embeddings", `{"model":"bge-m3","input":["x"]}`, nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an unroutable request", resp.StatusCode)
	}

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want the unroutable attempt recorded", len(events))
	}
	e := events[0]
	if e.Status != http.StatusBadGateway {
		t.Errorf("Status = %d, want 502", e.Status)
	}
	if e.Error == "" {
		t.Error("Error is empty; an unroutable request is still evidence")
	}
	if e.ModelRequested != "bge-m3" {
		t.Errorf("ModelRequested = %q, want the model that had no route", e.ModelRequested)
	}
	if e.Upstream != "" {
		t.Errorf("Upstream = %q, want empty when nothing served the request", e.Upstream)
	}
}

// A request whose body is larger than the peek cap still routes correctly when
// the model sits at the front, and the whole body still reaches the upstream.
func TestLargeRequestBodyRoutesWhenModelIsEarly(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c","model":"m","choices":[{"index":0,"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	})
	h := newHarness(t, upstream, nil)

	filler := strings.Repeat("x", modelPeekCap+64<<10)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + filler + `"}]}`
	h.postAndDrain("/v1/chat/completions", body, nil)

	e := h.events()[0]
	if e.ModelRequested != "gpt-4" {
		t.Errorf("ModelRequested = %q; a model at the front of a large body must still route", e.ModelRequested)
	}
	if e.Content.Input.Truncated {
		t.Error("record marked truncated even though the model was found within the cap")
	}
	if e.Content.Input.Bytes != len(body) {
		t.Errorf("recorded input Bytes = %d, want the full %d: the peek dropped bytes", e.Content.Input.Bytes, len(body))
	}
}

// Streaming must still reach the client incrementally after a request body that
// exceeded the peek cap, or the bounded peek would have reintroduced buffering.
func TestStreamingSurvivesABodyLargerThanThePeekCap(t *testing.T) {
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
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

	filler := strings.Repeat("x", modelPeekCap+64<<10)
	body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"` + filler + `"}]}`
	resp := h.post("/v1/chat/completions", body, nil)
	defer resp.Body.Close()

	first := make([]byte, 64)
	done := make(chan int, 1)
	go func() {
		n, _ := resp.Body.Read(first)
		done <- n
	}()

	select {
	case n := <-done:
		if n == 0 || !bytes.Contains(first[:n], []byte("first")) {
			close(release)
			t.Fatalf("first flush not relayed after a large-body peek: %q", first[:n])
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("no bytes reached the client before the upstream finished: the peek broke streaming")
	}
	close(release)
	io.Copy(io.Discard, resp.Body)
}

// When the model lies beyond the peek cap, routing cannot see it, so the record
// is marked truncated. The larger parse prefix still recovers the model, so the
// record itself is complete: the peek degrades routing, never the evidence.
func TestModelBeyondPeekCapIsMarkedTruncated(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) { c.ContentMode = evidence.ModeStore })

	filler := strings.Repeat("x", modelPeekCap+64<<10)
	body := `{"messages":[{"role":"user","content":"` + filler + `"}],"model":"buried-model"}`
	h.postAndDrain("/v1/chat/completions", body, nil)

	e := h.events()[0]
	if !e.Content.Input.Truncated {
		t.Error("record not marked truncated when the model lay beyond the peek cap")
	}
	if e.ModelRequested != "buried-model" {
		t.Errorf("ModelRequested = %q; the larger parse prefix should still recover the model", e.ModelRequested)
	}
}
