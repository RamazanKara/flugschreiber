package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// An interaction still streaming when the proxy stops used to leave no record,
// no error, no metric and no log line: it happened, the client saw most of an
// answer, and the evidence said the traffic never existed. One replica is the
// supported topology, so every image bump passes through this window.
func TestInteractionsStillStreamingAtShutdownAreRecorded(t *testing.T) {
	started := make(chan struct{})
	hold := make(chan struct{})
	// Released however this test ends. Without it a failed assertion leaves the
	// upstream handler and the client goroutine blocked, and the package hangs
	// until the go test timeout instead of reporting the failure.
	var once sync.Once
	release := func() { once.Do(func() { close(hold) }) }
	defer release()

	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-hold // never completes, like a long generation at shutdown
	})

	h := newHarness(t, upstream, func(c *config.Config) { c.ContentMode = evidence.ModeHash })

	go func() {
		resp, err := http.Post(h.proxy.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			return
		}
		buf := make([]byte, 32)
		_, _ = resp.Body.Read(buf) // take the first frame, then stop reading
		<-hold
		resp.Body.Close()
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream never started streaming")
	}

	// What shutdown does after the grace period expires.
	n := h.srv.AbandonInFlight()
	release()
	if n != 1 {
		t.Fatalf("AbandonInFlight recorded %d interactions, want 1", n)
	}

	if err := h.store.Close(); err != nil {
		t.Fatal(err)
	}
	var got []evidence.Event
	if err := evidence.Walk(h.dataDir, func(e evidence.Entry) error {
		got = append(got, e.Event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("recorded %d events, want the abandoned interaction", len(got))
	}
	ev := got[0]
	if ev.Error == "" {
		t.Error("the record does not say why it is partial")
	}
	if ev.Content == nil || ev.Content.Output == nil || !ev.Content.Output.Truncated {
		t.Error("the record presents a partial capture as a complete one")
	}
	if ev.RequestID == "" {
		t.Error("the record carries no request id, so it cannot be tied to anything")
	}
	_ = io.Discard
}

// A body over the parse cap used to lose model_requested entirely, although the
// router had already read the model out of the same bytes.
func TestAnOversizedBodyKeepsTheModelItWasRoutedOn(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	// A prompt comfortably past the bounded parse prefix.
	big := strings.Repeat("x", 9<<20)
	body := fmt.Sprintf(`{"model":"llama-3.1-8b","messages":[{"role":"user","content":%q}]}`, big)
	h.postAndDrain("/v1/chat/completions", body, nil)

	events := h.events()
	if len(events) == 0 {
		t.Fatal("nothing was recorded")
	}
	ev := events[len(events)-1]
	if ev.ModelRequested != "llama-3.1-8b" {
		t.Errorf("model_requested = %q, want the model the request was routed on; a record less accurate than the routing decision taken from the same bytes",
			ev.ModelRequested)
	}
}

var _ = httptest.NewServer
