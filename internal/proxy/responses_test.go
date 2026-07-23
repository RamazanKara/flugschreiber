package proxy

import (
	"io"
	"net/http"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// A non-streamed Responses interaction is recorded as one inference event whose
// UpstreamPreviousID carries the request's previous_response_id, the Responses
// API's own linkage between turns.
func TestResponsesInteractionRecordsUpstreamPreviousID(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"resp_new","model":"gpt-4o","output":[{"type":"message",`+
			`"content":[{"type":"output_text","text":"hello back"}]}],`+
			`"usage":{"input_tokens":4,"output_tokens":2}}`)
	})
	h := newHarness(t, upstream, func(c *config.Config) { c.ContentMode = evidence.ModeStore })

	h.postAndDrain("/v1/responses",
		`{"model":"gpt-4o","previous_response_id":"resp_prev_42","input":"continue"}`, nil)

	e := h.events()[0]
	if e.EventType != evidence.EventInference {
		t.Fatalf("EventType = %q, want a recorded inference", e.EventType)
	}
	if e.Endpoint != "/v1/responses" {
		t.Errorf("Endpoint = %q, want /v1/responses", e.Endpoint)
	}
	if e.UpstreamPreviousID != "resp_prev_42" {
		t.Errorf("UpstreamPreviousID = %q, want the request's previous_response_id", e.UpstreamPreviousID)
	}
	if e.UpstreamRespID != "resp_new" {
		t.Errorf("UpstreamRespID = %q, want the response id", e.UpstreamRespID)
	}
	if e.ModelServed != "gpt-4o" {
		t.Errorf("ModelServed = %q", e.ModelServed)
	}
	if e.Stream {
		t.Error("Stream = true for a JSON (non-streamed) Responses reply")
	}
}

// The streamed-versus-not detection keys off the response content type, so a
// Responses SSE reply is recorded as streamed just like chat, and the request's
// previous_response_id is still captured.
func TestStreamedResponsesIsDetectedAsStreaming(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "event: response.completed\ndata: {\"response\":{\"id\":\"resp_s\"}}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
		f.Flush()
	})
	h := newHarness(t, upstream, nil)

	h.postAndDrain("/v1/responses",
		`{"model":"gpt-4o","previous_response_id":"p","input":"hi","stream":true}`, nil)

	e := h.events()[0]
	if !e.Stream {
		t.Error("a Responses SSE reply was not recorded as streamed")
	}
	if e.UpstreamPreviousID != "p" {
		t.Errorf("UpstreamPreviousID = %q, want p", e.UpstreamPreviousID)
	}
}

// A chat request carrying a role:"tool" message records a tool result linking
// the call id to a digest of what came back. In store mode the text is kept.
func TestChatToolResultIsRecordedWithDigest(t *testing.T) {
	h := newHarness(t, mockHandler(), func(c *config.Config) { c.ContentMode = evidence.ModeStore })

	const result = "the account balance is 4711 EUR"
	body := `{"model":"m","messages":[` +
		`{"role":"user","content":"balance?"},` +
		`{"role":"tool","tool_call_id":"call_5","content":"` + result + `"}]}`
	h.postAndDrain("/v1/chat/completions", body, nil)

	e := h.events()[0]
	if len(e.ToolResults) != 1 {
		t.Fatalf("ToolResults = %+v, want exactly one", e.ToolResults)
	}
	tr := e.ToolResults[0]
	if tr.CallID != "call_5" {
		t.Errorf("CallID = %q, want call_5", tr.CallID)
	}
	if len(tr.SHA256) != 64 {
		t.Errorf("SHA256 = %q, want a digest of the result", tr.SHA256)
	}
	if tr.Bytes != len(result) {
		t.Errorf("Bytes = %d, want %d", tr.Bytes, len(result))
	}
	if tr.Content != result {
		t.Errorf("Content = %q, want the result retained in store mode", tr.Content)
	}
}

// Tool result content is as sensitive as a prompt: in the default hash mode it
// must be digested but never written to disk.
func TestToolResultTextIsNotOnDiskInHashMode(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	const secret = "patient 4711 balance is confidential"
	body := `{"model":"m","messages":[{"role":"tool","tool_call_id":"call_9","content":"` + secret + `"}]}`
	h.postAndDrain("/v1/chat/completions", body, nil)

	e := h.events()[0]
	if len(e.ToolResults) != 1 {
		t.Fatalf("ToolResults = %+v, want exactly one", e.ToolResults)
	}
	tr := e.ToolResults[0]
	if tr.CallID != "call_9" {
		t.Errorf("CallID = %q, want call_9", tr.CallID)
	}
	if tr.Content != "" {
		t.Errorf("hash mode retained the tool result text: %q", tr.Content)
	}
	if len(tr.SHA256) != 64 || tr.Bytes != len(secret) {
		t.Errorf("digest and byte count must survive hash mode: %+v", tr)
	}
	assertNotOnDisk(t, h.dataDir, secret)
}
