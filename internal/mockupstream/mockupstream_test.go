package mockupstream

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/openai"
)

func post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	srv := httptest.NewServer(Handler(Options{}))
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// Mock output ends up in evidence files and, from there, in generated
// documents. Text that could be mistaken for a model's output inside a
// compliance artifact is a liability, so every reply announces itself.
func TestEveryReplyAnnouncesItIsAMock(t *testing.T) {
	status, body := post(t, "/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)
	if status != 200 {
		t.Fatalf("status = %d: %s", status, body)
	}
	if !strings.Contains(body, "No model was involved") {
		t.Errorf("mock reply does not identify itself: %s", body)
	}
}

func TestStreamedChatEndsWithDone(t *testing.T) {
	status, body := post(t, "/v1/chat/completions",
		`{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`)
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Errorf("stream does not terminate with [DONE]:\n%s", body)
	}
	if !strings.Contains(body, `"prompt_tokens"`) {
		t.Errorf("include_usage did not produce a usage chunk:\n%s", body)
	}
}

// Identical input must produce identical replies, because the quickstart and
// CI depend on captured evidence being reproducible.
func TestRepliesAreDeterministic(t *testing.T) {
	const req = `{"model":"m","messages":[{"role":"user","content":"same"}]}`
	extract := func(raw string) string {
		var r struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(raw), &r); err != nil || len(r.Choices) == 0 {
			t.Fatalf("unexpected reply: %s", raw)
		}
		return r.Choices[0].Message.Content
	}
	_, first := post(t, "/v1/chat/completions", req)
	_, second := post(t, "/v1/chat/completions", req)
	if extract(first) != extract(second) {
		t.Error("two identical requests produced different replies")
	}
}

func TestEmbeddingsShapeAndDeterminism(t *testing.T) {
	status, body := post(t, "/v1/embeddings", `{"model":"m","input":["a","b"]}`)
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	var r struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 2 || len(r.Data[0].Embedding) == 0 {
		t.Fatalf("embeddings shape = %+v", r.Data)
	}
	_, again := post(t, "/v1/embeddings", `{"model":"m","input":["a","b"]}`)
	if body != again {
		t.Error("identical embedding requests differ")
	}
}

// The mock's Responses body must parse back through the real parser, so the
// two agree on the wire shape and the demo needs no live server.
func TestResponsesNonStreamedRoundTrips(t *testing.T) {
	status, body := post(t, "/v1/responses",
		`{"model":"m","input":"hello"}`)
	if status != 200 {
		t.Fatalf("status = %d: %s", status, body)
	}
	resp := openai.ParseResponse(openai.EndpointResponses, []byte(body))
	if !strings.Contains(resp.Text, "No model was involved") {
		t.Errorf("assembled text does not self-identify as a mock: %q", resp.Text)
	}
	if resp.ID == "" || resp.Model != ModelName {
		t.Errorf("ID/Model = %q/%q", resp.ID, resp.Model)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens == 0 {
		t.Errorf("Usage = %+v, want input/output tokens", resp.Usage)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "completed" {
		t.Errorf("FinishReasons = %v, want [completed]", resp.FinishReasons)
	}
}

// The streamed body must assemble to the same response as the non-streamed one.
func TestResponsesStreamedRoundTripsToTheSameText(t *testing.T) {
	_, nonStream := post(t, "/v1/responses", `{"model":"m","input":"hello"}`)
	want := openai.ParseResponse(openai.EndpointResponses, []byte(nonStream))

	status, body := post(t, "/v1/responses",
		`{"model":"m","stream":true,"input":"hello"}`)
	if status != 200 {
		t.Fatalf("status = %d: %s", status, body)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Errorf("stream does not terminate with [DONE]:\n%s", body)
	}
	got := openai.ParseStream(openai.EndpointResponses, []byte(body))
	if got.Text != want.Text {
		t.Errorf("streamed text = %q, non-streamed = %q", got.Text, want.Text)
	}
	if got.ID != want.ID {
		t.Errorf("streamed ID = %q, non-streamed = %q", got.ID, want.ID)
	}
	if got.Usage == nil || got.Usage.TotalTokens != want.Usage.TotalTokens {
		t.Errorf("streamed Usage = %+v, want total %d", got.Usage, want.Usage.TotalTokens)
	}
}

func TestResponsesRepliesAreDeterministic(t *testing.T) {
	const req = `{"model":"m","input":"same"}`
	_, first := post(t, "/v1/responses", req)
	_, second := post(t, "/v1/responses", req)
	// created_at is a wall-clock field, so compare the assembled reply and id
	// rather than the raw bytes.
	a := openai.ParseResponse(openai.EndpointResponses, []byte(first))
	b := openai.ParseResponse(openai.EndpointResponses, []byte(second))
	if a.Text != b.Text || a.ID != b.ID {
		t.Errorf("two identical Responses requests diverged: %q/%q vs %q/%q",
			a.Text, a.ID, b.Text, b.ID)
	}
}

func TestBadJSONIsA400NotACrash(t *testing.T) {
	status, body := post(t, "/v1/chat/completions", `{not json`)
	if status != 400 {
		t.Errorf("status = %d, want 400: %s", status, body)
	}
}

func TestUnknownPathIsA404(t *testing.T) {
	status, _ := post(t, "/v1/images/generations", `{}`)
	if status != 404 {
		t.Errorf("status = %d, want 404", status)
	}
}
