package mockupstream

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
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
