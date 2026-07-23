package openai

import (
	"strings"
	"testing"
)

func TestClassifyPath(t *testing.T) {
	cases := map[string]string{
		"/v1/chat/completions":        EndpointChat,
		"/openai/v1/chat/completions": EndpointChat,
		"/v1/completions":             EndpointCompletion,
		"/v1/embeddings":              EndpointEmbedding,
		"/v1/models":                  EndpointOther,
		"/healthz":                    EndpointOther,
	}
	for path, want := range cases {
		if got := ClassifyPath(path); got != want {
			t.Errorf("ClassifyPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestParseRequestChat(t *testing.T) {
	body := []byte(`{
		"model": "llama-3.1-8b",
		"stream": true,
		"temperature": 0.7,
		"max_tokens": 512,
		"stop": ["\n\n"],
		"tools": [{"type":"function","function":{"name":"lookup_order"}}],
		"tool_choice": {"type":"function","function":{"name":"lookup_order"}},
		"messages": [
			{"role":"system","content":"Be brief."},
			{"role":"user","content":"Where is order 12?"}
		]
	}`)

	req := ParseRequest(EndpointChat, body)
	if req.Model != "llama-3.1-8b" {
		t.Errorf("Model = %q", req.Model)
	}
	if !req.Stream {
		t.Error("Stream = false, want true")
	}
	if len(req.Messages) != 2 || req.Messages[1].Content != "Where is order 12?" {
		t.Errorf("Messages = %+v", req.Messages)
	}
	if req.Params == nil {
		t.Fatal("Params = nil")
	}
	if *req.Params.Temperature != 0.7 || *req.Params.MaxTokens != 512 {
		t.Errorf("Params = %+v", req.Params)
	}
	if got := req.Params.ToolsOffered; len(got) != 1 || got[0] != "lookup_order" {
		t.Errorf("ToolsOffered = %v", got)
	}
	if req.Params.ToolChoice != "function:lookup_order" {
		t.Errorf("ToolChoice = %q", req.Params.ToolChoice)
	}
}

// Multimodal messages must not inline image payloads into a stored transcript.
func TestParseRequestFlattensMultimodalWithoutInliningBinary(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":[
		{"type":"text","text":"What is this?"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAAAAAA"}}
	]}]}`)

	req := ParseRequest(EndpointChat, body)
	got := req.Messages[0].Content
	if !strings.Contains(got, "What is this?") {
		t.Errorf("text part lost: %q", got)
	}
	if strings.Contains(got, "base64") || strings.Contains(got, "AAAAAAAA") {
		t.Errorf("image data was inlined into the transcript: %q", got)
	}
	if !strings.Contains(got, "[image_url]") {
		t.Errorf("image part not noted: %q", got)
	}
}

// A body the proxy cannot parse must still yield a usable record rather than
// an error, because refusing to log unparseable traffic defeats the purpose.
func TestParseRequestToleratesGarbage(t *testing.T) {
	req := ParseRequest(EndpointChat, []byte(`{not json at all`))
	if req == nil {
		t.Fatal("ParseRequest returned nil")
	}
	if req.Model != "" || req.Params != nil {
		t.Errorf("expected an empty request, got %+v", req)
	}
}

func TestParseResponseChat(t *testing.T) {
	body := []byte(`{
		"id":"chatcmpl-1","model":"llama-3.1-8b",
		"choices":[{"index":0,"message":{"role":"assistant","content":"Order 12 shipped."},"finish_reason":"stop"}],
		"usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}
	}`)

	resp := ParseResponse(EndpointChat, body)
	if resp.ID != "chatcmpl-1" || resp.Model != "llama-3.1-8b" {
		t.Errorf("ID/Model = %q/%q", resp.ID, resp.Model)
	}
	if resp.Text != "Order 12 shipped." {
		t.Errorf("Text = %q", resp.Text)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "stop" {
		t.Errorf("FinishReasons = %v", resp.FinishReasons)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 15 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
}

func TestParseResponseToolCalls(t *testing.T) {
	body := []byte(`{
		"id":"chatcmpl-2","model":"m",
		"choices":[{"index":0,"message":{"role":"assistant","content":null,
			"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_order","arguments":"{\"id\":12}"}}]},
			"finish_reason":"tool_calls"}]
	}`)

	resp := ParseResponse(EndpointChat, body)
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v", resp.ToolCalls)
	}
	tc := resp.ToolCalls[0]
	if tc.Name != "lookup_order" || tc.Arguments != `{"id":12}` || tc.ID != "call_1" {
		t.Errorf("ToolCall = %+v", tc)
	}
}

func TestParseStreamAssemblesCompleteMessage(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"c1","model":"llama-3.1-8b","choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		"",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Order "}}]}`,
		"",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"12 "}}]}`,
		"",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"shipped."},"finish_reason":null}]}`,
		"",
		`data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		"",
		`data: {"id":"c1","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointChat, []byte(stream))
	if resp.Text != "Order 12 shipped." {
		t.Errorf("Text = %q, want the reassembled message", resp.Text)
	}
	if resp.ID != "c1" || resp.Model != "llama-3.1-8b" {
		t.Errorf("ID/Model = %q/%q", resp.ID, resp.Model)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "stop" {
		t.Errorf("FinishReasons = %v", resp.FinishReasons)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 15 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
}

// Tool call arguments arrive split across frames and must be concatenated in
// order, or the recorded arguments are worse than useless.
func TestParseStreamAssemblesSplitToolArguments(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"lookup_order","arguments":"{\"or"}}]}}]}`,
		"",
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"der\":"}}]}}]}`,
		"",
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"12}"}}]}}]}`,
		"",
		`data: {"id":"c2","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointChat, []byte(stream))
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v", resp.ToolCalls)
	}
	tc := resp.ToolCalls[0]
	if tc.Arguments != `{"order":12}` {
		t.Errorf("Arguments = %q, want the concatenated JSON", tc.Arguments)
	}
	if tc.Name != "lookup_order" || tc.ID != "call_9" {
		t.Errorf("ToolCall = %+v", tc)
	}
}

// One unparseable frame in the middle of a stream must not discard the frames
// around it.
func TestParseStreamSkipsMalformedFrames(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"before "}}]}`,
		"",
		`data: {"broken`,
		"",
		`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"after"}}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointChat, []byte(stream))
	if resp.Text != "before after" {
		t.Errorf("Text = %q, want the surviving frames to be assembled", resp.Text)
	}
}

func TestParseStreamHandlesCRLFAndComments(t *testing.T) {
	stream := ": keep-alive\r\n\r\n" +
		"data: {\"id\":\"c4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\r\n\r\n" +
		"data: [DONE]\r\n\r\n"

	resp := ParseStream(EndpointChat, []byte(stream))
	if resp.Text != "ok" {
		t.Errorf("Text = %q", resp.Text)
	}
}

func TestParseStreamMultipleChoicesJoinInIndexOrder(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"id":"c5","choices":[{"index":1,"delta":{"content":"second"}}]}`,
		"",
		`data: {"id":"c5","choices":[{"index":0,"delta":{"content":"first"}}]}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointChat, []byte(stream))
	if resp.Text != "first\nsecond" {
		t.Errorf("Text = %q, want choices joined in index order", resp.Text)
	}
}

func TestParseResponseEmbeddings(t *testing.T) {
	body := []byte(`{"object":"list","model":"bge-m3","data":[
		{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]},
		{"object":"embedding","index":1,"embedding":[0.4,0.5,0.6]}],
		"usage":{"prompt_tokens":8,"total_tokens":8}}`)

	resp := ParseResponse(EndpointEmbedding, body)
	if resp.Vectors != 2 || resp.Dimensions != 3 {
		t.Errorf("Vectors/Dimensions = %d/%d, want 2/3", resp.Vectors, resp.Dimensions)
	}
	if resp.Text != "" {
		t.Errorf("Text = %q, embeddings should not produce transcript text", resp.Text)
	}
}

func TestStringOrArrayShapes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{`"one prompt"`, 1},
		{`["a","b","c"]`, 3},
		{`[1,2,3,4]`, 1},
		{`[[1,2],[3,4]]`, 2},
	}
	for _, tc := range cases {
		if got := stringOrArray([]byte(tc.in)); len(got) != tc.want {
			t.Errorf("stringOrArray(%s) returned %d items, want %d", tc.in, len(got), tc.want)
		}
	}
}
