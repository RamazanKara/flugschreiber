package openai

import (
	"reflect"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestClassifyPath(t *testing.T) {
	cases := map[string]string{
		"/v1/chat/completions":        EndpointChat,
		"/openai/v1/chat/completions": EndpointChat,
		"/v1/completions":             EndpointCompletion,
		"/v1/embeddings":              EndpointEmbedding,
		"/v1/responses":               EndpointResponses,
		"/openai/v1/responses":        EndpointResponses,
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

func TestParseRequestResponsesStringInput(t *testing.T) {
	body := []byte(`{
		"model":"gpt-4o",
		"instructions":"Be brief.",
		"previous_response_id":"resp_100",
		"temperature":0.5,
		"max_output_tokens":256,
		"tools":[{"type":"function","name":"get_weather"}],
		"input":"What is the weather?"
	}`)

	req := ParseRequest(EndpointResponses, body)
	if req.Model != "gpt-4o" {
		t.Errorf("Model = %q", req.Model)
	}
	if req.PreviousID != "resp_100" {
		t.Errorf("PreviousID = %q, want resp_100", req.PreviousID)
	}
	if req.Params == nil {
		t.Fatal("Params = nil")
	}
	if req.Params.Temperature == nil || *req.Params.Temperature != 0.5 {
		t.Errorf("Temperature = %v", req.Params.Temperature)
	}
	if req.Params.MaxTokens == nil || *req.Params.MaxTokens != 256 {
		t.Errorf("MaxTokens = %v, want max_output_tokens mapped through", req.Params.MaxTokens)
	}
	if got := req.Params.ToolsOffered; len(got) != 1 || got[0] != "get_weather" {
		t.Errorf("ToolsOffered = %v, want the top-level Responses tool name", got)
	}
	want := []evidence.Message{
		{Role: "system", Content: "Be brief."},
		{Role: "user", Content: "What is the weather?"},
	}
	if !reflect.DeepEqual(req.Messages, want) {
		t.Errorf("Messages = %+v, want %+v", req.Messages, want)
	}
}

func TestParseRequestResponsesItemArrayInput(t *testing.T) {
	body := []byte(`{
		"model":"gpt-4o",
		"input":[
			{"type":"message","role":"user","content":[
				{"type":"input_text","text":"What is this?"},
				{"type":"input_image","image_url":"data:image/png;base64,AAAAAAAA"}
			]},
			{"type":"function_call_output","call_id":"call_1","output":"Order 12 shipped."}
		]
	}`)

	req := ParseRequest(EndpointResponses, body)
	if len(req.Messages) != 2 {
		t.Fatalf("Messages = %+v", req.Messages)
	}
	if req.Messages[0].Role != "user" || !strings.Contains(req.Messages[0].Content, "What is this?") {
		t.Errorf("first message = %+v", req.Messages[0])
	}
	if strings.Contains(req.Messages[0].Content, "base64") || strings.Contains(req.Messages[0].Content, "AAAAAAAA") {
		t.Errorf("image data was inlined into the transcript: %q", req.Messages[0].Content)
	}
	if !strings.Contains(req.Messages[0].Content, "[input_image]") {
		t.Errorf("image part not noted by type: %q", req.Messages[0].Content)
	}
	if req.Messages[1].Role != "tool" || req.Messages[1].Content != "Order 12 shipped." {
		t.Errorf("tool message = %+v", req.Messages[1])
	}
	want := []ToolResultMessage{{CallID: "call_1", Content: "Order 12 shipped."}}
	if !reflect.DeepEqual(req.ToolResults, want) {
		t.Errorf("ToolResults = %+v, want %+v", req.ToolResults, want)
	}
}

// Tool results the caller sends back in a chat request live in role:"tool"
// messages and must be surfaced as raw results, keyed by tool_call_id.
func TestParseRequestChatExtractsToolResults(t *testing.T) {
	body := []byte(`{"model":"m","messages":[
		{"role":"user","content":"Where is order 12?"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_order","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"Order 12 shipped."}
	]}`)

	req := ParseRequest(EndpointChat, body)
	want := []ToolResultMessage{{CallID: "call_1", Content: "Order 12 shipped."}}
	if !reflect.DeepEqual(req.ToolResults, want) {
		t.Errorf("ToolResults = %+v, want %+v", req.ToolResults, want)
	}
	// The tool message stays in the transcript too, exactly as the chat wire
	// shape carries it.
	if last := req.Messages[len(req.Messages)-1]; last.Role != "tool" || last.Content != "Order 12 shipped." {
		t.Errorf("tool message not retained in transcript: %+v", last)
	}
}

func TestParseRequestResponsesToleratesGarbage(t *testing.T) {
	req := ParseRequest(EndpointResponses, []byte(`{not json at all`))
	if req == nil {
		t.Fatal("ParseRequest returned nil")
	}
	if req.Model != "" || len(req.Messages) != 0 || len(req.ToolResults) != 0 {
		t.Errorf("expected an empty request, got %+v", req)
	}
}

func TestParseResponseResponses(t *testing.T) {
	body := []byte(`{
		"id":"resp_1","object":"response","previous_response_id":"resp_0",
		"model":"gpt-4o","status":"completed",
		"output":[
			{"type":"reasoning","id":"rs_1","summary":[]},
			{"type":"message","id":"msg_1","role":"assistant","content":[
				{"type":"output_text","text":"Order 12 shipped.","annotations":[]}]},
			{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":"{\"id\":12}"}
		],
		"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}
	}`)

	resp := ParseResponse(EndpointResponses, body)
	if resp.ID != "resp_1" || resp.PreviousID != "resp_0" || resp.Model != "gpt-4o" {
		t.Errorf("ID/PreviousID/Model = %q/%q/%q", resp.ID, resp.PreviousID, resp.Model)
	}
	if resp.Text != "Order 12 shipped." {
		t.Errorf("Text = %q", resp.Text)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v", resp.ToolCalls)
	}
	if tc := resp.ToolCalls[0]; tc.ID != "call_9" || tc.Name != "lookup_order" || tc.Arguments != `{"id":12}` {
		t.Errorf("ToolCall = %+v", tc)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 11 || resp.Usage.CompletionTokens != 4 || resp.Usage.TotalTokens != 15 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "completed" {
		t.Errorf("FinishReasons = %v, want [completed]", resp.FinishReasons)
	}
}

func TestParseResponseResponsesIncompleteReason(t *testing.T) {
	body := []byte(`{
		"id":"resp_2","status":"incomplete",
		"incomplete_details":{"reason":"max_output_tokens"},
		"output":[{"type":"message","content":[{"type":"output_text","text":"partial"}]}]
	}`)

	resp := ParseResponse(EndpointResponses, body)
	if resp.Text != "partial" {
		t.Errorf("Text = %q", resp.Text)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "max_output_tokens" {
		t.Errorf("FinishReasons = %v, want the incomplete reason", resp.FinishReasons)
	}
}

func TestParseResponseResponsesToleratesGarbage(t *testing.T) {
	resp := ParseResponse(EndpointResponses, []byte(`{broken`))
	if resp == nil {
		t.Fatal("ParseResponse returned nil")
	}
	if resp.Text != "" || len(resp.ToolCalls) != 0 {
		t.Errorf("expected an empty response, got %+v", resp)
	}
}

func TestParseStreamResponsesViaCompletedEvent(t *testing.T) {
	final := `{"id":"resp_1","previous_response_id":"resp_0","model":"gpt-4o","status":"completed",` +
		`"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Order 12 shipped."}]},` +
		`{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":"{\"id\":12}"}],` +
		`"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}}`
	stream := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_1","model":"gpt-4o"}}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"Order "}`,
		"",
		"event: response.completed",
		`data: {"type":"response.completed","response":` + final + `}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointResponses, []byte(stream))
	if resp.Text != "Order 12 shipped." {
		t.Errorf("Text = %q, want the completed event's assembled text", resp.Text)
	}
	if resp.ID != "resp_1" || resp.PreviousID != "resp_0" || resp.Model != "gpt-4o" {
		t.Errorf("ID/PreviousID/Model = %q/%q/%q", resp.ID, resp.PreviousID, resp.Model)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Arguments != `{"id":12}` {
		t.Errorf("ToolCalls = %+v", resp.ToolCalls)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 15 {
		t.Errorf("Usage = %+v", resp.Usage)
	}
	if len(resp.FinishReasons) != 1 || resp.FinishReasons[0] != "completed" {
		t.Errorf("FinishReasons = %v", resp.FinishReasons)
	}
}

func TestParseStreamResponsesViaDeltas(t *testing.T) {
	stream := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_3","model":"gpt-4o","previous_response_id":"resp_2"}}`,
		"",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"Order "}`,
		"",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"12 "}`,
		"",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"shipped."}`,
		"",
		`data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":""}}`,
		"",
		`data: {"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"id\":"}`,
		"",
		`data: {"type":"response.function_call_arguments.delta","output_index":1,"delta":"12}"}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointResponses, []byte(stream))
	if resp.Text != "Order 12 shipped." {
		t.Errorf("Text = %q, want the reassembled deltas", resp.Text)
	}
	if resp.ID != "resp_3" || resp.Model != "gpt-4o" || resp.PreviousID != "resp_2" {
		t.Errorf("ID/Model/PreviousID = %q/%q/%q", resp.ID, resp.Model, resp.PreviousID)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v", resp.ToolCalls)
	}
	if tc := resp.ToolCalls[0]; tc.ID != "call_9" || tc.Name != "lookup_order" || tc.Arguments != `{"id":12}` {
		t.Errorf("ToolCall = %+v, want the concatenated arguments", tc)
	}
}

// A single unparseable frame must not discard the surviving deltas.
func TestParseStreamResponsesSkipsMalformedFrames(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"before "}`,
		"",
		`data: {"type":"response.output_text.delta` + "\n" + `{broken`,
		"",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"after"}`,
		"",
		"data: [DONE]",
		"",
	}, "\n")

	resp := ParseStream(EndpointResponses, []byte(stream))
	if resp.Text != "before after" {
		t.Errorf("Text = %q, want the surviving frames assembled", resp.Text)
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
