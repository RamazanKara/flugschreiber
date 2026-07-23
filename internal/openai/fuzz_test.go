package openai

import (
	"reflect"
	"testing"
)

// allKinds is every endpoint kind the parsers branch on. Each fuzz target runs
// its input through all of them, so one corpus entry exercises the chat,
// completion, embedding, Responses and fall-through paths at once.
var allKinds = []string{
	EndpointChat, EndpointCompletion, EndpointEmbedding,
	EndpointResponses, EndpointOther,
}

// edgeSeeds are inputs that are hostile to any JSON parser and belong in every
// corpus: empty, the bare JSON scalars, an object and array that unmarshal but
// carry nothing, truncated JSON, and raw control bytes.
var edgeSeeds = []string{
	"",
	"{}",
	"[]",
	"null",
	"true",
	`""`,
	"{not json at all",
	`{"model":`,
	"\x00\x01\x02",
	`{"model":123}`,
	`{"model":"m","stream":"yes"}`,
}

// requestSeeds are real request-body shapes drawn from openai_test.go: chat with
// tools and a tool result, multimodal content, the Responses string and item
// forms, and the completion and embedding prompt shapes.
var requestSeeds = []string{
	`{"model":"llama-3.1-8b","stream":true,"temperature":0.7,"max_tokens":512,` +
		`"stop":["\n\n"],"tools":[{"type":"function","function":{"name":"lookup_order"}}],` +
		`"tool_choice":{"type":"function","function":{"name":"lookup_order"}},` +
		`"messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Where is order 12?"}]}`,
	`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"What is this?"},` +
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAAAAAA"}}]}]}`,
	`{"model":"m","messages":[{"role":"user","content":"Where is order 12?"},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_order","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":"Order 12 shipped."}]}`,
	`{"model":"gpt-4o","instructions":"Be brief.","previous_response_id":"resp_100",` +
		`"temperature":0.5,"max_output_tokens":256,"tools":[{"type":"function","name":"get_weather"}],` +
		`"input":"What is the weather?"}`,
	`{"model":"gpt-4o","input":[{"type":"message","role":"user","content":[` +
		`{"type":"input_text","text":"What is this?"},{"type":"input_image","image_url":"data:image/png;base64,AAAAAAAA"}]},` +
		`{"type":"function_call_output","call_id":"call_1","output":"Order 12 shipped."}]}`,
	`{"model":"m","prompt":"complete this"}`,
	`{"model":"m","prompt":["a","b","c"]}`,
	`{"model":"m","prompt":[1,2,3,4]}`,
	`{"model":"bge-m3","input":["one","two"]}`,
	`{"model":"m","seed":42,"n":2,"top_p":0.9,"presence_penalty":0.1,"frequency_penalty":-0.2,"response_format":{"type":"json_object"}}`,
}

// responseSeeds are real non-streamed response bodies: chat text, chat tool
// calls, embeddings, and the Responses body with a message, a reasoning item, a
// function call and an incomplete status.
var responseSeeds = []string{
	`{"id":"chatcmpl-1","model":"llama-3.1-8b","choices":[{"index":0,"message":{"role":"assistant","content":"Order 12 shipped."},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}}`,
	`{"id":"chatcmpl-2","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_order","arguments":"{\"id\":12}"}}]},"finish_reason":"tool_calls"}]}`,
	`{"object":"list","model":"bge-m3","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]},{"object":"embedding","index":1,"embedding":[0.4,0.5,0.6]}],"usage":{"prompt_tokens":8,"total_tokens":8}}`,
	`{"id":"resp_1","object":"response","previous_response_id":"resp_0","model":"gpt-4o","status":"completed","output":[{"type":"reasoning","id":"rs_1","summary":[]},{"type":"message","id":"msg_1","role":"assistant","content":[{"type":"output_text","text":"Order 12 shipped.","annotations":[]}]},{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":"{\"id\":12}"}],"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}}`,
	`{"id":"resp_2","status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"type":"message","content":[{"type":"output_text","text":"partial"}]}]}`,
	`{"choices":[{"index":1,"message":{"content":"b"}},{"index":0,"message":{"content":"a"}}]}`,
}

// streamSeeds are captured SSE byte streams: chat assembly, tool-argument
// fragments split across frames, a malformed frame between good ones, CRLF plus
// a comment line, multiple choices out of index order, and both Responses
// streaming shapes (the terminal completed event and the delta accumulation).
var streamSeeds = []string{
	join(
		`data: {"id":"c1","model":"llama-3.1-8b","choices":[{"index":0,"delta":{"role":"assistant"}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Order "}}]}`, "",
		`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"12 shipped."},"finish_reason":"stop"}]}`, "",
		`data: {"id":"c1","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":4,"total_tokens":15}}`, "",
		"data: [DONE]", "",
	),
	join(
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"lookup_order","arguments":"{\"or"}}]}}]}`, "",
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"der\":"}}]}}]}`, "",
		`data: {"id":"c2","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"12}"}}]}}]}`, "",
		"data: [DONE]", "",
	),
	join(
		`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"before "}}]}`, "",
		`data: {"broken`, "",
		`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"after"}}]}`, "",
		"data: [DONE]", "",
	),
	": keep-alive\r\n\r\ndata: {\"id\":\"c4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n",
	join(
		`data: {"id":"c5","choices":[{"index":1,"delta":{"content":"second"}}]}`, "",
		`data: {"id":"c5","choices":[{"index":0,"delta":{"content":"first"}}]}`, "",
		"data: [DONE]", "",
	),
	join(
		`data: {"type":"response.created","response":{"id":"resp_1","model":"gpt-4o"}}`, "",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"Order "}`, "",
		`data: {"type":"response.completed","response":{"id":"resp_1","previous_response_id":"resp_0","model":"gpt-4o","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Order 12 shipped."}]},{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":"{\"id\":12}"}],"usage":{"input_tokens":11,"output_tokens":4,"total_tokens":15}}}`, "",
		"data: [DONE]", "",
	),
	join(
		`data: {"type":"response.created","response":{"id":"resp_3","model":"gpt-4o","previous_response_id":"resp_2"}}`, "",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"Order "}`, "",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"12 shipped."}`, "",
		`data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_9","name":"lookup_order","arguments":""}}`, "",
		`data: {"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"id\":12}"}`, "",
		"data: [DONE]", "",
	),
	"data: [DONE]\n\n",
}

// join glues SSE lines with newlines, matching how the parser tests build their
// streams; a trailing empty argument yields a trailing newline.
func join(lines ...string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

// FuzzParseRequest asserts that ParseRequest never panics on any bytes, always
// returns a non-nil Request, and is deterministic: a second parse of the same
// body under the same kind yields an equal result. D12 promises a malformed body
// costs a field and never the record, so the parser must survive arbitrary input.
func FuzzParseRequest(f *testing.F) {
	for _, s := range requestSeeds {
		f.Add([]byte(s))
	}
	for _, s := range edgeSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, kind := range allKinds {
			got := ParseRequest(kind, body)
			if got == nil {
				t.Fatalf("ParseRequest(%q) returned nil", kind)
			}
			if again := ParseRequest(kind, body); !reflect.DeepEqual(got, again) {
				t.Fatalf("ParseRequest(%q) is not deterministic\n first: %+v\nsecond: %+v", kind, got, again)
			}
		}
	})
}

// FuzzParseResponse asserts the same properties for the non-streamed response
// parser across every endpoint kind.
func FuzzParseResponse(f *testing.F) {
	for _, s := range responseSeeds {
		f.Add([]byte(s))
	}
	for _, s := range edgeSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, kind := range allKinds {
			got := ParseResponse(kind, body)
			if got == nil {
				t.Fatalf("ParseResponse(%q) returned nil", kind)
			}
			if again := ParseResponse(kind, body); !reflect.DeepEqual(got, again) {
				t.Fatalf("ParseResponse(%q) is not deterministic\n first: %+v\nsecond: %+v", kind, got, again)
			}
		}
	})
}

// FuzzParseStream asserts the same properties for SSE assembly. Determinism is
// the load-bearing claim here, because assembly walks maps keyed by choice and
// output index; the parser must sort them into a stable order for every input.
func FuzzParseStream(f *testing.F) {
	for _, s := range streamSeeds {
		f.Add([]byte(s))
	}
	for _, s := range edgeSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, kind := range allKinds {
			got := ParseStream(kind, raw)
			if got == nil {
				t.Fatalf("ParseStream(%q) returned nil", kind)
			}
			if again := ParseStream(kind, raw); !reflect.DeepEqual(got, again) {
				t.Fatalf("ParseStream(%q) is not deterministic\n first: %+v\nsecond: %+v", kind, got, again)
			}
		}
	})
}
