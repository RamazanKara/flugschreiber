// Package mockupstream serves a deterministic OpenAI-compatible API. It exists
// so that the quickstart, the acceptance demo and CI all run with no model
// server, no GPU and no network access.
//
// It is not a model. It echoes a canned reply derived from the request so that
// captured evidence is meaningful and reproducible.
package mockupstream

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	"time"
)

// ModelName is what the mock reports serving.
const ModelName = "flugschreiber-mock-1"

// Options tune the mock's behaviour.
type Options struct {
	// ChunkDelay is the pause between streamed chunks. A small non-zero delay
	// makes streaming visibly incremental in the demo.
	ChunkDelay time.Duration
}

// Handler returns the mock API.
func Handler(opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		chat(w, r, opts)
	})
	mux.HandleFunc("POST /v1/completions", func(w http.ResponseWriter, r *http.Request) {
		completion(w, r, opts)
	})
	mux.HandleFunc("POST /v1/responses", func(w http.ResponseWriter, r *http.Request) {
		responses(w, r, opts)
	})
	mux.HandleFunc("POST /v1/embeddings", embeddings)
	mux.HandleFunc("GET /v1/models", models)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "unknown endpoint "+r.URL.Path)
	})
	return mux
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	} `json:"tools"`
	StreamOptions *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

func chat(w http.ResponseWriter, r *http.Request, opts Options) {
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	var prompt string
	if n := len(req.Messages); n > 0 {
		prompt = textOf(req.Messages[n-1].Content)
	}
	reply := replyTo(prompt)
	id := "chatcmpl-mock-" + digest(prompt)
	created := time.Now().Unix()
	promptTokens := estimateTokens(prompt)
	completionTokens := estimateTokens(reply)

	if !req.Stream {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":      id,
			"object":  "chat.completion",
			"created": created,
			"model":   ModelName,
			"choices": []any{map[string]any{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": reply},
				"finish_reason": "stop",
			}},
			"usage": usage(promptTokens, completionTokens),
		})
		return
	}

	flusher, ok := beginSSE(w)
	if !ok {
		return
	}

	sendChunk(w, flusher, map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": created, "model": ModelName,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
	}, opts.ChunkDelay)

	for _, word := range chunkWords(reply) {
		sendChunk(w, flusher, map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": ModelName,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": word}, "finish_reason": nil}},
		}, opts.ChunkDelay)
	}

	sendChunk(w, flusher, map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": created, "model": ModelName,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
	}, 0)

	if req.StreamOptions != nil && req.StreamOptions.IncludeUsage {
		sendChunk(w, flusher, map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": ModelName,
			"choices": []any{},
			"usage":   usage(promptTokens, completionTokens),
		}, 0)
	}

	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

type completionRequest struct {
	Model  string          `json:"model"`
	Stream bool            `json:"stream"`
	Prompt json.RawMessage `json:"prompt"`
}

func completion(w http.ResponseWriter, r *http.Request, opts Options) {
	var req completionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	prompt := textOf(req.Prompt)
	reply := replyTo(prompt)
	id := "cmpl-mock-" + digest(prompt)
	created := time.Now().Unix()

	if !req.Stream {
		writeJSON(w, http.StatusOK, map[string]any{
			"id": id, "object": "text_completion", "created": created, "model": ModelName,
			"choices": []any{map[string]any{"index": 0, "text": reply, "finish_reason": "stop"}},
			"usage":   usage(estimateTokens(prompt), estimateTokens(reply)),
		})
		return
	}

	flusher, ok := beginSSE(w)
	if !ok {
		return
	}
	for _, word := range chunkWords(reply) {
		sendChunk(w, flusher, map[string]any{
			"id": id, "object": "text_completion", "created": created, "model": ModelName,
			"choices": []any{map[string]any{"index": 0, "text": word, "finish_reason": nil}},
		}, opts.ChunkDelay)
	}
	sendChunk(w, flusher, map[string]any{
		"id": id, "object": "text_completion", "created": created, "model": ModelName,
		"choices": []any{map[string]any{"index": 0, "text": "", "finish_reason": "stop"}},
	}, 0)
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

type responsesRequest struct {
	Model      string          `json:"model"`
	Stream     bool            `json:"stream"`
	Input      json.RawMessage `json:"input"`
	PreviousID string          `json:"previous_response_id"`
}

// responses serves the OpenAI Responses API shape, streamed and not. It mirrors
// the real body closely enough that the openai parser round-trips it: an
// "output" array with a "message" item holding an "output_text" part, a "usage"
// object with input_tokens and output_tokens, and, when streamed, a terminal
// "response.completed" event embedding the whole final response.
func responses(w http.ResponseWriter, r *http.Request, opts Options) {
	var req responsesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	prompt := responsesPrompt(req.Input)
	reply := replyTo(prompt)
	id := "resp-mock-" + digest(prompt)
	created := time.Now().Unix()
	promptTokens := estimateTokens(prompt)
	completionTokens := estimateTokens(reply)

	body := func(status string) map[string]any {
		return map[string]any{
			"id":                   id,
			"object":               "response",
			"created_at":           created,
			"model":                ModelName,
			"status":               status,
			"previous_response_id": nilOrString(req.PreviousID),
			"output": []any{map[string]any{
				"type":   "message",
				"id":     "msg-" + digest(prompt),
				"role":   "assistant",
				"status": "completed",
				"content": []any{map[string]any{
					"type":        "output_text",
					"text":        reply,
					"annotations": []any{},
				}},
			}},
			"usage": responsesUsage(promptTokens, completionTokens),
		}
	}

	if !req.Stream {
		writeJSON(w, http.StatusOK, body("completed"))
		return
	}

	flusher, ok := beginSSE(w)
	if !ok {
		return
	}
	sendEvent(w, flusher, "response.created", map[string]any{
		"type": "response.created", "response": body("in_progress"),
	}, opts.ChunkDelay)
	for _, word := range chunkWords(reply) {
		sendEvent(w, flusher, "response.output_text.delta", map[string]any{
			"type":          "response.output_text.delta",
			"output_index":  0,
			"content_index": 0,
			"delta":         word,
		}, opts.ChunkDelay)
	}
	sendEvent(w, flusher, "response.completed", map[string]any{
		"type": "response.completed", "response": body("completed"),
	}, 0)
	fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func embeddings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model string          `json:"model"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	inputs := inputList(req.Input)
	const dims = 8
	data := make([]any, 0, len(inputs))
	for i, in := range inputs {
		vec := make([]float64, dims)
		seed := fnvHash(in)
		for d := range vec {
			seed = seed*6364136223846793005 + 1442695040888963407
			vec[d] = float64(int64(seed>>33)%2000-1000) / 1000
		}
		data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": vec})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
		"model":  ModelName,
		"usage":  map[string]any{"prompt_tokens": estimateTokens(strings.Join(inputs, " ")), "total_tokens": estimateTokens(strings.Join(inputs, " "))},
	})
}

func models(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data": []any{map[string]any{
			"id": ModelName, "object": "model", "owned_by": "flugschreiber",
		}},
	})
}

func beginSSE(w http.ResponseWriter) (http.Flusher, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported by this server")
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return flusher, true
}

func sendChunk(w http.ResponseWriter, f http.Flusher, payload map[string]any, delay time.Duration) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
	if delay > 0 {
		time.Sleep(delay)
	}
}

// sendEvent writes one Responses SSE frame, an "event:" line naming the type
// followed by the JSON payload. The event line exercises a real detail of the
// wire format: a recorder must ignore it and read only the data.
func sendEvent(w http.ResponseWriter, f http.Flusher, event string, payload map[string]any, delay time.Duration) {
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	f.Flush()
	if delay > 0 {
		time.Sleep(delay)
	}
}

// responsesPrompt pulls a stable prompt string out of a Responses "input",
// whether it is a bare string or an array of items. The last message item wins,
// matching how the chat handler keys its reply on the final message.
func responsesPrompt(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var items []struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &items) == nil {
		for i := len(items) - 1; i >= 0; i-- {
			if items[i].Type == "" || items[i].Type == "message" {
				return textOf(items[i].Content)
			}
		}
	}
	return ""
}

func responsesUsage(input, output int) map[string]any {
	return map[string]any{
		"input_tokens":  input,
		"output_tokens": output,
		"total_tokens":  input + output,
	}
}

// nilOrString renders an absent previous_response_id as JSON null, the way the
// real API does, rather than an empty string.
func nilOrString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// replyTo produces a stable, self-describing answer. It deliberately says what
// it is, so nobody mistakes mock output for a model's output in a report.
func replyTo(prompt string) string {
	prompt = strings.TrimSpace(strings.ReplaceAll(prompt, "\n", " "))
	if len(prompt) > 120 {
		prompt = prompt[:120] + "…"
	}
	if prompt == "" {
		return "This is the Flugschreiber mock upstream. No model was involved in producing this text."
	}
	return fmt.Sprintf(
		"This is the Flugschreiber mock upstream responding to %q. No model was involved in producing this text.",
		prompt)
}

func chunkWords(s string) []string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for i, f := range fields {
		if i == 0 {
			out = append(out, f)
			continue
		}
		out = append(out, " "+f)
	}
	return out
}

func textOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return string(raw)
}

func inputList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var ss []string
	if json.Unmarshal(raw, &ss) == nil {
		return ss
	}
	return []string{string(raw)}
}

func usage(prompt, completion int) map[string]any {
	return map[string]any{
		"prompt_tokens":     prompt,
		"completion_tokens": completion,
		"total_tokens":      prompt + completion,
	}
}

// estimateTokens is a word count, not a tokenizer. The mock reports it so the
// usage plumbing has something to carry; real upstreams report real numbers.
func estimateTokens(s string) int {
	return len(strings.Fields(s))
}

func digest(s string) string {
	return fmt.Sprintf("%08x", fnvHash(s))
}

func fnvHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": message, "type": "invalid_request_error"},
	})
}
