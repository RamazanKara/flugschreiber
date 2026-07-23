package openai

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Response is the recordable content of an inference response, whether it
// arrived as one JSON body or as a stream of SSE frames.
type Response struct {
	ID            string
	Model         string
	Text          string
	FinishReasons []string
	ToolCalls     []ToolCall
	Usage         *evidence.Usage
	Choices       int
	Vectors       int
	Dimensions    int
}

// ToolCall is a function call assembled from a response, with arguments still
// unredacted. The caller applies the content mode.
type ToolCall struct {
	ID        string
	Index     int
	Name      string
	Arguments string
}

type rawUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func (u *rawUsage) convert() *evidence.Usage {
	if u == nil {
		return nil
	}
	if u.PromptTokens == 0 && u.CompletionTokens == 0 && u.TotalTokens == 0 {
		return nil
	}
	return &evidence.Usage{
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
	}
}

type rawToolCall struct {
	Index    *int   `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type rawResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []rawToolCall   `json:"tool_calls"`
		} `json:"message"`
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Data []struct {
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
	Usage *rawUsage `json:"usage"`
}

// ParseResponse reads a non-streamed response body.
func ParseResponse(kind string, body []byte) *Response {
	resp := &Response{}
	var raw rawResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return resp
	}

	resp.ID = raw.ID
	resp.Model = raw.Model
	resp.Usage = raw.Usage.convert()
	resp.Choices = len(raw.Choices)

	if kind == EndpointEmbedding {
		resp.Vectors = len(raw.Data)
		if len(raw.Data) > 0 {
			resp.Dimensions = len(raw.Data[0].Embedding)
		}
		return resp
	}

	var texts []string
	for _, c := range raw.Choices {
		if text := flattenContent(c.Message.Content); text != "" {
			texts = append(texts, text)
		} else if c.Text != "" {
			texts = append(texts, c.Text)
		}
		if c.FinishReason != "" {
			resp.FinishReasons = append(resp.FinishReasons, c.FinishReason)
		}
		for i, tc := range c.Message.ToolCalls {
			idx := i
			if tc.Index != nil {
				idx = *tc.Index
			}
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:        tc.ID,
				Index:     idx,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}
	}
	resp.Text = strings.Join(texts, "\n")
	return resp
}

type streamChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []rawToolCall   `json:"tool_calls"`
		} `json:"delta"`
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *rawUsage `json:"usage"`
}

// ParseStream assembles a complete response from captured SSE bytes. It
// reconstructs what the client received, which is the thing an audit needs to
// know: not the frames, but the message they add up to.
//
// Frames that do not parse are skipped rather than aborting assembly, so one
// malformed chunk from an upstream does not erase the whole interaction.
func ParseStream(kind string, raw []byte) *Response {
	resp := &Response{}
	texts := map[int]*strings.Builder{}
	tools := map[int]*ToolCall{}
	finish := map[int]string{}

	for _, data := range sseData(raw) {
		if data == "[DONE]" {
			continue
		}
		var chunk streamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.ID != "" {
			resp.ID = chunk.ID
		}
		if chunk.Model != "" {
			resp.Model = chunk.Model
		}
		if u := chunk.Usage.convert(); u != nil {
			resp.Usage = u
		}
		for _, c := range chunk.Choices {
			if b, ok := texts[c.Index]; ok {
				b.WriteString(deltaText(c.Delta.Content, c.Text))
			} else {
				b := &strings.Builder{}
				b.WriteString(deltaText(c.Delta.Content, c.Text))
				texts[c.Index] = b
			}
			if c.FinishReason != "" {
				finish[c.Index] = c.FinishReason
			}
			for i, tc := range c.Delta.ToolCalls {
				idx := i
				if tc.Index != nil {
					idx = *tc.Index
				}
				cur, ok := tools[idx]
				if !ok {
					cur = &ToolCall{Index: idx}
					tools[idx] = cur
				}
				if tc.ID != "" {
					cur.ID = tc.ID
				}
				if tc.Function.Name != "" {
					cur.Name = tc.Function.Name
				}
				cur.Arguments += tc.Function.Arguments
			}
		}
	}

	resp.Choices = len(texts)
	for _, idx := range sortedKeys(texts) {
		if s := texts[idx].String(); s != "" {
			if resp.Text != "" {
				resp.Text += "\n"
			}
			resp.Text += s
		}
	}
	for _, idx := range sortedKeys(finish) {
		resp.FinishReasons = append(resp.FinishReasons, finish[idx])
	}
	for _, idx := range sortedKeys(tools) {
		resp.ToolCalls = append(resp.ToolCalls, *tools[idx])
	}
	return resp
}

func deltaText(content json.RawMessage, text string) string {
	if s := flattenContent(content); s != "" {
		return s
	}
	return text
}

// sseData extracts the payload of every `data:` field in an SSE byte stream,
// concatenating the continuation lines of multi-line fields as the spec
// requires.
func sseData(raw []byte) []string {
	var out []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.Join(cur, "\n"))
			cur = cur[:0]
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if field != "data" {
			continue
		}
		cur = append(cur, strings.TrimPrefix(value, " "))
	}
	flush()
	return out
}

func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
