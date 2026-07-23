// Package openai parses the subset of the OpenAI-compatible wire format that
// Flugschreiber records. It is deliberately tolerant: an unknown or malformed
// field costs a piece of metadata, never the record itself, because a server
// that refuses to log traffic it cannot fully parse is worse than useless as
// an audit tool.
package openai

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Endpoint kinds Flugschreiber understands.
const (
	EndpointChat       = "chat"
	EndpointCompletion = "completion"
	EndpointEmbedding  = "embedding"
	EndpointResponses  = "responses"
	EndpointOther      = "other"
)

// ClassifyPath maps a request path to an endpoint kind. Paths are matched by
// suffix so that upstreams mounted under a prefix still classify correctly.
func ClassifyPath(path string) string {
	switch {
	case strings.HasSuffix(path, "/responses"):
		return EndpointResponses
	case strings.HasSuffix(path, "/chat/completions"):
		return EndpointChat
	case strings.HasSuffix(path, "/completions"):
		return EndpointCompletion
	case strings.HasSuffix(path, "/embeddings"):
		return EndpointEmbedding
	default:
		return EndpointOther
	}
}

// Request is the recordable content of an inference request.
type Request struct {
	Model    string
	Stream   bool
	Params   *evidence.Params
	Messages []evidence.Message
	Text     string
	Items    int

	// PreviousID carries the Responses API previous_response_id.
	PreviousID string

	// ToolResults holds tool outputs the caller sent back, from chat
	// tool-role messages or Responses function_call_output items.
	ToolResults []ToolResultMessage
}

// ToolResultMessage is one tool output present in a request, before the content
// mode is applied.
type ToolResultMessage struct {
	CallID  string
	Content string
}

type rawRequest struct {
	Model            string          `json:"model"`
	Stream           *bool           `json:"stream"`
	Messages         []rawMessage    `json:"messages"`
	Prompt           json.RawMessage `json:"prompt"`
	Input            json.RawMessage `json:"input"`
	Temperature      *float64        `json:"temperature"`
	TopP             *float64        `json:"top_p"`
	MaxTokens        *int            `json:"max_tokens"`
	MaxCompletion    *int            `json:"max_completion_tokens"`
	N                *int            `json:"n"`
	Seed             *int64          `json:"seed"`
	Stop             json.RawMessage `json:"stop"`
	PresencePenalty  *float64        `json:"presence_penalty"`
	FrequencyPenalty *float64        `json:"frequency_penalty"`
	ResponseFormat   json.RawMessage `json:"response_format"`
	ToolChoice       json.RawMessage `json:"tool_choice"`
	Tools            []rawTool       `json:"tools"`
	Functions        []rawFunction   `json:"functions"`
}

type rawMessage struct {
	Role    string          `json:"role"`
	Name    string          `json:"name"`
	Content json.RawMessage `json:"content"`
}

type rawTool struct {
	Type     string      `json:"type"`
	Function rawFunction `json:"function"`
}

type rawFunction struct {
	Name string `json:"name"`
}

// ParseRequest extracts metadata and a readable rendering from a request body.
// A body that is not valid JSON yields a Request with only what could be
// recovered and no error, so the interaction is still recorded.
func ParseRequest(kind string, body []byte) *Request {
	req := &Request{}
	var raw rawRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return req
	}

	req.Model = raw.Model
	if raw.Stream != nil {
		req.Stream = *raw.Stream
	}
	req.Params = buildParams(&raw)

	switch kind {
	case EndpointChat:
		req.Messages = make([]evidence.Message, 0, len(raw.Messages))
		for _, m := range raw.Messages {
			req.Messages = append(req.Messages, evidence.Message{
				Role:    m.Role,
				Name:    m.Name,
				Content: flattenContent(m.Content),
			})
		}
		req.Items = len(req.Messages)
	case EndpointCompletion:
		parts := stringOrArray(raw.Prompt)
		req.Text = strings.Join(parts, "\n")
		req.Items = len(parts)
	case EndpointEmbedding:
		parts := stringOrArray(raw.Input)
		req.Text = strings.Join(parts, "\n")
		req.Items = len(parts)
	}
	return req
}

func buildParams(raw *rawRequest) *evidence.Params {
	p := &evidence.Params{
		Temperature:      raw.Temperature,
		TopP:             raw.TopP,
		MaxTokens:        raw.MaxTokens,
		N:                raw.N,
		Seed:             raw.Seed,
		PresencePenalty:  raw.PresencePenalty,
		FrequencyPenalty: raw.FrequencyPenalty,
		Stop:             stringOrArray(raw.Stop),
	}
	if p.MaxTokens == nil {
		p.MaxTokens = raw.MaxCompletion
	}
	if len(raw.ResponseFormat) > 0 {
		var rf struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw.ResponseFormat, &rf) == nil {
			p.ResponseFormat = rf.Type
		}
	}
	if len(raw.ToolChoice) > 0 {
		p.ToolChoice = describeToolChoice(raw.ToolChoice)
	}
	for _, t := range raw.Tools {
		if t.Function.Name != "" {
			p.ToolsOffered = append(p.ToolsOffered, t.Function.Name)
		}
	}
	for _, f := range raw.Functions {
		if f.Name != "" {
			p.ToolsOffered = append(p.ToolsOffered, f.Name)
		}
	}
	if isZeroParams(p) {
		return nil
	}
	return p
}

func isZeroParams(p *evidence.Params) bool {
	return p.Temperature == nil && p.TopP == nil && p.MaxTokens == nil &&
		p.N == nil && p.Seed == nil && p.PresencePenalty == nil &&
		p.FrequencyPenalty == nil && len(p.Stop) == 0 &&
		p.ResponseFormat == "" && p.ToolChoice == "" && len(p.ToolsOffered) == 0
}

func describeToolChoice(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Type     string      `json:"type"`
		Function rawFunction `json:"function"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Function.Name != "" {
		return obj.Type + ":" + obj.Function.Name
	}
	return obj.Type
}

// stringOrArray accepts the several shapes the OpenAI API allows for prompt,
// input and stop: a string, an array of strings, or an array of token ids.
func stringOrArray(raw json.RawMessage) []string {
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
	var tokens []int
	if json.Unmarshal(raw, &tokens) == nil {
		return []string{"[" + strconv.Itoa(len(tokens)) + " token ids]"}
	}
	var nested [][]int
	if json.Unmarshal(raw, &nested) == nil {
		out := make([]string, 0, len(nested))
		for _, t := range nested {
			out = append(out, "["+strconv.Itoa(len(t))+" token ids]")
		}
		return out
	}
	return nil
}

// flattenContent renders a message body, which may be a plain string or the
// multimodal array form. Non-text parts are noted by type rather than
// embedded, so that a stored transcript never inlines a base64 image.
func flattenContent(raw json.RawMessage) string {
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
			if p.Type == "text" || p.Text != "" {
				b.WriteString(p.Text)
				continue
			}
			b.WriteString("[" + p.Type + "]")
		}
		return b.String()
	}
	return string(raw)
}
