package evidence

// SchemaVersion is the version of the Event structure written to disk. It is
// bumped only for breaking changes; see docs/SCHEMA.md for the compatibility
// policy.
const SchemaVersion = 1

// Event types recorded by the proxy and the API.
const (
	EventInference         = "inference"
	EventToolCall          = "tool_call"
	EventToolResult        = "tool_result"
	EventHumanIntervention = "human_intervention"
	EventSessionStart      = "session_start"
	EventSessionEnd        = "session_end"
	EventConfigChange      = "config_change"
	EventSystemEvent       = "system_event"
)

// Content capture modes.
const (
	ModeStore  = "store"
	ModeHash   = "hash"
	ModeRedact = "redact"
)

// Event is the payload of one evidence record. Fields that the proxy could not
// observe are omitted rather than zero-filled, so that a reader can tell "not
// present" from "present and zero".
type Event struct {
	SchemaVersion int    `json:"schema_version"`
	EventType     string `json:"event_type"`
	RequestID     string `json:"request_id"`
	SessionID     string `json:"session_id,omitempty"`
	ClientHash    string `json:"client_hash,omitempty"`

	Endpoint string `json:"endpoint,omitempty"`
	Method   string `json:"method,omitempty"`
	Upstream string `json:"upstream,omitempty"`

	ModelRequested string `json:"model_requested,omitempty"`
	ModelServed    string `json:"model_served,omitempty"`
	UpstreamRespID string `json:"upstream_response_id,omitempty"`

	Params *Params `json:"params,omitempty"`
	Usage  *Usage  `json:"usage,omitempty"`

	Stream        bool       `json:"stream"`
	FinishReasons []string   `json:"finish_reasons,omitempty"`
	ToolCalls     []ToolCall `json:"tool_calls,omitempty"`

	Status    int     `json:"status,omitempty"`
	Error     string  `json:"error,omitempty"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	TTFBMS    float64 `json:"ttfb_ms,omitempty"`

	Content *Content `json:"content,omitempty"`

	// Note carries free-form context for system_event and
	// human_intervention records.
	Note string `json:"note,omitempty"`

	// Actor identifies who performed a human_intervention. It is supplied by
	// the caller of the intervention endpoint and is not verified by
	// Flugschreiber.
	Actor string `json:"actor,omitempty"`
}

// Params records the generation parameters that were requested. Only
// parameters actually present in the request are recorded.
type Params struct {
	Temperature      *float64 `json:"temperature,omitempty"`
	TopP             *float64 `json:"top_p,omitempty"`
	MaxTokens        *int     `json:"max_tokens,omitempty"`
	N                *int     `json:"n,omitempty"`
	Seed             *int64   `json:"seed,omitempty"`
	Stop             []string `json:"stop,omitempty"`
	PresencePenalty  *float64 `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64 `json:"frequency_penalty,omitempty"`
	ResponseFormat   string   `json:"response_format,omitempty"`
	ToolChoice       string   `json:"tool_choice,omitempty"`
	ToolsOffered     []string `json:"tools_offered,omitempty"`
}

// Usage holds token accounting as reported by the upstream. Absent when the
// upstream does not report it (streaming without stream_options.include_usage).
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ToolCall records a function call the model asked for. Arguments follow the
// active content mode: they are hashed unless the mode stores content.
type ToolCall struct {
	ID            string `json:"id,omitempty"`
	Index         int    `json:"index"`
	Name          string `json:"name"`
	Arguments     string `json:"arguments,omitempty"`
	ArgumentsHash string `json:"arguments_sha256,omitempty"`
}

// Content is the record of what was sent and received, at the fidelity the
// configured content mode allows.
type Content struct {
	Mode   string   `json:"mode"`
	Input  *Payload `json:"input,omitempty"`
	Output *Payload `json:"output,omitempty"`
}

// Payload describes one side of an interaction. SHA256 and Bytes are always
// computed over the raw bytes as they crossed the wire, in every content mode,
// so that a stored transcript can be checked against the hash of the original.
type Payload struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`

	Messages []Message `json:"messages,omitempty"`
	Text     string    `json:"text,omitempty"`

	Truncated  bool           `json:"truncated,omitempty"`
	Redactions map[string]int `json:"redactions,omitempty"`
}

// Message is one chat message, retained only in store and redact modes.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}
