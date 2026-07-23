// Package evidence is the append-only, hash-chained log at the centre of
// Flugschreiber, together with its verifier, its signed checkpoints, its
// retention enforcement and its archival hook.
//
// It imports nothing from the rest of the project, deliberately: the package
// that defines what the evidence is must stay readable and auditable on its
// own. See ARCHITECTURE.md.
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
	EventIncident          = "incident"
)

// Incident severities, recordable through the oversight events endpoint. They
// support Article 73 serious-incident reporting: an operator records what a
// human concluded about an interaction, never what a model did.
const (
	SeveritySuspected = "suspected"
	SeveritySerious   = "serious"
	SeverityResolved  = "resolved"
)

// ValidSeverity reports whether s is a recognised incident severity.
func ValidSeverity(s string) bool {
	switch s {
	case SeveritySuspected, SeveritySerious, SeverityResolved:
		return true
	}
	return false
}

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

	// UpstreamPreviousID carries the OpenAI Responses API previous_response_id,
	// which is that API's own linkage between turns of one conversation.
	UpstreamPreviousID string `json:"upstream_previous_id,omitempty"`

	Params *Params `json:"params,omitempty"`
	Usage  *Usage  `json:"usage,omitempty"`

	Stream        bool         `json:"stream"`
	FinishReasons []string     `json:"finish_reasons,omitempty"`
	ToolCalls     []ToolCall   `json:"tool_calls,omitempty"`
	ToolResults   []ToolResult `json:"tool_results,omitempty"`

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

	// Decision is the structured outcome of a human_intervention. Article 14
	// oversight is far easier to evidence when the outcome is a value that can
	// be counted than when it is buried in free text.
	Decision string `json:"decision,omitempty"`

	// RefRequestID points at the inference record this event concerns, for
	// events that comment on an interaction rather than being one.
	RefRequestID string `json:"ref_request_id,omitempty"`

	// Severity classifies an incident record. Empty on every other event type.
	Severity string `json:"severity,omitempty"`
}

// Decisions a human_intervention may record.
const (
	DecisionApprove  = "approve"
	DecisionOverride = "override"
	DecisionReject   = "reject"
	DecisionEscalate = "escalate"
	DecisionHalt     = "halt"
	DecisionAnnotate = "annotate"
)

// ValidDecision reports whether d is a recognised intervention outcome.
func ValidDecision(d string) bool {
	switch d {
	case DecisionApprove, DecisionOverride, DecisionReject,
		DecisionEscalate, DecisionHalt, DecisionAnnotate:
		return true
	}
	return false
}

// RecordableEventType reports whether an event type may be submitted through
// the events API. Inference records are deliberately excluded: they are written
// only by the proxy from observed traffic, and letting a caller post one would
// mean anyone holding the events token could fabricate a model interaction.
func RecordableEventType(t string) bool {
	switch t {
	case EventHumanIntervention, EventSessionStart, EventSessionEnd,
		EventConfigChange, EventToolCall, EventToolResult, EventSystemEvent,
		EventIncident:
		return true
	}
	return false
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

// ToolResult records what a tool returned, carried on the inference event
// rather than as a separate chain event: chat clients resend the whole
// conversation each turn, so a per-message event would duplicate one result
// into the chain once per subsequent turn. Content follows the active content
// mode; the digest and byte count are always over the result as it was seen.
type ToolResult struct {
	CallID  string `json:"call_id,omitempty"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Content string `json:"content,omitempty"`
}

// Content is the record of what was sent and received, at the fidelity the
// configured content mode allows.
type Content struct {
	Mode       string             `json:"mode"`
	Input      *Payload           `json:"input,omitempty"`
	Output     *Payload           `json:"output,omitempty"`
	Encryption *ContentEncryption `json:"encryption,omitempty"`
}

// ContentEncryption marks a record whose stored text is encrypted at rest, so
// that an Article 17 erasure can destroy the wrapping key and render the
// content unrecoverable without touching the chain. When Erased is true the
// key is gone; the digests over the original wire bytes remain as claims that
// can no longer be re-proven, which the documentation states plainly.
type ContentEncryption struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Erased    bool   `json:"erased,omitempty"`
	ErasedAt  string `json:"erased_at,omitempty"`
}

// Payload describes one side of an interaction. SHA256 and Bytes are always
// computed over the raw bytes as they crossed the wire, in every content mode,
// so that a stored transcript can be checked against the hash of the original.
type Payload struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`

	Messages []Message `json:"messages,omitempty"`
	Text     string    `json:"text,omitempty"`

	// Ciphertext holds base64(nonce || AES-GCM ciphertext) when content
	// encryption is on. Text and Messages are then empty; erasing the wrapping
	// key leaves this present but permanently undecryptable.
	Ciphertext string `json:"ciphertext,omitempty"`

	Truncated  bool           `json:"truncated,omitempty"`
	Redactions map[string]int `json:"redactions,omitempty"`
}

// Message is one chat message, retained only in store and redact modes.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}
