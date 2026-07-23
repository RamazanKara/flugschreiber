package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// Session is a reconstructed sequence of interactions and the human decisions
// taken around them.
type Session struct {
	SessionID string         `json:"session_id,omitempty"`
	Records   int            `json:"records"`
	First     string         `json:"first"`
	Last      string         `json:"last"`
	Models    []string       `json:"models,omitempty"`
	Clients   []string       `json:"clients,omitempty"`
	Entries   []SessionEntry `json:"entries"`

	// ContentAvailable reports whether any entry carries readable text. In the
	// default hash mode it is false, and a reader needs to be told that
	// plainly rather than concluding the session was empty.
	ContentAvailable bool `json:"content_available"`
}

// SessionEntry is one record rendered for a human reader.
type SessionEntry struct {
	Seq       uint64 `json:"seq"`
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	RequestID string `json:"request_id,omitempty"`

	Model     string   `json:"model,omitempty"`
	Endpoint  string   `json:"endpoint,omitempty"`
	Status    int      `json:"status,omitempty"`
	Stream    bool     `json:"stream,omitempty"`
	LatencyMS float64  `json:"latency_ms,omitempty"`
	Finish    []string `json:"finish_reasons,omitempty"`
	Error     string   `json:"error,omitempty"`

	PromptTokens     int `json:"prompt_tokens,omitempty"`
	CompletionTokens int `json:"completion_tokens,omitempty"`

	Input      []evidence.Message `json:"input,omitempty"`
	Output     string             `json:"output,omitempty"`
	InputHash  string             `json:"input_sha256,omitempty"`
	OutputHash string             `json:"output_sha256,omitempty"`

	ToolCalls []evidence.ToolCall `json:"tool_calls,omitempty"`

	Actor        string `json:"actor,omitempty"`
	Decision     string `json:"decision,omitempty"`
	Note         string `json:"note,omitempty"`
	RefRequestID string `json:"ref_request_id,omitempty"`
}

// Query selects what to reconstruct. Exactly one selector should be set;
// when both are empty every record is returned.
type Query struct {
	SessionID string
	RequestID string
	Limit     int
}

// Reconstruct reads an evidence directory and rebuilds the matching records in
// chain order.
//
// What it can show depends entirely on the content mode that was in force when
// the records were written. In hash mode there is no text to show, and the
// result says so rather than presenting an empty conversation.
func Reconstruct(dir string, q Query) (*Session, error) {
	s := &Session{SessionID: q.SessionID}
	models := map[string]struct{}{}
	clients := map[string]struct{}{}

	err := evidence.Walk(dir, func(e evidence.Entry) error {
		if !matches(e.Event, q) {
			return nil
		}
		if q.Limit > 0 && len(s.Entries) >= q.Limit {
			return nil
		}

		ev := e.Event
		entry := SessionEntry{
			Seq:          e.Record.Seq,
			Timestamp:    e.Record.Timestamp,
			EventType:    ev.EventType,
			RequestID:    ev.RequestID,
			Endpoint:     ev.Endpoint,
			Status:       ev.Status,
			Stream:       ev.Stream,
			LatencyMS:    ev.LatencyMS,
			Finish:       ev.FinishReasons,
			Error:        ev.Error,
			ToolCalls:    ev.ToolCalls,
			Actor:        ev.Actor,
			Decision:     ev.Decision,
			Note:         ev.Note,
			RefRequestID: ev.RefRequestID,
		}
		if name := servedOrRequested(ev); name != "" {
			entry.Model = name
			models[name] = struct{}{}
		}
		if ev.ClientHash != "" {
			clients[ev.ClientHash] = struct{}{}
		}
		if ev.Usage != nil {
			entry.PromptTokens = ev.Usage.PromptTokens
			entry.CompletionTokens = ev.Usage.CompletionTokens
		}
		if ev.Content != nil {
			if in := ev.Content.Input; in != nil {
				entry.InputHash = in.SHA256
				entry.Input = in.Messages
				if len(in.Messages) == 0 && in.Text != "" {
					entry.Input = []evidence.Message{{Role: "input", Content: in.Text}}
				}
			}
			if out := ev.Content.Output; out != nil {
				entry.OutputHash = out.SHA256
				entry.Output = out.Text
			}
		}
		if len(entry.Input) > 0 || entry.Output != "" {
			s.ContentAvailable = true
		}
		if s.SessionID == "" && ev.SessionID != "" {
			s.SessionID = ev.SessionID
		}

		if s.First == "" {
			s.First = e.Record.Timestamp
		}
		s.Last = e.Record.Timestamp
		s.Records++
		s.Entries = append(s.Entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.Models = sortedKeys(models)
	s.Clients = sortedKeys(clients)
	return s, nil
}

func matches(ev evidence.Event, q Query) bool {
	switch {
	case q.SessionID != "":
		return ev.SessionID == q.SessionID
	case q.RequestID != "":
		return ev.RequestID == q.RequestID || ev.RefRequestID == q.RequestID
	default:
		return true
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Render writes a session as readable text.
func (s *Session) Render(w *strings.Builder) {
	if s.Records == 0 {
		w.WriteString("no matching records\n")
		return
	}

	if s.SessionID != "" {
		fmt.Fprintf(w, "session %s\n", s.SessionID)
	}
	fmt.Fprintf(w, "  records   %d\n", s.Records)
	fmt.Fprintf(w, "  window    %s\n            %s\n", s.First, s.Last)
	if len(s.Models) > 0 {
		fmt.Fprintf(w, "  models    %s\n", strings.Join(s.Models, ", "))
	}
	if len(s.Clients) > 0 {
		fmt.Fprintf(w, "  callers   %s\n", strings.Join(s.Clients, ", "))
	}
	w.WriteString("\n")

	for _, e := range s.Entries {
		fmt.Fprintf(w, "[%d] %s  %s\n", e.Seq, e.Timestamp, e.EventType)

		switch e.EventType {
		case evidence.EventHumanIntervention:
			fmt.Fprintf(w, "     %s by %s\n", strings.ToUpper(e.Decision), e.Actor)
			if e.RefRequestID != "" {
				fmt.Fprintf(w, "     concerning request %s\n", e.RefRequestID)
			}
			if e.Note != "" {
				fmt.Fprintf(w, "     %s\n", e.Note)
			}
		default:
			if e.Model != "" {
				fmt.Fprintf(w, "     model %s via %s", e.Model, e.Endpoint)
				if e.Stream {
					w.WriteString(" (streamed)")
				}
				w.WriteString("\n")
			}
			if e.Status != 0 {
				fmt.Fprintf(w, "     status %d in %.0f ms", e.Status, e.LatencyMS)
				if e.PromptTokens > 0 || e.CompletionTokens > 0 {
					fmt.Fprintf(w, ", %d prompt + %d completion tokens", e.PromptTokens, e.CompletionTokens)
				}
				w.WriteString("\n")
			}
			if e.Error != "" {
				fmt.Fprintf(w, "     error: %s\n", e.Error)
			}
			for _, m := range e.Input {
				fmt.Fprintf(w, "     %s> %s\n", m.Role, indent(m.Content))
			}
			if e.Output != "" {
				fmt.Fprintf(w, "     assistant> %s\n", indent(e.Output))
			}
			for _, tc := range e.ToolCalls {
				fmt.Fprintf(w, "     tool call %s", tc.Name)
				if tc.Arguments != "" {
					fmt.Fprintf(w, " %s", tc.Arguments)
				}
				w.WriteString("\n")
			}
			if e.Note != "" {
				fmt.Fprintf(w, "     %s\n", e.Note)
			}
			if len(e.Input) == 0 && e.Output == "" && e.InputHash != "" {
				fmt.Fprintf(w, "     content not retained; input %s output %s\n",
					shortHash(e.InputHash), shortHash(e.OutputHash))
			}
		}
		w.WriteString("\n")
	}

	if !s.ContentAvailable {
		w.WriteString("No prompt or completion text is recorded in this log.\n")
		w.WriteString("The content mode was hash, which retains a digest of each request and\n")
		w.WriteString("response and no text. The digests above still prove which interaction\n")
		w.WriteString("each record describes.\n")
	}
}

func indent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return strings.ReplaceAll(s, "\n", "\n     ")
}

func shortHash(h string) string {
	if h == "" {
		return "(none)"
	}
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
