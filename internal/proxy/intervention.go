package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/content"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
	"github.com/RamazanKara/flugschreiber/internal/metrics"
)

// EventsPath is the endpoint applications post oversight events to. It is
// namespaced away from /v1 so it can never collide with an upstream's API
// surface, however that upstream evolves.
const EventsPath = "/flugschreiber/v1/events"

// maxEventBody bounds a submitted event. Oversight notes are prose written by a
// person, so this is generous; it exists to stop the endpoint being used as a
// blob store.
const maxEventBody = 64 << 10

// maxNoteBytes bounds the free-text fields of a single event.
const maxNoteBytes = 8 << 10

// eventRequest is what a caller posts. It is deliberately narrower than the
// evidence Event: a caller may describe what a human did, and may not describe
// what a model did.
type eventRequest struct {
	EventType    string `json:"event_type"`
	SessionID    string `json:"session_id"`
	RefRequestID string `json:"ref_request_id"`
	Actor        string `json:"actor"`
	Decision     string `json:"decision"`
	Note         string `json:"note"`
}

type eventResponse struct {
	Recorded  bool   `json:"recorded"`
	RequestID string `json:"request_id"`
	EventType string `json:"event_type"`
}

// handleEvents records a human oversight event in the evidence chain.
//
// Article 14 asks for human oversight that is effective in practice. Proving
// that after the fact needs a record of what a person actually did, in the same
// tamper-evident log as the model interaction they did it about. This endpoint
// is how that record gets there without an application taking on the evidence
// format itself.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.eventsEnabled() {
		// An unauthenticated endpoint that appends to the evidence log would
		// let anyone who can reach the proxy fabricate oversight records, which
		// is worse than having no endpoint at all. So it stays off until an
		// operator sets a token and thereby makes a decision about it.
		writeEventError(w, http.StatusNotFound,
			"the events endpoint is disabled; start Flugschreiber with --events-token to enable it")
		return
	}
	if !s.eventsAuthorised(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="flugschreiber-events"`)
		writeEventError(w, http.StatusUnauthorized, "a valid bearer token is required")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBody))
	if err != nil {
		writeEventError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("event body exceeds %d bytes", maxEventBody))
		return
	}

	var req eventRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeEventError(w, http.StatusBadRequest, "invalid event body: "+err.Error())
		return
	}

	if problem := validateEvent(&req); problem != "" {
		writeEventError(w, http.StatusBadRequest, problem)
		return
	}

	ev := &evidence.Event{
		SchemaVersion: evidence.SchemaVersion,
		EventType:     req.EventType,
		RequestID:     newID(),
		SessionID:     req.SessionID,
		RefRequestID:  req.RefRequestID,
		ClientHash:    content.ClientHash(s.salt, credential(r)),
		Endpoint:      EventsPath,
		Method:        r.Method,
		Actor:         req.Actor,
		Decision:      req.Decision,
		Note:          req.Note,
		Status:        http.StatusAccepted,
	}

	if err := s.store.Append(ev); err != nil {
		s.captureErrors.Add(1)
		s.metrics.CaptureError(metrics.CaptureErrorAppendFailed)
		s.log.Error("failed to append oversight event",
			slog.String("event_type", req.EventType),
			slog.String("error", err.Error()))
		writeEventError(w, http.StatusServiceUnavailable, "the evidence store rejected the event: "+err.Error())
		return
	}
	s.metrics.EventAppended()

	s.log.Info("oversight event recorded",
		slog.String("event_type", ev.EventType),
		slog.String("request_id", ev.RequestID),
		slog.String("decision", ev.Decision))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(eventResponse{
		Recorded:  true,
		RequestID: ev.RequestID,
		EventType: ev.EventType,
	})
}

// validateEvent returns a human-readable problem, or the empty string when the
// event is acceptable. The messages name the field and the allowed values,
// because the caller is an application developer wiring this up once.
func validateEvent(req *eventRequest) string {
	if req.EventType == "" {
		return "event_type is required"
	}
	if req.EventType == evidence.EventInference {
		return "event_type inference cannot be submitted: inference records are written only by the proxy from observed traffic"
	}
	if !evidence.RecordableEventType(req.EventType) {
		return fmt.Sprintf("event_type %q is not recordable; use one of: %s",
			req.EventType, strings.Join([]string{
				evidence.EventHumanIntervention, evidence.EventSessionStart,
				evidence.EventSessionEnd, evidence.EventConfigChange,
				evidence.EventToolCall, evidence.EventToolResult,
				evidence.EventSystemEvent,
			}, ", "))
	}

	if req.EventType == evidence.EventHumanIntervention {
		if strings.TrimSpace(req.Actor) == "" {
			return "actor is required for a human_intervention: an oversight record that does not say who is not oversight evidence"
		}
		if req.Decision == "" {
			return fmt.Sprintf("decision is required for a human_intervention; use one of: %s",
				strings.Join([]string{
					evidence.DecisionApprove, evidence.DecisionOverride,
					evidence.DecisionReject, evidence.DecisionEscalate,
					evidence.DecisionHalt, evidence.DecisionAnnotate,
				}, ", "))
		}
	}

	if req.Decision != "" && !evidence.ValidDecision(req.Decision) {
		return fmt.Sprintf("decision %q is not recognised", req.Decision)
	}
	if len(req.Note) > maxNoteBytes {
		return fmt.Sprintf("note exceeds %d bytes", maxNoteBytes)
	}
	if len(req.Actor) > 256 {
		return "actor exceeds 256 bytes"
	}
	if len(req.SessionID) > 256 || len(req.RefRequestID) > 256 {
		return "session_id and ref_request_id must each be at most 256 bytes"
	}
	return ""
}

func (s *Server) eventsEnabled() bool {
	return s.cfg.EventsToken != ""
}

// eventsAuthorised compares the presented token in constant time, so that a
// caller cannot learn the token one byte at a time from response timing.
func (s *Server) eventsAuthorised(r *http.Request) bool {
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if presented == "" {
		presented = r.Header.Get("X-Flugschreiber-Token")
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.EventsToken)) == 1
}

func writeEventError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"recorded": false,
		"error":    map[string]any{"message": message, "type": "invalid_request_error"},
	})
}
