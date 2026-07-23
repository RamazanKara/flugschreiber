package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

const testToken = "test-events-token"

func eventsHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, mockHandler(), func(c *config.Config) {
		c.EventsToken = testToken
	})
}

func (h *harness) postEvent(body string, token string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.proxy.URL+EventsPath, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func drain(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHumanInterventionIsRecordedInTheChain(t *testing.T) {
	h := eventsHarness(t)

	resp := h.postEvent(`{
		"event_type": "human_intervention",
		"session_id": "sess-9",
		"ref_request_id": "req-abc",
		"actor": "alice@muster.example",
		"decision": "override",
		"note": "Model recommended refusing the refund. Agent issued it manually under policy 4.2."
	}`, testToken)
	body := drain(t, resp)

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var out eventResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, body)
	}
	if !out.Recorded || out.RequestID == "" {
		t.Errorf("response = %+v", out)
	}

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if e.EventType != evidence.EventHumanIntervention {
		t.Errorf("EventType = %q", e.EventType)
	}
	if e.Actor != "alice@muster.example" || e.Decision != evidence.DecisionOverride {
		t.Errorf("Actor/Decision = %q/%q", e.Actor, e.Decision)
	}
	if e.RefRequestID != "req-abc" || e.SessionID != "sess-9" {
		t.Errorf("RefRequestID/SessionID = %q/%q", e.RefRequestID, e.SessionID)
	}
	if !strings.Contains(e.Note, "policy 4.2") {
		t.Errorf("Note = %q", e.Note)
	}

	res, err := evidence.Verify(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("chain broken after an oversight event: %v", res.Problems)
	}
}

// An oversight record nobody authenticated is not evidence of oversight, so the
// endpoint stays off until an operator configures a token.
func TestEventsEndpointIsDisabledWithoutAToken(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)

	resp := h.postEvent(`{"event_type":"system_event","note":"hello"}`, "")
	body := drain(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no token is configured: %s", resp.StatusCode, body)
	}
	if events := h.events(); len(events) != 0 {
		t.Errorf("recorded %d events with the endpoint disabled", len(events))
	}
}

func TestEventsEndpointRejectsBadTokens(t *testing.T) {
	for _, token := range []string{"", "wrong", testToken + "x", strings.ToUpper(testToken)} {
		t.Run("token="+token, func(t *testing.T) {
			h := eventsHarness(t)
			resp := h.postEvent(`{"event_type":"system_event","note":"hello"}`, token)
			drain(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
			if events := h.events(); len(events) != 0 {
				t.Errorf("an unauthorised caller wrote %d events", len(events))
			}
		})
	}
}

// The most important rule of this endpoint: a caller may describe what a human
// did, and may never describe what a model did. Otherwise anyone holding the
// token could fabricate a model interaction that verifies.
func TestInferenceRecordsCannotBeSubmitted(t *testing.T) {
	h := eventsHarness(t)

	resp := h.postEvent(`{
		"event_type": "inference",
		"note": "a completely fabricated model call"
	}`, testToken)
	body := drain(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "written only by the proxy") {
		t.Errorf("error does not explain why: %s", body)
	}
	if events := h.events(); len(events) != 0 {
		t.Fatalf("a forged inference record was written")
	}
}

func TestUnknownEventTypesAreRejected(t *testing.T) {
	h := eventsHarness(t)
	resp := h.postEvent(`{"event_type":"model_training","note":"x"}`, testToken)
	body := drain(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "not recordable") {
		t.Errorf("body = %s", body)
	}
}

func TestInterventionValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "intervention without an actor",
			body: `{"event_type":"human_intervention","decision":"approve"}`,
			want: "actor is required",
		},
		{
			name: "intervention without a decision",
			body: `{"event_type":"human_intervention","actor":"bob"}`,
			want: "decision is required",
		},
		{
			name: "unrecognised decision",
			body: `{"event_type":"human_intervention","actor":"bob","decision":"maybe"}`,
			want: "not recognised",
		},
		{
			name: "missing event type",
			body: `{"actor":"bob"}`,
			want: "event_type is required",
		},
		{
			name: "unknown field",
			body: `{"event_type":"system_event","surprise":true}`,
			want: "invalid event body",
		},
		{
			name: "oversized note",
			body: `{"event_type":"system_event","note":"` + strings.Repeat("x", maxNoteBytes+1) + `"}`,
			want: "note exceeds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := eventsHarness(t)
			resp := h.postEvent(tc.body, testToken)
			body := drain(t, resp)

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("error %q does not mention %q", body, tc.want)
			}
			if events := h.events(); len(events) != 0 {
				t.Errorf("an invalid event was recorded")
			}
		})
	}
}

func TestSessionLifecycleEventsAreRecordable(t *testing.T) {
	h := eventsHarness(t)

	for _, et := range []string{evidence.EventSessionStart, evidence.EventSessionEnd, evidence.EventConfigChange} {
		resp := h.postEvent(`{"event_type":"`+et+`","session_id":"sess-1","note":"n"}`, testToken)
		body := drain(t, resp)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("%s: status = %d: %s", et, resp.StatusCode, body)
		}
	}

	events := h.events()
	if len(events) != 3 {
		t.Fatalf("recorded %d events, want 3", len(events))
	}
	for i, want := range []string{evidence.EventSessionStart, evidence.EventSessionEnd, evidence.EventConfigChange} {
		if events[i].EventType != want {
			t.Errorf("events[%d].EventType = %q, want %q", i, events[i].EventType, want)
		}
	}
}

// Oversight events and inference records share one chain, which is the point:
// the override and the interaction it concerns are ordered relative to each
// other and neither can be altered without breaking the other.
func TestOversightAndInferenceShareOneChain(t *testing.T) {
	h := eventsHarness(t)

	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"refund?"}]}`, nil)
	resp := h.postEvent(`{"event_type":"human_intervention","actor":"alice","decision":"reject","note":"n"}`, testToken)
	drain(t, resp)

	events := h.events()
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want 2", len(events))
	}
	if events[0].EventType != evidence.EventInference {
		t.Errorf("events[0] = %q", events[0].EventType)
	}
	if events[1].EventType != evidence.EventHumanIntervention {
		t.Errorf("events[1] = %q", events[1].EventType)
	}

	res, err := evidence.Verify(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.Records != 2 {
		t.Errorf("verify = %d records, problems %v", res.Records, res.Problems)
	}
}

func TestEventsEndpointRejectsNonPost(t *testing.T) {
	h := eventsHarness(t)
	resp, err := http.Get(h.proxy.URL + EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, resp)
	if resp.StatusCode == http.StatusAccepted {
		t.Error("GET on the events endpoint was accepted")
	}
}

// Article 73 incident records go through the same authenticated endpoint and
// the same forgery protections: a token is required, and an incident cannot
// masquerade as an inference record.
func TestIncidentIsRecordedWithSeverity(t *testing.T) {
	h := eventsHarness(t)
	resp := h.postEvent(`{
		"event_type": "incident",
		"session_id": "sess-9",
		"ref_request_id": "req-abc",
		"actor": "dpo@muster.example",
		"severity": "serious",
		"note": "Model produced defamatory output about a named individual."
	}`, testToken)
	body := drain(t, resp)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}

	events := h.events()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	e := events[0]
	if e.EventType != evidence.EventIncident {
		t.Errorf("EventType = %q", e.EventType)
	}
	if e.Severity != evidence.SeveritySerious {
		t.Errorf("Severity = %q, want serious", e.Severity)
	}
	if e.Actor == "" || e.RefRequestID != "req-abc" {
		t.Errorf("incident = %+v", e)
	}
}

func TestIncidentValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"incident without actor", `{"event_type":"incident","severity":"serious"}`, "actor is required"},
		{"incident without severity", `{"event_type":"incident","actor":"a"}`, "severity is required"},
		{"unrecognised severity", `{"event_type":"incident","actor":"a","severity":"catastrophic"}`, "not recognised"},
		{"severity on a non-incident", `{"event_type":"system_event","severity":"serious","note":"x"}`, "only be set on an incident"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := eventsHarness(t)
			resp := h.postEvent(tc.body, testToken)
			body := drain(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("error %q does not mention %q", body, tc.want)
			}
			if events := h.events(); len(events) != 0 {
				t.Error("an invalid incident was recorded")
			}
		})
	}
}

// An incident is a statement about a human's conclusion, so it may not be used
// to inject a fabricated model interaction any more than an intervention can.
func TestIncidentCannotForgeInference(t *testing.T) {
	h := eventsHarness(t)
	resp := h.postEvent(`{"event_type":"inference","severity":"serious","actor":"a"}`, testToken)
	body := drain(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
	}
	if events := h.events(); len(events) != 0 {
		t.Fatal("a forged inference record was written through the incident path")
	}
}
