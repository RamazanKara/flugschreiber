package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// fixture writes a deterministic log: two inference records in one session, an
// oversight override, a long quiet stretch, then one more inference in a second
// session.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	offsets := []time.Duration{
		0,
		30 * time.Second,
		45 * time.Second,
		4 * time.Hour,
	}
	i := -1
	store, err := evidence.Open(evidence.Options{
		Dir: dir,
		Now: func() time.Time {
			i++
			if i < len(offsets) {
				return base.Add(offsets[i])
			}
			return base.Add(offsets[len(offsets)-1])
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	events := []*evidence.Event{
		{
			EventType: evidence.EventInference, RequestID: "req-1", SessionID: "sess-a",
			ClientHash: "client-1", Endpoint: "/v1/chat/completions",
			ModelRequested: "llama-3.1-8b", ModelServed: "llama-3.1-8b",
			Status: 200, Stream: false, LatencyMS: 400,
			Usage: &evidence.Usage{PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30},
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("a", 64), Bytes: 100},
				Output: &evidence.Payload{SHA256: strings.Repeat("b", 64), Bytes: 200}},
		},
		{
			EventType: evidence.EventInference, RequestID: "req-2", SessionID: "sess-a",
			ClientHash: "client-1", Endpoint: "/v1/chat/completions",
			ModelRequested: "llama-3.1-8b", ModelServed: "llama-3.1-8b",
			Status: 500, Stream: true, LatencyMS: 900, Error: "upstream exploded",
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("c", 64), Bytes: 100},
				Output: &evidence.Payload{SHA256: strings.Repeat("d", 64), Bytes: 0}},
		},
		{
			EventType: evidence.EventHumanIntervention, RequestID: "int-1", SessionID: "sess-a",
			Actor: "alice@muster.example", Decision: evidence.DecisionOverride,
			RefRequestID: "req-2", Note: "Upstream failed, answered the customer by hand.",
		},
		{
			EventType: evidence.EventInference, RequestID: "req-3", SessionID: "sess-b",
			ClientHash: "client-2", Endpoint: "/v1/embeddings",
			ModelRequested: "bge-m3", ModelServed: "bge-m3", Status: 200, LatencyMS: 40,
			Usage: &evidence.Usage{PromptTokens: 5, TotalTokens: 5},
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("e", 64), Bytes: 50},
				Output: &evidence.Payload{SHA256: strings.Repeat("f", 64), Bytes: 900}},
		},
	}
	for _, e := range events {
		if err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAnalyseCountsRecordsAndFidelity(t *testing.T) {
	c, err := Analyse(fixture(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if c.Records != 4 || c.Inference != 3 {
		t.Errorf("Records/Inference = %d/%d, want 4/3", c.Records, c.Inference)
	}
	if c.Streamed != 1 {
		t.Errorf("Streamed = %d, want 1", c.Streamed)
	}
	if c.Failed != 1 {
		t.Errorf("Failed = %d, want 1", c.Failed)
	}
	if c.DistinctSessions != 2 || c.DistinctClients != 2 {
		t.Errorf("sessions/clients = %d/%d, want 2/2", c.DistinctSessions, c.DistinctClients)
	}
	if !c.ChainVerified {
		t.Errorf("chain did not verify, %d problems", c.ChainProblems)
	}

	if len(c.ByContentMode) != 1 || c.ByContentMode[0].Name != evidence.ModeHash {
		t.Errorf("ByContentMode = %+v", c.ByContentMode)
	}
	if c.ByContentMode[0].Percent != 100 {
		t.Errorf("content mode share = %v, want 100", c.ByContentMode[0].Percent)
	}
}

// Token usage is absent whenever an upstream does not report it, and an
// operator needs to see that share rather than assume the accounting is
// complete.
func TestAnalyseReportsMetadataCompleteness(t *testing.T) {
	c, err := Analyse(fixture(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c.WithUsage != 2 {
		t.Errorf("WithUsage = %d, want 2 of 3 inference records", c.WithUsage)
	}
	if c.WithSession != 3 {
		t.Errorf("WithSession = %d, want 3", c.WithSession)
	}
	if c.WithClient != 3 {
		t.Errorf("WithClient = %d, want 3", c.WithClient)
	}
}

// A quiet stretch is the only signal this tool has that it might not have been
// running, so it must be surfaced rather than smoothed over.
func TestAnalyseReportsQuietStretches(t *testing.T) {
	c, err := Analyse(fixture(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Gaps) != 1 {
		t.Fatalf("Gaps = %+v, want exactly one", c.Gaps)
	}
	if c.Gaps[0].Duration != "3h59m15s" {
		t.Errorf("gap duration = %q", c.Gaps[0].Duration)
	}
	if c.Gaps[0].AfterSeq != 3 {
		t.Errorf("gap AfterSeq = %d, want 3", c.Gaps[0].AfterSeq)
	}
}

func TestAnalyseGapThresholdIsRespected(t *testing.T) {
	dir := fixture(t)

	wide, err := Analyse(dir, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(wide.Gaps) != 0 {
		t.Errorf("an 8h threshold should not flag a 4h quiet stretch: %+v", wide.Gaps)
	}

	narrow, err := Analyse(dir, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(narrow.Gaps) < 2 {
		t.Errorf("a 10s threshold should flag the short stretches too: %+v", narrow.Gaps)
	}
}

func TestAnalyseIsDeterministic(t *testing.T) {
	dir := fixture(t)
	first, err := Analyse(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyse(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first.ByModel {
		if first.ByModel[i] != second.ByModel[i] {
			t.Fatalf("ByModel differs between runs: %+v vs %+v", first.ByModel, second.ByModel)
		}
	}
	if first.Records != second.Records || len(first.Gaps) != len(second.Gaps) {
		t.Error("analysis is not deterministic")
	}
}

func TestPercent(t *testing.T) {
	cases := []struct {
		part, total int
		want        float64
	}{
		{0, 0, 0},
		{1, 3, 33.3},
		{2, 3, 66.7},
		{3, 3, 100},
		{1, 8, 12.5},
	}
	for _, tc := range cases {
		if got := Percent(tc.part, tc.total); got != tc.want {
			t.Errorf("Percent(%d, %d) = %v, want %v", tc.part, tc.total, got, tc.want)
		}
	}
}

func TestReconstructBySession(t *testing.T) {
	s, err := Reconstruct(fixture(t), Query{SessionID: "sess-a"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Records != 3 {
		t.Fatalf("Records = %d, want the two inferences and the override", s.Records)
	}
	if s.Entries[2].EventType != evidence.EventHumanIntervention {
		t.Errorf("last entry = %q", s.Entries[2].EventType)
	}
	if s.Entries[2].Decision != evidence.DecisionOverride || s.Entries[2].Actor == "" {
		t.Errorf("intervention = %+v", s.Entries[2])
	}
	if len(s.Models) != 1 || s.Models[0] != "llama-3.1-8b" {
		t.Errorf("Models = %v", s.Models)
	}
}

// An override recorded against a request must be findable from that request id,
// otherwise the link between an interaction and the human decision about it is
// only discoverable by reading the whole log.
func TestReconstructByRequestFindsTheInterventionThatReferencesIt(t *testing.T) {
	s, err := Reconstruct(fixture(t), Query{RequestID: "req-2"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Records != 2 {
		t.Fatalf("Records = %d, want the inference and the intervention about it", s.Records)
	}
	kinds := []string{s.Entries[0].EventType, s.Entries[1].EventType}
	if kinds[0] != evidence.EventInference || kinds[1] != evidence.EventHumanIntervention {
		t.Errorf("entries = %v", kinds)
	}
}

func TestReconstructLimit(t *testing.T) {
	s, err := Reconstruct(fixture(t), Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if s.Records != 2 {
		t.Errorf("Records = %d, want 2", s.Records)
	}
}

func TestReconstructUnknownSessionIsEmptyNotAnError(t *testing.T) {
	s, err := Reconstruct(fixture(t), Query{SessionID: "nope"})
	if err != nil {
		t.Fatalf("unknown session should not error: %v", err)
	}
	if s.Records != 0 {
		t.Errorf("Records = %d, want 0", s.Records)
	}
}

// In hash mode there is no transcript. The renderer must say so, because a
// reader who sees an empty conversation will otherwise conclude nothing
// happened.
func TestRenderExplainsWhyThereIsNoTranscript(t *testing.T) {
	s, err := Reconstruct(fixture(t), Query{SessionID: "sess-a"})
	if err != nil {
		t.Fatal(err)
	}
	if s.ContentAvailable {
		t.Fatal("ContentAvailable = true for a hash-mode log")
	}

	var b strings.Builder
	s.Render(&b)
	out := b.String()

	if !strings.Contains(out, "No prompt or completion text is recorded") {
		t.Errorf("render does not explain the absent transcript:\n%s", out)
	}
	if !strings.Contains(out, "content not retained") {
		t.Errorf("render does not mark records whose content was not retained:\n%s", out)
	}
	if !strings.Contains(out, "OVERRIDE by alice@muster.example") {
		t.Errorf("render does not show the oversight decision:\n%s", out)
	}
}

func TestRenderShowsTranscriptWhenStored(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Append(&evidence.Event{
		EventType: evidence.EventInference, RequestID: "r", SessionID: "s",
		ModelServed: "m", Endpoint: "/v1/chat/completions", Status: 200,
		Content: &evidence.Content{
			Mode: evidence.ModeStore,
			Input: &evidence.Payload{SHA256: strings.Repeat("a", 64),
				Messages: []evidence.Message{{Role: "user", Content: "where is my order"}}},
			Output: &evidence.Payload{SHA256: strings.Repeat("b", 64), Text: "It shipped on Tuesday."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	s, err := Reconstruct(dir, Query{SessionID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.ContentAvailable {
		t.Fatal("ContentAvailable = false for a store-mode log")
	}

	var b strings.Builder
	s.Render(&b)
	out := b.String()
	if !strings.Contains(out, "user> where is my order") {
		t.Errorf("input not rendered:\n%s", out)
	}
	if !strings.Contains(out, "assistant> It shipped on Tuesday.") {
		t.Errorf("output not rendered:\n%s", out)
	}
	if strings.Contains(out, "No prompt or completion text is recorded") {
		t.Errorf("render wrongly claims no transcript exists:\n%s", out)
	}
}

func TestAnalyseEmptyDirectory(t *testing.T) {
	c, err := Analyse(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c.Records != 0 {
		t.Errorf("Records = %d", c.Records)
	}
	if c.ChainVerified {
		t.Error("an empty directory should not report a verified chain")
	}
}

// The changes to the evidence itself, erasures, rotations, repairs, salt
// boundaries, are what an auditor most needs to see and what a per-type tally
// would bury. Coverage surfaces them as a list.
func TestCoverageSurfacesLifecycleEvents(t *testing.T) {
	dir := t.TempDir()
	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	events := []*evidence.Event{
		{EventType: evidence.EventInference, RequestID: "r-1", Endpoint: "/v1/chat/completions", Status: 200,
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("a", 64), Bytes: 1},
				Output: &evidence.Payload{SHA256: strings.Repeat("b", 64), Bytes: 1}}},
		{EventType: evidence.EventConfigChange, Note: "signing key rotated"},
		{EventType: evidence.EventSystemEvent, Actor: "dpo@example.org", Note: "stored content erased for session s-1"},
		{EventType: evidence.EventIncident, Severity: evidence.SeveritySerious, Actor: "alice@example.org",
			RefRequestID: "r-1", Note: "wrongly denied claim"},
	}
	for _, e := range events {
		if err := store.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := Analyse(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Lifecycle) != 3 {
		t.Fatalf("Lifecycle has %d events, want the rotation, the erasure and the incident", len(c.Lifecycle))
	}
	// The inference record is not a lifecycle event.
	for _, l := range c.Lifecycle {
		if l.Type == evidence.EventInference {
			t.Error("an inference record was surfaced as a lifecycle event")
		}
	}
	// The erasure carries who did it, and the incident carries its severity.
	var sawActor, sawSeverity bool
	for _, l := range c.Lifecycle {
		if l.Actor == "dpo@example.org" {
			sawActor = true
		}
		if l.Severity == evidence.SeveritySerious {
			sawSeverity = true
		}
	}
	if !sawActor {
		t.Error("the erasure did not carry the actor who performed it")
	}
	if !sawSeverity {
		t.Error("the incident did not carry its severity")
	}
}
