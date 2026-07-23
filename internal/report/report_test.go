package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flugschreiber/flugschreiber/internal/config"
	"github.com/flugschreiber/flugschreiber/internal/evidence"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func ptrF(f float64) *float64 { return &f }
func ptrI(i int) *int         { return &i }

// buildFixture writes a deterministic evidence log covering the shapes the
// generator has to describe: streamed and non-streamed chat, a model
// substitution, a tool call, embeddings, and a failed request.
func buildFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	base := time.Date(2026, 5, 4, 8, 30, 0, 0, time.UTC)
	tick := 0
	store, err := evidence.Open(evidence.Options{
		Dir: dir,
		Now: func() time.Time {
			tick++
			return base.Add(time.Duration(tick) * time.Minute)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	events := []*evidence.Event{
		{
			EventType: evidence.EventInference, RequestID: "req-1", SessionID: "sess-a",
			ClientHash: "aaaa1111", Endpoint: "/v1/chat/completions", Method: "POST",
			Upstream: "http://vllm:8000", ModelRequested: "llama-3.1-8b-instruct",
			ModelServed: "llama-3.1-8b-instruct", Status: 200, LatencyMS: 812.4, TTFBMS: 1.2,
			Params:        &evidence.Params{Temperature: ptrF(0.2), MaxTokens: ptrI(512)},
			Usage:         &evidence.Usage{PromptTokens: 180, CompletionTokens: 64, TotalTokens: 244},
			FinishReasons: []string{"stop"},
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("a", 64), Bytes: 412},
				Output: &evidence.Payload{SHA256: strings.Repeat("b", 64), Bytes: 903}},
		},
		{
			EventType: evidence.EventInference, RequestID: "req-2", SessionID: "sess-a",
			ClientHash: "aaaa1111", Endpoint: "/v1/chat/completions", Method: "POST",
			Upstream: "http://vllm:8000", ModelRequested: "llama-3.1-8b-instruct",
			ModelServed: "llama-3.1-8b-instruct", Status: 200, LatencyMS: 2240.9, TTFBMS: 1.4,
			Stream:        true,
			Params:        &evidence.Params{Temperature: ptrF(0.7), TopP: ptrF(0.95), MaxTokens: ptrI(1024)},
			Usage:         &evidence.Usage{PromptTokens: 210, CompletionTokens: 340, TotalTokens: 550},
			FinishReasons: []string{"stop"},
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("c", 64), Bytes: 520},
				Output: &evidence.Payload{SHA256: strings.Repeat("d", 64), Bytes: 4102}},
		},
		{
			EventType: evidence.EventInference, RequestID: "req-3", SessionID: "sess-b",
			ClientHash: "bbbb2222", Endpoint: "/v1/chat/completions", Method: "POST",
			Upstream: "http://vllm:8000", ModelRequested: "llama-3.1-8b-instruct",
			ModelServed: "llama-3.1-8b-instruct-awq", Status: 200, LatencyMS: 640.1, TTFBMS: 0.9,
			Params: &evidence.Params{Temperature: ptrF(0.0), MaxTokens: ptrI(256),
				ToolsOffered: []string{"lookup_order", "issue_refund"}, ToolChoice: "auto"},
			Usage:         &evidence.Usage{PromptTokens: 340, CompletionTokens: 28, TotalTokens: 368},
			FinishReasons: []string{"tool_calls"},
			ToolCalls: []evidence.ToolCall{
				{ID: "call_1", Index: 0, Name: "lookup_order", ArgumentsHash: strings.Repeat("e", 64)},
			},
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("f", 64), Bytes: 880},
				Output: &evidence.Payload{SHA256: strings.Repeat("0", 64), Bytes: 214}},
		},
		{
			EventType: evidence.EventInference, RequestID: "req-4", SessionID: "sess-b",
			ClientHash: "bbbb2222", Endpoint: "/v1/embeddings", Method: "POST",
			Upstream: "http://vllm:8000", ModelRequested: "bge-m3", ModelServed: "bge-m3",
			Status: 200, LatencyMS: 48.7, TTFBMS: 0.7,
			Usage: &evidence.Usage{PromptTokens: 96, TotalTokens: 96},
			Note:  "4 embedding vectors of 1024 dimensions",
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("1", 64), Bytes: 300},
				Output: &evidence.Payload{SHA256: strings.Repeat("2", 64), Bytes: 40960}},
		},
		{
			EventType: evidence.EventInference, RequestID: "req-5", SessionID: "sess-c",
			ClientHash: "cccc3333", Endpoint: "/v1/chat/completions", Method: "POST",
			Upstream: "http://vllm:8000", ModelRequested: "mistral-7b", Status: 503,
			LatencyMS: 30012.0, Error: "upstream request failed: context deadline exceeded",
			Content: &evidence.Content{Mode: evidence.ModeHash,
				Input:  &evidence.Payload{SHA256: strings.Repeat("3", 64), Bytes: 260},
				Output: &evidence.Payload{SHA256: strings.Repeat("4", 64), Bytes: 0}},
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

func fixtureInput(t *testing.T, dir string) Input {
	t.Helper()
	summary, err := Summarise(dir, time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Summary: summary,
		Deployment: config.Deployment{
			Organisation: "Muster GmbH",
			SystemName:   "Support-Assistent",
			Purpose:      "drafting first-line support replies, reviewed by an agent before sending",
			Contact:      "ai-governance@muster.example",
			Role:         "deployer",
			Environment:  "production",
		},
		ContentMode:   evidence.ModeHash,
		RetentionDays: 180,
		// A fixed display path: the real directory is a temp dir, and the
		// golden output must not depend on where the test ran.
		DataDir: "/var/lib/flugschreiber",
		Version: "v0.1.0-test",
		Now:     time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC),
	}
}

func TestGenerateMatchesGoldenFiles(t *testing.T) {
	generated, err := Generate(fixtureInput(t, buildFixture(t)))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(generated.Artifacts) != 6 {
		t.Fatalf("generated %d artifacts, want 6 (three Markdown documents and an HTML rendering of each)", len(generated.Artifacts))
	}

	for _, a := range generated.Artifacts {
		// The HTML renderings are deliberately not golden files. They are 20 KB
		// each and a one-line stylesheet change would produce a diff nobody can
		// read, which CONTRIBUTING requires a human to read. Their structure is
		// covered by TestGeneratedDocumentsRenderToValidPages.
		if strings.HasSuffix(a.Filename, ".html") {
			continue
		}
		golden := filepath.Join("testdata", "golden", a.Filename)
		if *update {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, a.Content, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read golden %s: %v (run: go test ./internal/report -update)", golden, err)
		}
		if string(a.Content) != string(want) {
			t.Errorf("%s does not match its golden file.\n%s", a.Filename, firstDiff(string(want), string(a.Content)))
		}
	}
	if *update {
		t.Log("golden files rewritten")
	}
}

// The count is what the CLI tells an operator to go and deal with, so counting
// the HTML renderings as well would send them looking for twice the work that
// exists.
func TestTODOsCountsEachGapOnce(t *testing.T) {
	generated, err := Generate(fixtureInput(t, buildFixture(t)))
	if err != nil {
		t.Fatal(err)
	}

	want := 0
	for _, a := range generated.Artifacts {
		if a.Format == FormatMarkdown {
			want += strings.Count(string(a.Content), "**TODO:**")
		}
	}
	if want == 0 {
		t.Fatal("the fixture produced no TODO markers, so this test proves nothing")
	}
	if got := generated.TODOs(); got != want {
		t.Errorf("TODOs() = %d, want %d: the HTML renderings carry the same markers as the documents they render", got, want)
	}

	// The generated pages happen to render every marker as markup, so summing
	// over all six artifacts gives the right answer today by accident. The
	// contract is that the format decides, not whether a page happens to spell
	// the marker out, so it is asserted against a page that does.
	byHand := &Generated{Artifacts: []Artifact{
		{Filename: "doc.md", Format: FormatMarkdown, Content: []byte("**TODO:** name the operator.\n")},
		{Filename: "doc.html", Format: FormatHTML, Content: []byte("<pre><code>**TODO:** name the operator.\n</code></pre>\n")},
	}}
	if got := byHand.TODOs(); got != 1 {
		t.Errorf("TODOs() = %d, want 1: a marker quoted by an HTML rendering is not a second gap", got)
	}
}

// Two rows in the CLI listing that read the same tell an operator nothing about
// which file is which.
func TestEveryArtifactHasItsOwnTitle(t *testing.T) {
	generated, err := Generate(fixtureInput(t, buildFixture(t)))
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, a := range generated.Artifacts {
		if other, dup := seen[a.Title]; dup {
			t.Errorf("%s and %s share the title %q", other, a.Filename, a.Title)
		}
		seen[a.Title] = a.Filename

		want := FormatMarkdown
		if strings.HasSuffix(a.Filename, ".html") {
			want = FormatHTML
		}
		if a.Format != want {
			t.Errorf("%s has Format %q, want %q", a.Filename, a.Format, want)
		}
	}
}

// Generating twice from the same input must produce identical bytes, or the
// golden test would be checking noise and diffs between report runs would be
// unreadable.
func TestGenerateIsDeterministic(t *testing.T) {
	in := fixtureInput(t, buildFixture(t))

	first, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first.Artifacts {
		if string(first.Artifacts[i].Content) != string(second.Artifacts[i].Content) {
			t.Errorf("%s differs between two runs on identical input", first.Artifacts[i].Filename)
		}
	}
}

func TestSummariseAggregatesTraffic(t *testing.T) {
	s, err := Summarise(buildFixture(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if !s.ChainVerified {
		t.Errorf("fixture chain did not verify: %v", s.ChainProblems)
	}
	if s.Records != 5 || s.Inference != 5 {
		t.Errorf("Records/Inference = %d/%d, want 5/5", s.Records, s.Inference)
	}
	if s.Streamed != 1 {
		t.Errorf("Streamed = %d, want 1", s.Streamed)
	}
	if s.Errors != 1 {
		t.Errorf("Errors = %d, want 1", s.Errors)
	}
	if s.DistinctClients != 3 {
		t.Errorf("DistinctClients = %d, want 3", s.DistinctClients)
	}
	if s.DistinctSessions != 3 {
		t.Errorf("DistinctSessions = %d, want 3", s.DistinctSessions)
	}
	if s.PromptTokens != 826 || s.CompletionTokens != 432 {
		t.Errorf("tokens = %d/%d, want 826/432", s.PromptTokens, s.CompletionTokens)
	}
	if !s.Substituted() {
		t.Error("Substituted() = false, but the fixture serves an -awq variant for one request")
	}
	if len(s.ToolsCalled) != 1 || s.ToolsCalled[0].Name != "lookup_order" {
		t.Errorf("ToolsCalled = %+v", s.ToolsCalled)
	}
	if len(s.ToolsOffered) != 2 {
		t.Errorf("ToolsOffered = %+v, want two", s.ToolsOffered)
	}
}

// Counts are sorted by frequency then name so that two runs over the same log
// produce the same document.
func TestSortCountsIsStable(t *testing.T) {
	got := sortCounts(map[string]int{"b": 2, "a": 2, "c": 5})
	want := []Count{{"c", 5}, {"a", 2}, {"b", 2}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortCounts = %+v, want %+v", got, want)
		}
	}
}

// A report over an empty directory must still generate, and must say plainly
// that nothing was observed rather than implying coverage.
func TestGenerateOnEmptyEvidenceDirectory(t *testing.T) {
	summary, err := Summarise(t.TempDir(), time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := Generate(Input{
		Summary: summary, ContentMode: evidence.ModeHash,
		RetentionDays: 180, DataDir: "/var/lib/flugschreiber", Version: "test",
		Now: time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	doc := string(generated.Artifacts[0].Content)
	if !strings.Contains(doc, "No inference traffic was recorded") {
		t.Error("an empty log should say so explicitly")
	}
	if !strings.Contains(doc, "VERIFICATION FAILED") {
		t.Error("an empty directory does not verify and the document should say so")
	}
}

// The honest-framing rules are load-bearing: nothing generated may claim to
// confer compliance.
func TestGeneratedDocumentsNeverClaimCompliance(t *testing.T) {
	generated, err := Generate(fixtureInput(t, buildFixture(t)))
	if err != nil {
		t.Fatal(err)
	}

	banned := []string{
		"makes you compliant",
		"ensures compliance",
		"guarantees compliance",
		"fully compliant",
		"legal advice is",
	}
	for _, a := range generated.Artifacts {
		lower := strings.ToLower(string(a.Content))
		for _, phrase := range banned {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s contains the banned claim %q", a.Filename, phrase)
			}
		}
		if !strings.Contains(lower, "not legal advice") && !strings.Contains(lower, "keine rechtsberatung") {
			t.Errorf("%s does not carry the not-legal-advice disclaimer", a.Filename)
		}
	}
}

func TestEveryTODOCarriesGuidance(t *testing.T) {
	generated, err := Generate(fixtureInput(t, buildFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range generated.Artifacts {
		for i, line := range strings.Split(string(a.Content), "\n") {
			if !strings.Contains(line, "**TODO:**") {
				continue
			}
			_, guidance, _ := strings.Cut(line, "**TODO:**")
			if len(strings.Fields(guidance)) < 6 {
				t.Errorf("%s:%d has a TODO with no useful guidance: %q", a.Filename, i+1, line)
			}
		}
	}
}

func firstDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) && i < len(gotLines); i++ {
		if wantLines[i] != gotLines[i] {
			return "first difference at line " + itoa(i+1) +
				"\n  want: " + wantLines[i] +
				"\n  got:  " + gotLines[i] +
				"\n\nrun: go test ./internal/report -update"
		}
	}
	return "line counts differ: want " + itoa(len(wantLines)) + ", got " + itoa(len(gotLines)) +
		"\n\nrun: go test ./internal/report -update"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
