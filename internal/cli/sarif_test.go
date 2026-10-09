package cli

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestVerifySARIF(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kinds    []string
		levels   []string
		complete bool
		code     int
	}{
		{"clean", nil, nil, true, 0},
		{"integrity", []string{evidence.ProblemHashMismatch}, []string{"error"}, true, 1},
		{"incomplete", []string{evidence.ProblemUnknownKey}, []string{"warning"}, false, 2},
		{"mixed", []string{evidence.ProblemHashMismatch, evidence.ProblemBadTimestamp}, []string{"error", "warning"}, false, 1},
		{"repeated rule", []string{evidence.ProblemHashMismatch, evidence.ProblemHashMismatch}, []string{"error", "error"}, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &evidence.VerifyResult{Dir: filepath.Join(t.TempDir(), "evidence #1"), Records: 7, Pruned: true, Notes: []string{"pruned log"}}
			for i, kind := range tc.kinds {
				res.Problems = append(res.Problems, evidence.Problem{
					Kind: kind, Detail: "check failed", Segment: "segment #1%.jsonl", Line: i, Seq: 7,
				})
			}
			doc, err := verifySARIF(res)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Version string
				Runs    []struct {
					Tool struct {
						Driver struct{ Rules []struct{ ID string } }
					}
					OriginalURIBaseIDs map[string]struct{ URI string }
					Invocations        []struct {
						ExecutionSuccessful bool
						ExitCode            int
					}
					Results []struct {
						RuleID, Level string
						Message       struct{ Text string }
						Locations     []struct {
							PhysicalLocation struct {
								ArtifactLocation struct{ URI, URIBaseID string }
								Region           *struct{ StartLine int }
							}
						}
					}
					Properties struct {
						Pruned bool
						Notes  []string
					}
				}
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got.Version != "2.1.0" || len(got.Runs) != 1 {
				t.Fatalf("invalid SARIF document: %s", data)
			}
			run := got.Runs[0]
			if len(run.Results) != len(tc.kinds) || len(run.Invocations) != 1 ||
				run.Invocations[0].ExecutionSuccessful != tc.complete || run.Invocations[0].ExitCode != tc.code {
				t.Fatalf("wrong results or completion status: %s", data)
			}
			if run.Results == nil || !run.Properties.Pruned || len(run.Properties.Notes) != 1 {
				t.Fatalf("missing results array or evidence context: %s", data)
			}
			base, err := url.Parse(run.OriginalURIBaseIDs["EVIDENCE"].URI)
			if err != nil || base.Scheme != "file" || !strings.HasSuffix(base.Path, "/evidence #1/") {
				t.Fatalf("invalid evidence base URI: %v, %v", base, err)
			}
			seen := map[string]bool{}
			for i, result := range run.Results {
				seen[tc.kinds[i]] = true
				if result.RuleID != tc.kinds[i] || result.Level != tc.levels[i] || result.Message.Text != "check failed" {
					t.Errorf("wrong result: %+v", result)
				}
				loc := result.Locations[0].PhysicalLocation
				if loc.ArtifactLocation.URI != "segment%20%231%25.jsonl" || loc.ArtifactLocation.URIBaseID != "EVIDENCE" {
					t.Errorf("invalid artifact URI: %+v", loc)
				}
				if i == 0 && loc.Region != nil || i > 0 && (loc.Region == nil || loc.Region.StartLine != i) {
					t.Errorf("invalid line region: %+v", loc)
				}
			}
			if len(run.Tool.Driver.Rules) != len(seen) {
				t.Errorf("duplicate or missing rules: %+v", run.Tool.Driver.Rules)
			}
		})
	}
}

func TestVerifyFormats(t *testing.T) {
	dir := t.TempDir()
	signedLog(t, dir, 1)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 0, "hash chain intact"},
		{[]string{"--format", "text"}, 0, "hash chain intact"},
		{[]string{"--json"}, 0, `"head_hash"`},
		{[]string{"--format", "json"}, 0, `"head_hash"`},
		{[]string{"--format", "sarif"}, 0, `"runs"`},
		{[]string{"--format", "sarif", "--quiet"}, 0, ""},
		{[]string{"--json", "--format", "json"}, 0, `"head_hash"`},
		{[]string{"--json", "--format", "sarif"}, 1, ""},
		{[]string{"--format", "yaml"}, 1, ""},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			args := append([]string{"verify", "--dir", dir}, tc.args...)
			code, out := runCLI(t, args...)
			if code != tc.code || !strings.Contains(out, tc.want) || tc.want == "" && out != "" {
				t.Fatalf("verify %v: code %d, output %q", tc.args, code, out)
			}
		})
	}
}
