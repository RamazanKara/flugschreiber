package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

func TestReportLanguageAndFormats(t *testing.T) {
	dir := t.TempDir()
	signedLog(t, dir, 1)
	for _, tc := range []struct {
		name  string
		flags []string
		docs  []string
		pdf   bool
	}{
		{"default", nil, []string{"technical-documentation", "technical-documentation-de", "transparency-article-50-en", "transparency-article-50-de"}, false},
		{"English", []string{"--lang", "en"}, []string{"technical-documentation", "transparency-article-50-en"}, false},
		{"German PDF", []string{"--lang", "de", "--pdf"}, []string{"technical-documentation-de", "transparency-article-50-de"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir()
			args := []string{"report", "--dir", dir, "--out", out, "--now", "2026-07-22T12:00:00Z", "--organisation", "Muster GmbH", "--system-name", "Support Assistant"}
			if code, output := runCLI(t, append(args, tc.flags...)...); code != 0 {
				t.Fatalf("report exited %d: %s", code, output)
			}
			exts := []string{".md", ".html"}
			if tc.pdf {
				exts = append(exts, ".pdf")
			}
			files, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != len(tc.docs)*len(exts) {
				t.Fatalf("generated %d files, want %d", len(files), len(tc.docs)*len(exts))
			}
			for _, doc := range tc.docs {
				for _, ext := range exts {
					body, err := os.ReadFile(filepath.Join(out, doc+ext))
					if err != nil {
						t.Fatal(err)
					}
					if ext == ".pdf" {
						if !strings.HasPrefix(string(body), "%PDF-") || !strings.Contains(string(body), "%%EOF") {
							t.Fatalf("%s is not a complete PDF", doc)
						}
					} else if !strings.Contains(string(body), "Muster GmbH") || !strings.Contains(string(body), "Support Assistant") {
						t.Fatalf("%s%s lost the deployment metadata", doc, ext)
					}
				}
			}
		})
	}
}

func TestReportRejectsInvalidOptions(t *testing.T) {
	for _, args := range [][]string{{"--lang", "fr"}, {"--now", "tomorrow"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "reports")
			args = append([]string{"--dir", t.TempDir(), "--out", out}, args...)
			if err := Report(args); err == nil {
				t.Fatal("invalid report options were accepted")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("invalid options created output: %v", err)
			}
		})
	}
}

func TestRepairRecordsActualSequence(t *testing.T) {
	dir := t.TempDir()
	signedLog(t, dir, 2)
	path := filepath.Join(dir, evidence.SegmentName(1))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	torn := append(original, []byte(`{"seq":3,"event":`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCLI(t, "repair", "--dir", dir); code != 0 || !strings.Contains(out, "Nothing has been changed") {
		t.Fatalf("repair dry run exited %d: %s", code, out)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(torn) {
		t.Fatalf("dry run changed evidence: %v", err)
	}
	code, out := runCLI(t, "repair", "--dir", dir, "--confirm", "--actor", "operator", "--json")
	if code != 0 {
		t.Fatalf("repair exited %d: %s", code, out)
	}
	var result repairReport
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Repaired || result.DryRun || result.Seq != 3 {
		t.Fatalf("repair report = %+v, want repair recorded at seq 3", result)
	}
	verified, err := evidence.Verify(dir)
	if err != nil || !verified.OK() || verified.LastSeq != result.Seq {
		t.Fatalf("repaired chain = %+v, %v", verified, err)
	}
	var last evidence.Entry
	if err := evidence.Walk(dir, func(e evidence.Entry) error { last = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if last.Event.EventType != evidence.EventSystemEvent || last.Event.Actor != "operator" || !strings.Contains(last.Event.Note, "partial final record") {
		t.Fatalf("repair was not documented: %+v", last.Event)
	}
}
