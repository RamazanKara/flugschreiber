package pdf

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC)

func sampleDoc(t *testing.T) Doc {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "sample.md"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return ParseMarkdown(src)
}

func render(t *testing.T, doc Doc, opt Options) ([]byte, []Substitution) {
	t.Helper()
	if opt.Created.IsZero() {
		opt.Created = fixedTime
	}
	var buf bytes.Buffer
	subs, err := Render(&buf, doc, opt)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.Bytes(), subs
}

func TestEveryCrossReferenceOffsetPointsAtItsObject(t *testing.T) {
	data, _ := render(t, sampleDoc(t), Options{Title: "Sample", Lang: "de"})
	s, err := parsePDF(data)
	if err != nil {
		t.Fatalf("rendered file does not parse: %v", err)
	}
	if len(s.objects) < 10 {
		t.Fatalf("expected a real object graph, got %d objects", len(s.objects))
	}
	if !strings.Contains(string(s.objects[s.root]), "/Type /Catalog") {
		t.Errorf("/Root object %d is not a catalog: %s", s.root, s.objects[s.root])
	}
	if !strings.Contains(string(s.objects[s.info]), "/Producer") {
		t.Errorf("/Info object %d carries no producer: %s", s.info, s.objects[s.info])
	}
}

func TestAnEmptyDocumentStillProducesAValidFile(t *testing.T) {
	data, subs := render(t, Doc{}, Options{Title: "Nothing to report"})
	if len(subs) != 0 {
		t.Errorf("an empty document reported substitutions: %v", subs)
	}
	s, err := parsePDF(data)
	if err != nil {
		t.Fatalf("empty document does not parse: %v", err)
	}
	if !strings.Contains(string(s.objects[s.root]), "/Type /Catalog") {
		t.Error("empty document has no catalog")
	}
}

func TestACodeBlockTallerThanAPageKeepsEveryLine(t *testing.T) {
	lines := make([]string, 200)
	for i := range lines {
		lines[i] = fmt.Sprintf("line-%03d", i)
	}
	data, _ := render(t, Doc{Blocks: []Block{Code{Lines: lines}}}, Options{Title: "x"})
	for _, l := range lines {
		if !bytes.Contains(data, []byte(escapeForContent(l))) {
			t.Fatalf("%q was lost when the code block ran past the end of a page", l)
		}
	}
}

func TestTruncatedOrShiftedFileFailsTheStructureCheck(t *testing.T) {
	data, _ := render(t, sampleDoc(t), Options{Title: "Sample"})
	cases := []struct {
		name string
		harm func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:len(b)-40] }},
		{"byte inserted before the objects", func(b []byte) []byte {
			return append(append([]byte{}, append(b[:12], ' ')...), b[12:]...)
		}},
		{"startxref moved", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\nstartxref\n"), []byte("\nstartxref\n9"), 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harmed := tc.harm(append([]byte{}, data...))
			if _, err := parsePDF(harmed); err == nil {
				t.Fatal("structure check accepted a damaged file, so it proves nothing about an intact one")
			}
		})
	}
}

func TestContentStreamsAreBalanced(t *testing.T) {
	data, _ := render(t, sampleDoc(t), Options{Title: "Sample"})
	s, err := parsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	streams := 0
	for num, body := range s.objects {
		i := bytes.Index(body, []byte("\nstream\n"))
		if i < 0 {
			continue
		}
		streams++
		content := string(body[i+len("\nstream\n"):])
		if !balanced(content, "BT", "ET") {
			t.Errorf("object %d has unbalanced text objects", num)
		}
		if !balanced(content, "q", "Q") {
			t.Errorf("object %d has unbalanced graphics state", num)
		}
	}
	if streams == 0 {
		t.Fatal("no content streams were emitted")
	}
}

func TestSameInputRendersIdenticalBytes(t *testing.T) {
	doc := sampleDoc(t)
	opt := Options{Title: "Sample", Lang: "de", Created: fixedTime}
	first, _ := render(t, doc, opt)
	second, _ := render(t, ParseMarkdown(mustRead(t, filepath.Join("testdata", "sample.md"))), opt)
	if !bytes.Equal(first, second) {
		t.Fatal("two renders of the same document differ, so the output cannot be reproduced from the input")
	}
}

func TestDifferentContentGetsADifferentFileIdentifier(t *testing.T) {
	a, _ := render(t, Doc{Blocks: []Block{Paragraph{Text: Text("one")}}}, Options{Title: "x"})
	b, _ := render(t, Doc{Blocks: []Block{Paragraph{Text: Text("two")}}}, Options{Title: "x"})
	ida, idb := identifier(t, a), identifier(t, b)
	if ida == idb {
		t.Fatalf("two different documents share the identifier %s", ida)
	}
}

func identifier(t *testing.T, data []byte) string {
	t.Helper()
	s, err := parsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(s.trailer, "/ID [<")
	return s.trailer[i : i+40]
}

func TestUnrepresentableRunesAreShownAndReported(t *testing.T) {
	doc := Doc{Blocks: []Block{Paragraph{Text: Text("Haken ✓ und Umlaut ü und noch ein ✓")}}}
	data, subs := render(t, doc, Options{Title: "x"})
	if len(subs) != 1 {
		t.Fatalf("expected exactly one substitution, got %v", subs)
	}
	if subs[0].Rune != '✓' || subs[0].Count != 2 {
		t.Errorf("substitution report is wrong: %+v", subs[0])
	}
	if !bytes.Contains(data, []byte(`[U+2713]`)) {
		t.Error("the marker for the dropped rune is not in the content stream, so the reader would never see that something was lost")
	}
	if !bytes.Contains(data, []byte(`\374`)) {
		t.Error("the umlaut was not written as its WinAnsi byte")
	}
}

func TestAnUnsettableRuneInTheRunningHeadIsReported(t *testing.T) {
	// The title is stamped on every page, so an operator supplied
	// organisation name outside WinAnsi shows markers there. Leaving it out
	// of the report is the silent failure the return value exists to prevent.
	doc := Doc{Blocks: []Block{Paragraph{Text: Text("Nur ASCII im Text.")}}}
	data, subs := render(t, doc, Options{Title: "Bericht Ω GmbH"})
	if len(subs) != 1 || subs[0].Rune != 'Ω' {
		t.Fatalf("the title carried a rune the fonts cannot set and Render reported %v", subs)
	}
	if !bytes.Contains(data, []byte(subs[0].Marker)) {
		t.Errorf("%s is reported but never printed", subs[0].Marker)
	}
}

func TestPageCountAndLabelsAgree(t *testing.T) {
	var blocks []Block
	for i := 0; i < 120; i++ {
		blocks = append(blocks, Paragraph{Text: Text(fmt.Sprintf("Absatz %d. Dieser Text ist lang genug, um mehrere Seiten zu erzwingen und den Seitenumbruch zu prüfen.", i))})
	}
	data, _ := render(t, Doc{Blocks: blocks}, Options{Title: "Lang", Lang: "de"})
	s, err := parsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
	var tree string
	for _, body := range s.objects {
		if bytes.Contains(body, []byte("/Type /Page ")) || bytes.HasSuffix(body, []byte("/Type /Page")) {
			pages++
		}
		if bytes.Contains(body, []byte("/Type /Pages")) {
			tree = string(body)
		}
	}
	if pages < 3 {
		t.Fatalf("expected the document to run to several pages, got %d", pages)
	}
	if !strings.Contains(tree, fmt.Sprintf("/Count %d", pages)) {
		t.Errorf("page tree %s disagrees with the %d page objects present", tree, pages)
	}
	last := fmt.Sprintf("Seite %d von %d", pages, pages)
	if !bytes.Contains(data, []byte(escapeForContent(last))) {
		t.Errorf("the last page is not labelled %q", last)
	}
}

// escapeForContent renders text the way it appears inside a content stream, so
// a test can look for it there.
func escapeForContent(s string) string {
	lit := literal(encode(s, nil))
	return lit[1 : len(lit)-1]
}

func TestBookmarksCoverEveryHeadingAndNestByLevel(t *testing.T) {
	doc := Doc{Blocks: []Block{
		Heading{Level: 1, Text: Text("Title")},
		Heading{Level: 2, Text: Text("One")},
		Heading{Level: 3, Text: Text("One point one")},
		Heading{Level: 3, Text: Text("One point two")},
		Heading{Level: 2, Text: Text("Two")},
	}}
	data, _ := render(t, doc, Options{Title: "x"})
	s, err := parsePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	var root string
	items := 0
	for _, body := range s.objects {
		if bytes.Contains(body, []byte("/Type /Outlines")) {
			root = string(body)
		}
		if bytes.Contains(body, []byte("/Title ")) && bytes.Contains(body, []byte("/Dest [")) {
			items++
		}
	}
	if items != 5 {
		t.Fatalf("expected one bookmark per heading, got %d", items)
	}
	if !strings.Contains(root, "/Count 5") {
		t.Errorf("outline root must count every open descendant, got %s", root)
	}
	if !strings.Contains(string(s.objects[s.root]), "/Outlines") {
		t.Error("the catalog does not reference the outline")
	}
}

func TestOptionsRefuseMarginsThatLeaveNoColumn(t *testing.T) {
	cases := []struct {
		name string
		opt  Options
		want string
	}{
		{"no width", Options{MarginLeft: 290, MarginRight: 290}, "column width"},
		{"no height", Options{MarginTop: 400, MarginBottom: 400}, "page height"},
		{"unreadable body size", Options{BodySize: 0.5}, "body size"},
		{"negative page", Options{Size: PageSize{Width: -1, Height: -1}}, "not a page"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Render(&bytes.Buffer{}, Doc{}, tc.opt)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say what is wrong (%q)", err, tc.want)
			}
		})
	}
}

// A margin field of zero means "unset", and a caller who deliberately wants an
// edge says NoMargin. Reading the two the same way makes an explicit choice
// silently become 56.7 points.
func TestNoMarginIsHonouredAndAnUnsetMarginTakesTheDefault(t *testing.T) {
	tests := []struct {
		name string
		opt  Options
		want [4]float64 // left, right, top, bottom
	}{
		{name: "nothing set", opt: Options{}, want: [4]float64{defaultMarginX, defaultMarginX, defaultMarginY, defaultMarginY}},
		{name: "sides at the edge", opt: Options{MarginLeft: NoMargin, MarginRight: NoMargin}, want: [4]float64{0, 0, defaultMarginY, defaultMarginY}},
		{name: "every edge", opt: Options{MarginLeft: NoMargin, MarginRight: NoMargin, MarginTop: NoMargin, MarginBottom: NoMargin}, want: [4]float64{0, 0, 0, 0}},
		{name: "an explicit value is kept", opt: Options{MarginLeft: 30}, want: [4]float64{30, defaultMarginX, defaultMarginY, defaultMarginY}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			full := tt.opt.withDefaults()
			got := [4]float64{full.MarginLeft, full.MarginRight, full.MarginTop, full.MarginBottom}
			if got != tt.want {
				t.Errorf("margins = %v, want %v", got, tt.want)
			}
		})
	}
}

// The resolved margin has to be where the ink actually lands, not only what
// withDefaults returns.
func TestNoMarginPutsTextAtTheEdgeOfThePage(t *testing.T) {
	doc := Doc{Blocks: []Block{Paragraph{Text: Text("An der Kante.")}}}
	data, _ := render(t, doc, Options{Title: "x", MarginLeft: NoMargin})

	leftmost := math.Inf(1)
	for _, s := range contentStreams(t, data) {
		for _, p := range textOrigins(s) {
			leftmost = math.Min(leftmost, p.x)
		}
	}
	if leftmost != 0 {
		t.Errorf("the leftmost text sits at x=%v, want 0 for an explicit NoMargin", leftmost)
	}
}

// U+00AD has a byte in WinAnsi and the standard fonts draw it as an ordinary
// hyphen. It marks where a line may break, and this layout does not hyphenate,
// so printing it puts a hyphen in the middle of a word nobody wrote.
func TestASoftHyphenIsNotPrintedAsAHyphen(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{name: "soft hyphen", in: "Zusammen­arbeit", want: "Zusammenarbeit"},
		{name: "zero width joiner", in: "a‍b", want: "ab"},
		{name: "a real hyphen is untouched", in: "Zusammen-arbeit", want: "Zusammen-arbeit"},
		{name: "a non-breaking hyphen is still a substitution", in: "a‑b", want: "a[U+2011]b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(encode(tc.in, nil)); got != tc.want {
				t.Errorf("encode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	doc := Doc{Blocks: []Block{Paragraph{Text: Text("Zusammen­arbeit")}}}
	data, subs := render(t, doc, Options{Title: "x"})
	if len(subs) != 0 {
		t.Errorf("a soft hyphen carries nothing to see, so it is not a substitution: %v", subs)
	}
	if bytes.Contains(data, []byte(`\255`)) {
		t.Error("WinAnsi 0xAD is in the content stream, which the standard fonts draw as a visible hyphen")
	}
	if !bytes.Contains(data, []byte(escapeForContent("Zusammenarbeit"))) {
		t.Error("the word around the soft hyphen did not survive")
	}
}

// TestPopplerReadsTheDocument runs the rendered file through whatever real PDF
// tooling this machine has. It is the only check here that is not our own code
// marking its own homework.
func TestPopplerReadsTheDocument(t *testing.T) {
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is not installed, skipping the external reader check")
	}
	data, subs := render(t, sampleDoc(t), Options{Title: "Sample", Lang: "de"})
	path := filepath.Join(t.TempDir(), "sample.pdf")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tool, "-layout", path, "-").Output()
	if err != nil {
		t.Fatalf("%s could not read the document: %v", tool, err)
	}
	t.Logf("validated with %s", tool)

	text := strings.Join(strings.Fields(string(out)), " ")
	want := []string{
		"Technische Dokumentation: Support-Assistent",
		"Nichts davon stellt Konformität her.",
		"„so wie hier zitiert“",
		"Prüfen Sie den Wortlaut",
		"256 – 1024",
		"flugschreiber verify --dir <evidence-directory>",
		"Ansätze, grob nach Praxistauglichkeit",
		"[ ] Der Weg zu einer Person ist benannt",
		"(https://example.invalid/MAPPING.md)",
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("extracted text is missing %q", w)
		}
	}
	// The fixture puts a 64 character hash in a column too narrow for it, so
	// it has to be broken across lines. Every character must still be on the
	// page. Extraction is repeated in content order, because the column
	// layout interleaves the continuation with the neighbouring cells.
	raw, err := exec.Command(tool, "-raw", path, "-").Output()
	if err != nil {
		t.Fatalf("%s could not read the document in content order: %v", tool, err)
	}
	squashed := strings.Join(strings.Fields(string(raw)), "")
	if !strings.Contains(squashed, "b7b7feea6202d55ad35f83ff5c763fa29151c9a450efcecd06b5becd39ead10c") {
		t.Error("a token too wide for its column lost characters instead of being broken")
	}
	for _, s := range subs {
		if !strings.Contains(text, s.Marker) {
			t.Errorf("substitution %s is reported but does not appear in the page", s)
		}
	}
	if strings.Contains(text, "✓") {
		t.Error("a rune the standard fonts cannot set was somehow extracted, the marker should have replaced it")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
