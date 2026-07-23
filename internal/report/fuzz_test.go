package report

import (
	"os"
	"path/filepath"
	"testing"
)

// markdownSeeds are inputs that stress the renderer's escaping and block
// detection: the hostile break-out attempts from TestHostileInputNeverBecomesMarkup,
// executable and protocol-relative link destinations, the fence-info edge cases,
// and a document exercising every block kind. The golden documents are added on
// top of these in FuzzRenderMarkdown.
var markdownSeeds = []string{
	"<script>alert(1)</script>",
	"| Field | Value |\n| --- | --- |\n| Organisation | <img src=x onerror=alert(1)> |",
	"# <svg onload=alert(1)>Acme",
	"The model `<b onmouseover=alert(1)>x</b>` was served.",
	"```\n</code></pre><script>alert(1)</script>\n```",
	"**<iframe src=evil></iframe>**",
	"> **TODO:** name the system <script>alert(1)</script>",
	"- [ ] <object data=evil></object>",
	"<div onclick=\"steal()\">hello</div>",
	`[click](https://example.test/a"onmouseover="alert(1))`,
	`Contact: "><script>alert(1)</script>`,
	"[click](javascript:alert(1))",
	"[click](JaVaScRiPt:alert(1))",
	"[click](data:text/html;base64,PHNjcmlwdD4=)",
	"![alt](javascript:alert(1))",
	"[click](//evil.test/x)",
	`[click](/\evil.test/x)`,
	`[click](\\evil.test\x)`,
	"```go\" onmouseover=\"alert(1)\nx\n```\n",
	"```go><script\nx\n```\n",
	"# T\n\n## A\n\n## A\n\n| x | y |\n| ---: | :--- |\n| 1 | 2 |\n\n- [ ] a\n- [x] b\n\n> **TODO:** something\n",
	"- one\n  - nested a\n    - deeper\n- two\n",
	"> first\n>\n> second\n",
	"Title\n=====\n\nSee the note.[^1]\n\n~~strike~~\n",
	"",
	"#",
	"|",
	"```",
	">",
	"-",
	"\x00\x01\x02",
}

// FuzzRenderMarkdown drives the Markdown-to-HTML renderer with arbitrary bytes.
// It asserts three properties for every input: the renderer never panics, its
// output is a pure function of the input (two renders are byte-identical, the
// property TestRenderMarkdownIsDeterministic checks on fixed input), and no input
// can introduce a tag outside the fixed set the renderer emits itself. That last
// property is the escaping guarantee of TestHostileInputNeverBecomesMarkup
// generalised to all inputs: a break-out into <script> or any other unlisted tag
// in a document that goes to a regulator is a real vulnerability, so it is
// checked here against every byte sequence the fuzzer can produce.
func FuzzRenderMarkdown(f *testing.F) {
	for _, s := range markdownSeeds {
		f.Add([]byte(s))
	}
	if paths, err := filepath.Glob(filepath.Join("testdata", "golden", "*.md")); err == nil {
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}

	f.Fuzz(func(t *testing.T, src []byte) {
		doc := RenderMarkdown(src)
		if again := RenderMarkdown(src); again.Body != doc.Body || again.TitleHTML != doc.TitleHTML {
			t.Fatalf("RenderMarkdown is not deterministic for input %q", src)
		}
		// The title is rendered in front of the body by the page template, so the
		// escaping property has to hold over both halves joined.
		out := doc.TitleHTML + doc.Body
		for _, tag := range tagsIn(out) {
			if !allowedTags[tag] {
				t.Fatalf("RenderMarkdown emitted the tag %q, which no input may introduce\ninput: %q\noutput: %s", tag, src, out)
			}
		}
	})
}
