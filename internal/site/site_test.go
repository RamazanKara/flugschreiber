package site

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory to the module root, so
// the tests read the same Markdown the real build does rather than a fixture
// that could drift from it.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the module root")
		}
		dir = parent
	}
}

func build(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	if err := Build(Options{RepoRoot: repoRoot(t), Out: out, Version: "vTEST"}); err != nil {
		t.Fatalf("building the site: %v", err)
	}
	return out
}

// The build is where the link check and the self-contained check live, so a
// green build is most of the guarantee. This pins that it produces a page for
// every document and the landing page.
func TestBuildProducesEveryPage(t *testing.T) {
	out := build(t)
	want := []string{"index.html", "styles.css", ".nojekyll", "favicon.svg", "404.html"}
	for _, p := range Pages {
		want = append(want, p.Slug+".html")
	}
	for _, name := range want {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("the build did not produce %s", name)
		}
	}
}

// The whole argument of the site, and of the product, is that it depends on
// nothing external. A page that loads a font or a script from a CDN breaks that
// argument, so the build refuses it; this is the belt to that suspenders.
func TestNoPageLoadsAnythingExternal(t *testing.T) {
	out := build(t)
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		// An external destination behind a click is fine. An asset that loads
		// with the page is not.
		for _, bad := range []string{`src="http`, `src='http`, `@import`, `url(http`} {
			if strings.Contains(body, bad) {
				t.Errorf("%s loads an external asset (%q)", e.Name(), bad)
			}
		}
		if strings.Contains(body, "<link") && strings.Contains(body, `href="http`) {
			// A stylesheet link to an external host.
			for _, line := range strings.Split(body, "\n") {
				if strings.Contains(line, "<link") && strings.Contains(line, `href="http`) {
					t.Errorf("%s links an external stylesheet: %s", e.Name(), strings.TrimSpace(line))
				}
			}
		}
	}
}

// Every document the site lists must exist in the repository, or the landing
// page advertises a page the build cannot produce.
func TestEveryListedSourceExists(t *testing.T) {
	root := repoRoot(t)
	for _, p := range Pages {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p.Src))); err != nil {
			t.Errorf("the site lists %s but %s is not in the repository", p.Title, p.Src)
		}
	}
}

// A cross-document Markdown link that names another published page must resolve
// to that page on the site, not to a dead .md href. rewriteLinks enforces this;
// the test pins a known cross-reference so a regression is caught here rather
// than by a visitor.
func TestKnownCrossReferenceResolves(t *testing.T) {
	// README links to docs/STABILITY.md, which the site publishes as
	// stability.html; a page rendered from a document that references it should
	// carry the rewritten href.
	rewritten, err := rewriteLinks("see [the contract](docs/STABILITY.md) for details", "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rewritten, "stability.html") {
		t.Errorf("a link to a published document was not rewritten to its page: %q", rewritten)
	}

	// A link to a document that is NOT published falls back to the repository
	// rather than dangling.
	fellBack, err := rewriteLinks("see [the license](LICENSE)", "README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fellBack, "github.com") {
		t.Errorf("a link to an unpublished file did not fall back to the repository: %q", fellBack)
	}
}
