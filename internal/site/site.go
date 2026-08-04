// Package site builds the project website from the repository's own Markdown,
// using the same renderer that produces the compliance documents.
//
// The pages reference nothing external: no CDN, no web font, no analytics, no
// third-party script. That is the same rule the generated reports follow, and
// the same posture the product itself takes, so the website makes the argument
// the tool makes. The build fails on a link that resolves nowhere and on any
// external asset reference, because a site that ships broken is worse than a
// build that says so.
package site

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RamazanKara/flugschreiber/internal/report"
)

//go:embed templates
var templateFS embed.FS

// repoURL is where every source link points.
const repoURL = "https://github.com/RamazanKara/flugschreiber"

// Page is one documentation page on the site, rendered from a Markdown file in
// the repository. The Markdown stays the source of truth; the site is a
// rendering of it.
type Page struct {
	Slug  string // output name without extension
	Src   string // repo-relative Markdown path
	Title string // navigation title, used on the landing page index
	Group string // landing page grouping
	Blurb string // one line under the title on the landing page
}

// Pages is the published set, in the order the landing page lists them.
var Pages = []Page{
	{"kubernetes", "docs/tamper-evident-llm-audit-logs-on-kubernetes.md",
		"Audit logs on Kubernetes", "Guides",
		"The full deployment guide: chart, sidecars, network policy, scheduled verification."},
	{"article-12", "docs/ai-act-article-12-logging-for-vllm-and-ollama.md",
		"Article 12 logging for vLLM and Ollama", "Guides",
		"What record-keeping asks for, and how the proxy provides it in front of your model server."},
	{"annex-iv", "docs/annex-iv-technical-documentation-generator.md",
		"The Annex IV generator", "Guides",
		"How the technical documentation skeleton is produced from observed traffic."},

	{"mapping", "MAPPING.md",
		"Field mapping", "Reference",
		"Every recorded field, mapped to the AI Act provision it supports."},
	{"schema", "docs/SCHEMA.md",
		"Log format", "Reference",
		"The on-disk format, the hash construction, and the compatibility policy."},
	{"verifying", "docs/VERIFYING.md",
		"Verify it yourself", "Reference",
		"The whole format, and a reference verifier you can reimplement in any language."},
	{"backup", "docs/BACKUP.md",
		"Backup and restore", "Reference",
		"What to back up, how to restore it, and the result that looks alarming and is not."},
	{"stability", "docs/STABILITY.md",
		"Stability contract", "Reference",
		"What the command line promises: commands, flags, exit codes, JSON shapes."},
	{"security", "SECURITY.md",
		"Security model", "Reference",
		"The guarantees, the trust boundaries, and the hardening checklist."},

	{"architecture", "ARCHITECTURE.md",
		"Architecture", "Project",
		"The package map and the invariants, each enforced by a test."},
	{"decisions", "DECISIONS.md",
		"Decisions", "Project",
		"Why things are the way they are, one numbered entry per decision."},
	{"changelog", "CHANGELOG.md",
		"Changelog", "Project",
		"Every release, and what it shipped."},
	{"roadmap", "ROADMAP.md",
		"Roadmap", "Project",
		"What has shipped, what is out of scope, and what is queued."},
	{"contributing", "CONTRIBUTING.md",
		"Contributing", "Project",
		"How to work on Flugschreiber, and what a change needs to land."},
}

// Options configures a build.
type Options struct {
	// RepoRoot is the repository checkout the Markdown is read from.
	RepoRoot string
	// Out is the directory the site is written into. It is created if absent.
	Out string
	// Version overrides the release shown in the footer. Empty means the
	// newest entry in CHANGELOG.md, so the site always names a real release.
	Version string
}

// Build writes the whole site.
func Build(opts Options) error {
	if opts.RepoRoot == "" {
		opts.RepoRoot = "."
	}
	if opts.Out == "" {
		return fmt.Errorf("site: an output directory is required")
	}
	version := opts.Version
	if version == "" {
		v, err := versionFromChangelog(filepath.Join(opts.RepoRoot, "CHANGELOG.md"))
		if err != nil {
			return err
		}
		version = v
	}
	if err := os.MkdirAll(opts.Out, 0o755); err != nil {
		return err
	}

	tmpl, err := template.New("").Funcs(template.FuncMap{
		// dict lets a page pass named values into the shared head and foot
		// templates, which Go's template package cannot do otherwise.
		"dict": func(pairs ...any) (map[string]any, error) {
			if len(pairs)%2 != 0 {
				return nil, fmt.Errorf("dict needs an even number of arguments")
			}
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i < len(pairs); i += 2 {
				key, ok := pairs[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				m[key] = pairs[i+1]
			}
			return m, nil
		},
	}).ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		return fmt.Errorf("site: parse templates: %w", err)
	}

	if err := writeStatic(opts.Out); err != nil {
		return err
	}
	if err := copyAssets(opts.RepoRoot, opts.Out); err != nil {
		return err
	}
	if err := renderIndex(tmpl, opts.Out, version); err != nil {
		return err
	}
	for _, p := range Pages {
		if err := renderPage(tmpl, opts, p, version); err != nil {
			return err
		}
	}
	if err := checkLinks(opts.Out); err != nil {
		return err
	}
	return checkSelfContained(opts.Out)
}

// versionFromChangelog returns the newest release heading, for the footer.
var releaseHeading = regexp.MustCompile(`(?m)^## (v\d+\.\d+\.\d+)`)

func versionFromChangelog(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("site: read changelog: %w", err)
	}
	m := releaseHeading.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("site: no release heading in %s", path)
	}
	return string(m[1]), nil
}

type indexData struct {
	Version string
	Repo    string
	Groups  []indexGroup
}

type indexGroup struct {
	Name  string
	Pages []Page
}

func renderIndex(tmpl *template.Template, out, version string) error {
	var groups []indexGroup
	for _, p := range Pages {
		if len(groups) == 0 || groups[len(groups)-1].Name != p.Group {
			groups = append(groups, indexGroup{Name: p.Group})
		}
		g := &groups[len(groups)-1]
		g.Pages = append(g.Pages, p)
	}
	return renderTo(tmpl, "index.html.tmpl", filepath.Join(out, "index.html"), indexData{
		Version: version,
		Repo:    repoURL,
		Groups:  groups,
	})
}

type docData struct {
	Title     string
	Version   string
	Repo      string
	Src       string
	TitleHTML template.HTML
	Body      template.HTML
	TOC       []report.Heading
}

func renderPage(tmpl *template.Template, opts Options, p Page, version string) error {
	raw, err := os.ReadFile(filepath.Join(opts.RepoRoot, filepath.FromSlash(p.Src)))
	if err != nil {
		return fmt.Errorf("site: read %s: %w", p.Src, err)
	}
	md, err := rewriteLinks(string(raw), p.Src)
	if err != nil {
		return err
	}
	doc := report.RenderMarkdown([]byte(md))

	title := doc.Title
	if title == "" {
		title = p.Title
	}
	var toc []report.Heading
	for _, h := range doc.Headings {
		if h.Level == 2 {
			toc = append(toc, h)
		}
	}
	if len(toc) < 4 {
		toc = nil
	}
	return renderTo(tmpl, "doc.html.tmpl", filepath.Join(opts.Out, p.Slug+".html"), docData{
		Title:   title,
		Version: version,
		Repo:    repoURL,
		Src:     p.Src,
		// Safe for the same reason the report pages are: RenderMarkdown
		// escapes every byte of document text and emits only the fixed tag
		// set it constructs itself.
		TitleHTML: template.HTML(doc.TitleHTML),
		Body:      template.HTML(doc.Body),
		TOC:       toc,
	})
}

func renderTo(tmpl *template.Template, name, dst string, data any) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if err := tmpl.ExecuteTemplate(f, name, data); err != nil {
		f.Close()
		return fmt.Errorf("site: render %s: %w", dst, err)
	}
	return f.Close()
}

// mdLink matches a Markdown link destination. Destinations never contain
// spaces in this repository's documents.
var mdLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// rewriteLinks maps repository-relative Markdown links onto site pages, so the
// documents cross-reference each other on the site exactly as they do in the
// repository. A Markdown link with no page on the site is a build error rather
// than a broken link a visitor finds first.
func rewriteLinks(md, src string) (string, error) {
	slugs := map[string]string{"README.md": "./"}
	for _, p := range Pages {
		slugs[path.Base(p.Src)] = p.Slug + ".html"
	}

	var bad []string
	out := mdLink.ReplaceAllStringFunc(md, func(m string) string {
		target := m[2 : len(m)-1]
		dest, frag, _ := strings.Cut(target, "#")
		if frag != "" {
			frag = "#" + frag
		}
		switch {
		case dest == "" || strings.HasPrefix(target, "http://") ||
			strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "mailto:"):
			return m
		case strings.HasSuffix(dest, ".md"):
			if slug, ok := slugs[path.Base(dest)]; ok {
				return "](" + slug + frag + ")"
			}
			bad = append(bad, src+" links "+target)
			return m
		case strings.Contains(dest, "schema/") && strings.HasSuffix(dest, ".json"):
			return "](schema/" + path.Base(dest) + frag + ")"
		case path.Base(dest) == "LICENSE":
			return "](" + repoURL + "/blob/main/LICENSE)"
		default:
			// A repository path with no rendering on the site reads best at
			// the source.
			return "](" + repoURL + "/blob/main/" + strings.TrimPrefix(dest, "./") + frag + ")"
		}
	})
	if len(bad) > 0 {
		return "", fmt.Errorf("site: markdown links with no page on the site: %s", strings.Join(bad, "; "))
	}
	return out, nil
}

// copyAssets brings the demo recording and the published JSON Schemas over.
func copyAssets(root, out string) error {
	copies := map[string]string{
		"docs/media/demo.gif":            "media/demo.gif",
		"docs/media/demo.mp4":            "media/demo.mp4",
		"docs/schema/record.schema.json": "schema/record.schema.json",
		"docs/schema/event.schema.json":  "schema/event.schema.json",
	}
	for src, dst := range copies {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(src)))
		if err != nil {
			return fmt.Errorf("site: read asset %s: %w", src, err)
		}
		full := filepath.Join(out, filepath.FromSlash(dst))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// writeStatic writes the stylesheet, the favicon and the plumbing files.
func writeStatic(out string) error {
	css, err := templateFS.ReadFile("templates/styles.css")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"styles.css": css,
		// GitHub Pages runs Jekyll unless told otherwise, and Jekyll drops
		// files it does not recognise.
		".nojekyll":   {},
		"favicon.svg": []byte(faviconSVG),
		"404.html":    []byte(notFoundHTML),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(out, name), body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// faviconSVG is the recorder mark: international orange, the paint colour of
// the instrument the product is named after.
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">` +
	`<rect width="64" height="64" rx="10" fill="#ff4f00"/>` +
	`<rect x="14" y="30" width="36" height="5" fill="#141414"/>` +
	`<rect x="14" y="40" width="24" height="5" fill="#141414"/>` +
	`<rect x="14" y="20" width="30" height="5" fill="#141414"/>` +
	`</svg>` + "\n"

const notFoundHTML = `<!doctype html><meta charset="utf-8">` +
	`<meta http-equiv="refresh" content="0; url=./">` +
	`<title>Flugschreiber</title>` +
	`<p>This page moved. <a href="./">Continue to Flugschreiber</a>.</p>` + "\n"

// hrefAttr finds link and asset references in the emitted HTML.
var hrefAttr = regexp.MustCompile(`(?:href|src)="([^"]+)"`)

// checkLinks fails the build when a page references a file that is not in the
// output.
func checkLinks(out string) error {
	entries, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	var bad []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			return err
		}
		for _, m := range hrefAttr.FindAllStringSubmatch(string(raw), -1) {
			target := m[1]
			dest, _, _ := strings.Cut(target, "#")
			switch {
			case dest == "", strings.HasPrefix(dest, "http://"),
				strings.HasPrefix(dest, "https://"), strings.HasPrefix(dest, "mailto:"),
				strings.HasPrefix(dest, "data:"):
				continue
			}
			dest = strings.TrimSuffix(dest, "/")
			if dest == "." || dest == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(dest))); err != nil {
				bad = append(bad, e.Name()+" references "+target)
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("site: references with no target in the output: %s", strings.Join(bad, "; "))
	}
	return nil
}

// checkSelfContained fails the build when a page would make an external
// request. External destinations behind an explicit click are fine; assets
// that load with the page are not.
func checkSelfContained(out string) error {
	entries, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	external := regexp.MustCompile(`(?:src|<link[^>]*href)="https?://`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			return err
		}
		if external.Match(raw) {
			return fmt.Errorf("site: %s loads an external asset, and the pages reference nothing external", e.Name())
		}
	}
	return nil
}
