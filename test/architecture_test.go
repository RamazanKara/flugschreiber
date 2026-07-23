package acceptance_test

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePrefix = "github.com/RamazanKara/flugschreiber/"

// allowedImports is the dependency graph ARCHITECTURE.md documents. A package
// may import less than this, never more. Adding an edge here is an
// architectural decision: make it in ARCHITECTURE.md first, then here.
var allowedImports = map[string][]string{
	"cmd/flugschreiber": {"internal/cli"},
	"cmd/proxyd":        {"internal/cli"},

	// Foundations. Each stands alone so it can be trusted, ported or verified
	// without dragging the rest of the tree behind it.
	"internal/evidence":     {},
	"internal/archive":      {},
	"internal/metrics":      {},
	"internal/pdf":          {},
	"internal/mockupstream": {},
	"internal/version":      {},

	// The domain sits on evidence and nothing else sideways.
	"internal/content": {"internal/evidence"},
	"internal/openai":  {"internal/evidence"},
	"internal/audit":   {"internal/content", "internal/evidence"},
	"internal/custody": {"internal/evidence"},
	"internal/config":  {"internal/content", "internal/evidence"},
	"internal/report":  {"internal/config", "internal/evidence"},

	// Composition layers.
	"internal/proxy": {
		"internal/config", "internal/content", "internal/evidence",
		"internal/metrics", "internal/openai", "internal/version",
	},
	"internal/cli": {
		"internal/archive", "internal/audit", "internal/config",
		"internal/custody", "internal/evidence", "internal/metrics",
		"internal/mockupstream", "internal/pdf", "internal/proxy",
		"internal/report", "internal/version",
	},
}

// TestDependencyGraphMatchesArchitecture fails the build when a package grows
// an import the architecture does not grant it. The two edges that matter most
// carry their own messages, because the generic one undersells them.
func TestDependencyGraphMatchesArchitecture(t *testing.T) {
	out, err := exec.Command("go", "list", "-f",
		`{{.ImportPath}}|{{join .Imports " "}}`, "../cmd/...", "../internal/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	seen := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg, imports, _ := strings.Cut(line, "|")
		short := strings.TrimPrefix(pkg, modulePrefix)
		for _, imp := range strings.Fields(imports) {
			if strings.HasPrefix(imp, modulePrefix) {
				seen[short] = append(seen[short], strings.TrimPrefix(imp, modulePrefix))
			}
		}
		if _, known := allowedImports[short]; !known {
			t.Errorf("package %s is not in the architecture map; add it to ARCHITECTURE.md and then here", short)
		}
	}

	for pkg, imports := range seen {
		allowed := map[string]bool{}
		for _, a := range allowedImports[pkg] {
			allowed[a] = true
		}
		for _, imp := range imports {
			if allowed[imp] {
				continue
			}
			switch {
			case pkg == "internal/evidence":
				t.Errorf("internal/evidence imports %s. The verifier must stay buildable and auditable on its own: "+
					"a regulator checking a chain years from now should read one package, not a tree", imp)
			case pkg == "internal/archive" && imp == "internal/evidence":
				t.Error("internal/archive imports internal/evidence. The dependency points the other way: " +
					"evidence declares the Archiver interface and archive satisfies it structurally")
			default:
				t.Errorf("%s imports %s, which ARCHITECTURE.md does not grant it", pkg, imp)
			}
		}
	}

}

// outwardFacing is the standard-library machinery a foundation package must not
// reach, directly or through anything it imports.
var outwardFacing = []string{"net/http", "os/exec", "net/rpc", "net/smtp", "os/user", "plugin"}

// TestFoundationsHoldNoOutwardFacingMachinery is the invariant behind the
// dependency map rather than a restatement of it.
//
// internal/evidence is what somebody reads to satisfy themselves that a chain
// is intact, possibly years from now and possibly on a machine with no network
// at all. That reading is only as easy as the package's closure is small, and a
// closure is easy to grow by accident: one convenience call to an HTTP
// timestamping authority or a subprocess signing helper, and the package that
// was meant to be readable on its own now drags in a TLS stack. Both of those
// really were proposed; both now live in internal/custody behind an interface,
// which is what this test exists to keep true.
//
// internal/archive is the mirror image. It speaks HTTP by design and must not
// know what evidence is, which the dependency map already checks.
func TestFoundationsHoldNoOutwardFacingMachinery(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../internal/evidence").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	closure := map[string]bool{}
	for _, line := range strings.Fields(string(out)) {
		closure[line] = true
	}
	for _, pkg := range outwardFacing {
		if closure[pkg] {
			t.Errorf("internal/evidence reaches %s. Anything that talks to another process or another host "+
				"belongs in internal/custody, behind an interface evidence declares", pkg)
		}
	}
}
