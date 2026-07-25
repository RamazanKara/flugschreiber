package evidence

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// CONTRIBUTING.md makes this a project rule: "Update MAPPING.md in the same
// pull request. A field with no entry there is a field nobody can justify
// keeping." Nothing enforced it, and by 1.0 seven top-level fields and the
// whole content tree had drifted out, including the ones that hold prompts and
// completions. MAPPING.md is what a DPO reads to build a record of processing,
// so the fields missing from it were exactly the ones they most needed.
//
// This is the same shape as the published-schema sync test, and for the same
// reason: a document that has to be updated by hand will not be.
func TestEveryEventFieldHasAMappingEntry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "MAPPING.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	// Fields whose absence is deliberate. Each needs a reason, because the
	// cheap way to pass this test is to add names here.
	exempt := map[string]string{
		"schema_version": "described in the compatibility policy rather than as a mapped field",
	}

	var missing []string
	for _, name := range jsonFieldNames(reflect.TypeOf(Event{})) {
		if _, ok := exempt[name]; ok {
			continue
		}
		// Backticked, which is how every field in the document is written.
		if !strings.Contains(doc, "`"+name+"`") {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these event fields have no entry in MAPPING.md: %s\n"+
			"A field nobody can justify keeping is a field that should not be recorded. Add a row saying what it holds and where the support runs out.",
			strings.Join(missing, ", "))
	}
}

// The content tree is the part that holds personal data, so it is checked by
// name rather than being covered by the sweep above.
func TestTheContentTreeIsMapped(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "MAPPING.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	for _, want := range []string{
		"content.mode", "content.input", "content.output",
		".sha256", ".bytes", ".text", ".messages",
		".redactions", ".truncated", ".ciphertext", "content.encryption",
	} {
		if !strings.Contains(doc, "`"+want+"`") {
			t.Errorf("MAPPING.md has no entry for %s, which is where prompts and completions live", want)
		}
	}
}

// jsonFieldNames returns the json tag names of a struct's exported fields,
// following embedded structs and ignoring anything marked "-".
func jsonFieldNames(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	return out
}
