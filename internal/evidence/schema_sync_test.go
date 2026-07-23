package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// schemaDir is the published JSON Schema directory, served from the project
// site, relative to this package's directory.
const schemaDir = "../../docs/schema"

// schemaFiles are the two published schema documents the structs must match.
var schemaFiles = []string{"record.schema.json", "event.schema.json"}

// TestSchemaMatchesEvidenceStructs is the guard that keeps the published JSON
// Schema in docs/schema from drifting away from the Go types the proxy writes.
// A third party who reimplements the verifier reads those files, so a field
// added to the code but not the schema, or a property left in the schema after
// its field was removed, is a silent lie in the on-disk contract. The test
// reflects the JSON tag names off every evidence struct that appears in a
// record, collects every property name declared anywhere in the two schema
// files, and fails on any name present in one set but not the other.
func TestSchemaMatchesEvidenceStructs(t *testing.T) {
	structFields := jsonTagNames(
		reflect.TypeOf(Event{}),
		reflect.TypeOf(Record{}),
		reflect.TypeOf(ToolCall{}),
		reflect.TypeOf(ToolResult{}),
		reflect.TypeOf(Content{}),
		reflect.TypeOf(ContentEncryption{}),
		reflect.TypeOf(Payload{}),
		reflect.TypeOf(Params{}),
		reflect.TypeOf(Usage{}),
		reflect.TypeOf(Message{}),
	)

	schemaProps := map[string]bool{}
	for _, name := range schemaFiles {
		loadSchemaProperties(t, filepath.Join(schemaDir, name), schemaProps)
	}

	for _, name := range missing(structFields, schemaProps) {
		t.Errorf("field %q exists in an evidence struct but not in the published schema; add it to docs/schema so a third-party verifier sees it", name)
	}
	for _, name := range missing(schemaProps, structFields) {
		t.Errorf("property %q exists in the published schema but not in any evidence struct; the schema and the code have drifted", name)
	}
}

// jsonTagNames collects the wire names from the json tags of every exported
// field across the given struct types. The name is the part of the tag before
// the first comma; fields tagged "-" or with an empty name are skipped, since
// they are never written.
func jsonTagNames(types ...reflect.Type) map[string]bool {
	names := map[string]bool{}
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			names[name] = true
		}
	}
	return names
}

// loadSchemaProperties parses one schema file and records the key of every
// member declared under a "properties" object anywhere in the document, so
// that the Event's own fields and every field of the $defs sub-schemas are
// gathered together. Only keys directly under "properties" are collected, so
// schema keywords such as "type", "$ref" and "required" are never mistaken for
// field names.
func loadSchemaProperties(t *testing.T, path string, into map[string]bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse schema %s: %v", path, err)
	}
	walkProperties(doc, into)
}

// walkProperties descends the parsed schema, adding the immediate keys of every
// "properties" object to into.
func walkProperties(node any, into map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].(map[string]any); ok {
			for name, sub := range props {
				into[name] = true
				walkProperties(sub, into)
			}
		}
		for key, sub := range v {
			if key == "properties" {
				continue // already descended above
			}
			walkProperties(sub, into)
		}
	case []any:
		for _, sub := range v {
			walkProperties(sub, into)
		}
	}
}

// missing returns the sorted names present in have but absent from want.
func missing(have, want map[string]bool) []string {
	var out []string
	for name := range have {
		if !want[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
