package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func FuzzLoadFile(f *testing.F) {
	for _, seed := range []string{
		`{}`, `{"mock_upstream":true,"request_timeout":"30s"}`,
		`{"upstreams":[{"name":"local","url":"http://localhost:8000","default":true}]}`,
		`{"request_timeout":9223372036854775807}`, `{"unknown":true}`, `{} {}`, `null`, `{"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		c := Default()
		if err := c.LoadFile(path); err != nil {
			return
		}
		again := Default()
		if err := again.LoadFile(path); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c, again) {
			t.Fatal("configuration parsing is not deterministic")
		}
		_ = c.Validate()
	})
}

func FuzzDuration(f *testing.F) {
	for _, seed := range []string{`"30s"`, `"-1ns"`, `0`, `9223372036854775807`, `null`, `"invalid"`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var d Duration
		if err := json.Unmarshal(data, &d); err != nil {
			return
		}
		encoded, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var again Duration
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
		if d != again {
			t.Fatalf("duration changed from %v to %v", d.Std(), again.Std())
		}
	})
}
