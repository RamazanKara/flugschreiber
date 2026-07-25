package proxy

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamazanKara/flugschreiber/internal/config"
	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// A salt that changes silently turns one caller into several actors, and every
// record on both sides of the change is internally consistent, so the chain
// cannot reveal it. A short file used to read as an absent one.
func TestADamagedSaltIsRefusedRatherThanReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client-salt")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadOrCreateSalt(dir)
	if err == nil {
		t.Fatal("a truncated salt was silently replaced, giving every existing caller a new identity")
	}
	if !strings.Contains(err.Error(), "new identity") {
		t.Errorf("the refusal does not explain the consequence: %v", err)
	}

	// And the bytes are untouched, so a restore from backup is still possible.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "too short" {
		t.Error("the damaged salt was overwritten despite the refusal")
	}
}

// The same credential must hash the same way across restarts, which is the
// whole basis of the client_hash row in MAPPING.md.
func TestTheSaltSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, created, err := loadOrCreateSalt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("the first call did not report creating the salt")
	}
	second, created, err := loadOrCreateSalt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("the second call created a salt although one was already there")
	}
	if string(first) != string(second) {
		t.Fatal("the salt changed across a restart, so one caller becomes two actors")
	}
}

// Losing the salt on a directory that already holds records is the dangerous
// case, and the chain has to carry the boundary.
func TestANewSaltOverAnExistingLogIsRecordedInTheChain(t *testing.T) {
	h := newHarness(t, mockHandler(), nil)
	h.postAndDrain("/v1/chat/completions",
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`, nil)
	events := h.events()
	if len(events) == 0 {
		t.Fatal("nothing was recorded")
	}
	dir := h.dataDir

	// The salt goes missing, as it does on a restore from a bundle, which never
	// carries it.
	if err := os.Remove(filepath.Join(dir, "client-salt")); err != nil {
		t.Fatal(err)
	}

	store, err := evidence.Open(evidence.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.MockUpstream = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, store, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var marked bool
	if err := evidence.Walk(dir, func(e evidence.Entry) error {
		if e.Event.EventType == evidence.EventConfigChange &&
			strings.Contains(e.Event.Note, "new client salt") {
			marked = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !marked {
		t.Error("a new salt over an existing log left no boundary in the chain, so client_hash is silently incomparable across it")
	}
}
