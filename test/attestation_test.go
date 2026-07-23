package acceptance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type verifyJSON struct {
	Records             uint64 `json:"records"`
	Checkpoints         int    `json:"checkpoints"`
	CheckpointsVerified int    `json:"checkpoints_verified"`
	Attested            bool   `json:"attested"`
	KeyID               string `json:"key_id"`
	Pruned              bool   `json:"pruned"`
	Problems            []struct {
		Kind     string `json:"kind"`
		Severity string `json:"severity"`
		Detail   string `json:"detail"`
	} `json:"problems"`
}

func verifyAsJSON(t *testing.T, bin, dir string) verifyJSON {
	t.Helper()
	out, _ := run(t, bin, "verify", "--dir", dir, "--json")
	var v verifyJSON
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("verify --json did not emit JSON: %v\n%s", err, out)
	}
	return v
}

// TestSignedCheckpointsAttestTheChain covers the M2 promise: the log is not
// merely self-consistent, it is attested by a key, and rewriting it without that
// key leaves evidence of the rewrite behind.
func TestSignedCheckpointsAttestTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test builds and runs the binary")
	}

	bin := buildBinary(t)
	work := t.TempDir()
	dataDir := filepath.Join(work, "evidence")
	addr := freeAddr(t)

	proc := startServe(t, bin,
		"--mock-upstream", "--data-dir", dataDir, "--listen", addr,
		"--checkpoint-interval", "1s")
	waitHealthy(t, "http://"+addr+"/healthz")

	for i := 0; i < 3; i++ {
		postJSON(t, "http://"+addr+"/v1/chat/completions", map[string]any{
			"model":    "llama-3.1-8b",
			"messages": []any{msg("user", "hello")},
		})
	}
	// A clean shutdown always writes a checkpoint, so the test does not have to
	// wait on the timer.
	stopServe(t, proc)

	t.Run("keys are created with the right shape and permissions", func(t *testing.T) {
		priv := filepath.Join(dataDir, "signing-key.pem")
		info, err := os.Stat(priv)
		if err != nil {
			t.Fatalf("no signing key was created: %v", err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("signing key mode is %04o; it must not be group or world readable", mode)
		}
		body, err := os.ReadFile(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "BEGIN PRIVATE KEY") {
			t.Errorf("signing key is not a PKCS#8 PEM block:\n%s", body)
		}

		pub, err := os.ReadFile(filepath.Join(dataDir, "public-key.pem"))
		if err != nil {
			t.Fatalf("no public key was created: %v", err)
		}
		if !strings.Contains(string(pub), "BEGIN PUBLIC KEY") {
			t.Errorf("public key is not a PKIX PEM block:\n%s", pub)
		}
	})

	t.Run("verify reports the chain as attested", func(t *testing.T) {
		v := verifyAsJSON(t, bin, dataDir)
		if v.Records != 3 {
			t.Fatalf("Records = %d, want 3", v.Records)
		}
		if v.Checkpoints == 0 {
			t.Fatal("no checkpoints were written")
		}
		if v.CheckpointsVerified != v.Checkpoints {
			t.Errorf("%d of %d checkpoints verified", v.CheckpointsVerified, v.Checkpoints)
		}
		if !v.Attested {
			t.Error("Attested = false despite verified checkpoints")
		}
		if v.KeyID == "" {
			t.Error("no key id reported")
		}
		if len(v.Problems) != 0 {
			t.Errorf("problems on a clean log: %+v", v.Problems)
		}
	})

	// The decisive M2 property. An attacker who rewrites the log but does not
	// hold the signing key can produce a chain that is internally consistent.
	// The checkpoint still attests to the original head, so the two disagree.
	t.Run("a rewritten chain contradicts its own checkpoints", func(t *testing.T) {
		rewritten := filepath.Join(work, "rewritten")
		copyDir(t, dataDir, rewritten)

		// Rebuild the whole chain around an edited record, exactly as an
		// attacker with write access but no key would have to. The edit targets
		// the status code rather than the prompt, because the default content
		// mode records a digest of the prompt and not its text.
		seg := filepath.Join(rewritten, "seg-00000001.jsonl")
		changed, err := rechain(seg, `"status":200`, `"status":403`)
		if err != nil {
			t.Fatalf("could not rebuild the chain: %v", err)
		}
		if changed == 0 {
			t.Fatal("the rewrite changed nothing, so this test proves nothing")
		}

		out, verr := run(t, bin, "verify", "--dir", rewritten)
		if verr == nil {
			t.Fatalf("a rewritten log verified cleanly:\n%s", out)
		}

		v := verifyAsJSON(t, bin, rewritten)
		var sawMismatch bool
		for _, p := range v.Problems {
			if p.Kind == "checkpoint_mismatch" {
				sawMismatch = true
				if p.Severity != "high" {
					t.Errorf("checkpoint_mismatch severity = %q, want high", p.Severity)
				}
			}
			if p.Kind == "hash_mismatch" || p.Kind == "broken_link" {
				t.Errorf("the rewrite was not internally consistent, so this test is not testing what it claims: %+v", p)
			}
		}
		if !sawMismatch {
			t.Errorf("a consistent rewrite was not caught by the checkpoints: %+v", v.Problems)
		}
	})

	t.Run("removing the public key does not silently disable checking", func(t *testing.T) {
		stripped := filepath.Join(work, "stripped")
		copyDir(t, dataDir, stripped)
		if err := os.Remove(filepath.Join(stripped, "public-key.pem")); err != nil {
			t.Fatal(err)
		}

		v := verifyAsJSON(t, bin, stripped)
		if v.Attested {
			t.Error("Attested = true with no public key present")
		}
	})
}

// rechain rewrites every record in a segment so the chain is internally
// consistent after an edit. It is the attacker's job, done here so the test can
// prove the checkpoints catch what the chain alone cannot.
func rechain(path, from, to string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	const genesis = "0000000000000000000000000000000000000000000000000000000000000000"
	prev := genesis

	var out []string
	var changed int
	for _, line := range lines {
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return 0, err
		}

		event := string(rec["event"])
		if strings.Contains(event, from) {
			event = strings.ReplaceAll(event, from, to)
			changed++
		}
		rec["event"] = json.RawMessage(event)
		rec["prev_hash"] = mustJSON(prev)

		var seq uint64
		var ts string
		json.Unmarshal(rec["seq"], &seq)
		json.Unmarshal(rec["timestamp"], &ts)

		hash := recordHash(seq, ts, prev, []byte(event))
		rec["record_hash"] = mustJSON(hash)
		prev = hash

		// Field order in the file does not matter to the verifier, which parses
		// the JSON rather than the bytes.
		encoded, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		out = append(out, string(encoded))
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	return changed, nil
}

func mustJSON(s string) json.RawMessage {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return b
}

// recordHash reimplements the record preimage from docs/SCHEMA.md rather than
// calling the package that produces it. If the two ever disagree, either the
// implementation drifted or the published spec is wrong, and both are worth
// failing a build over: the spec is what a regulator's own verifier would be
// written against.
func recordHash(seq uint64, timestamp, prevHash string, event []byte) string {
	eventDigest := sha256.Sum256(event)

	preimage := "flugschreiber-record-v1\n" +
		"seq:" + strconv.FormatUint(seq, 10) + "\n" +
		"ts:" + timestamp + "\n" +
		"prev:" + prevHash + "\n" +
		"event:" + hex.EncodeToString(eventDigest[:]) + "\n"

	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:])
}
