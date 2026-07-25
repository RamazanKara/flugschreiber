package custody

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// The exec signer is driven by running this test binary again in helper mode,
// which is how the standard library tests os/exec. It keeps the test honest,
// a real process really is started and really answers over a pipe, without
// needing a shell script that would not run on every platform CI covers.
//
// The two variables sit outside the FLUGSCHREIBER_ prefix on purpose: the
// signer strips that prefix from the helper's environment, so a helper
// configured through it would never see them. The stripping has its own test.
const (
	execHelperKeyEnv  = "CUSTODY_TEST_SIGNER_KEY"
	execHelperModeEnv = "CUSTODY_TEST_SIGNER_MODE"
)

// TestExecSignerHelperProcess is not a test. When the environment names a key
// it is the signing helper the exec signer tests run: it reads a preimage from
// standard input and answers on standard output, in the shape the mode asks
// for. It exits before the testing framework can print anything, so standard
// output carries the signature and nothing else.
func TestExecSignerHelperProcess(t *testing.T) {
	keyHex := os.Getenv(execHelperKeyEnv)
	if keyHex == "" {
		t.Skip("not a test: this is the signing helper the exec signer tests run")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		os.Stderr.WriteString("helper: bad key\n")
		os.Exit(2)
	}
	preimage, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Stderr.WriteString("helper: cannot read stdin\n")
		os.Exit(2)
	}

	switch os.Getenv(execHelperModeEnv) {
	case "fail":
		os.Stderr.WriteString("smartcard reports: no key on slot 3\n")
		os.Exit(1)
	case "garbage":
		os.Stdout.WriteString("Signature: none, sorry\n")
	case "wrongkey":
		_, other, err := ed25519.GenerateKey(nil)
		if err != nil {
			os.Exit(2)
		}
		os.Stdout.WriteString(hex.EncodeToString(ed25519.Sign(other, preimage)))
	case "env":
		// The helper refuses to sign if it can read the proxy's own
		// configuration, which turns a leak into a failed signature rather
		// than into something only a reviewer would notice.
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "FLUGSCHREIBER_") {
				name, _, _ := strings.Cut(kv, "=")
				os.Stderr.WriteString("the helper can read " + name + "\n")
				os.Exit(3)
			}
		}
		os.Stdout.WriteString(hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), preimage)))
	case "raw":
		os.Stdout.Write(ed25519.Sign(ed25519.PrivateKey(key), preimage))
	default:
		os.Stdout.WriteString(hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), preimage)) + "\n")
	}
	os.Exit(0)
}

// writePublicKeyPEM writes the public half where an operator would keep it,
// through the standard library rather than through an evidence helper, so that
// the test proves the signer reads an ordinary PKIX file.
func writePublicKeyPEM(t *testing.T, path string, pub ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o644); err != nil {
		t.Fatal(err)
	}
}

// execSignerFor returns a signer that runs this binary in helper mode, holding
// the private half of kp, with the public half written where an operator would
// keep it.
func execSignerFor(t *testing.T, kp *evidence.KeyPair, mode string) evidence.Signer {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t") {
		t.Skip("the exec signer splits its command on whitespace, and this binary's path contains some")
	}

	pubPath := filepath.Join(t.TempDir(), "helper-public-key.pem")
	writePublicKeyPEM(t, pubPath, kp.Public)
	t.Setenv(execHelperKeyEnv, hex.EncodeToString(kp.Private))
	t.Setenv(execHelperModeEnv, mode)

	signer, err := NewExecSigner(exe+" -test.run=TestExecSignerHelperProcess", pubPath)
	if err != nil {
		t.Fatalf("NewExecSigner: %v", err)
	}
	return signer
}

// externalKey generates a key that never touches the evidence directory, which
// is the whole point of signing through a helper.
func externalKey(t *testing.T) *evidence.KeyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &evidence.KeyPair{Private: priv, Public: pub, ID: evidence.KeyID(pub)}
}

// fixedClock advances a step per call, so records are ordered and the test does
// not depend on the host clock.
func fixedClock() func() time.Time {
	base := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	var n int64
	return func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Millisecond)
	}
}

func appendN(t *testing.T, s *evidence.Store, n int) {
	t.Helper()
	for i := range n {
		err := s.Append(&evidence.Event{
			EventType: evidence.EventInference,
			RequestID: fmt.Sprintf("req-%03d", i),
			Endpoint:  "/v1/chat/completions",
			Status:    200,
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func sampleCheckpoint() evidence.Checkpoint {
	return evidence.Checkpoint{
		Version:    evidence.CheckpointVersion,
		Segment:    "seg-00000002.jsonl",
		Seq:        42,
		RecordHash: strings.Repeat("ab", 32),
		Records:    42,
		Timestamp:  "2026-03-01T12:00:00Z",
		KeyID:      "0123456789abcdef",
	}
}

// Moving custody off the host must not change the evidence. A chain signed
// through a helper has to verify with the ordinary verifier, against the
// ordinary public key file, with nothing else supplied.
func TestChainSignedThroughAHelperVerifiesUnchanged(t *testing.T) {
	for _, mode := range []string{"hex", "raw"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			kp := externalKey(t)
			signer := execSignerFor(t, kp, mode)

			s, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SegmentMaxBytes: 400, Now: fixedClock()})
			if err != nil {
				t.Fatal(err)
			}
			appendN(t, s, 12)
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// The private key never entered this directory, but the public half
			// has to, or nobody holding the log could check it.
			if _, err := os.Stat(filepath.Join(dir, evidence.SigningKeyFile)); !os.IsNotExist(err) {
				t.Errorf("a private key appeared in the evidence directory: %v", err)
			}
			onDisk, err := evidence.LoadPublicKeyPEM(filepath.Join(dir, evidence.PublicKeyFile))
			if err != nil {
				t.Fatalf("the helper's public key did not reach the evidence directory: %v", err)
			}
			if !onDisk.Equal(kp.Public) {
				t.Error("the public key in the evidence directory is not the helper's")
			}

			checks, err := evidence.ReadCheckpoints(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(checks) == 0 {
				t.Fatal("signing through a helper produced no checkpoints")
			}
			for _, c := range checks {
				if c.KeyID != kp.ID {
					t.Errorf("checkpoint at seq %d is attributed to %s, want %s", c.Seq, c.KeyID, kp.ID)
				}
			}

			res, err := evidence.Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK() {
				t.Fatalf("a helper-signed log did not verify: %v", res.Problems)
			}
			if !res.Attested || res.CheckpointsVerified != len(checks) {
				t.Errorf("Attested = %v with %d of %d checkpoints verified", res.Attested, res.CheckpointsVerified, len(checks))
			}
		})
	}
}

// The contract is that the checkpoint is byte-identical whoever holds the key.
// Ed25519 is deterministic, so the two signers must produce the same bytes.
func TestFileSignerAndHelperProduceTheSameSignature(t *testing.T) {
	kp := externalKey(t)
	helper := execSignerFor(t, kp, "hex")

	viaFile := sampleCheckpoint()
	if err := evidence.SignCheckpointWith(evidence.NewKeyPairSigner(kp), &viaFile); err != nil {
		t.Fatal(err)
	}
	viaHelper := sampleCheckpoint()
	if err := evidence.SignCheckpointWith(helper, &viaHelper); err != nil {
		t.Fatal(err)
	}

	if viaFile.Signature != viaHelper.Signature {
		t.Errorf("the same key signed the same checkpoint differently:\n file: %s\nhelper: %s", viaFile.Signature, viaHelper.Signature)
	}
	if viaFile.KeyID != viaHelper.KeyID {
		t.Errorf("key id differs: %s and %s", viaFile.KeyID, viaHelper.KeyID)
	}
	if err := evidence.VerifyCheckpointSignature(kp.Public, viaHelper); err != nil {
		t.Errorf("the helper's checkpoint does not verify: %v", err)
	}
}

// A signing failure is a store error and never a dropped record. The proxy has
// already served the traffic these records describe; losing them because a
// smartcard was unplugged would be the worst possible trade.
func TestAFailingHelperCostsCheckpointsNeverRecords(t *testing.T) {
	dir := t.TempDir()
	kp := externalKey(t)
	signer := execSignerFor(t, kp, "fail")

	s, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 5)
	if err := s.Close(); err == nil {
		t.Fatal("a failing signer was not reported as a store error")
	} else if !strings.Contains(err.Error(), "no key on slot 3") {
		t.Errorf("the error does not quote what the helper reported: %v", err)
	}

	if s.Appended() != 5 {
		t.Errorf("Appended = %d, want 5", s.Appended())
	}
	res, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 5 {
		t.Errorf("Records = %d, want 5: a signing failure cost evidence", res.Records)
	}
	for _, p := range res.Problems {
		if p.Kind != evidence.ProblemBadCheckpoint {
			t.Errorf("the chain itself is damaged: %v", p)
		}
	}
	if res.Checkpoints != 0 {
		t.Errorf("Checkpoints = %d, want 0: an unsigned checkpoint was written anyway", res.Checkpoints)
	}
}

// The dangerous moment for a failing signer is a segment rotation, because the
// old segment is closed before the checkpoint is signed. Abandoning the
// rotation there would leave the writer with no open segment, so a helper that
// stopped answering would cost not one checkpoint but every record after it.
func TestAHelperThatFailsAtASegmentRotationStillCostsNoRecords(t *testing.T) {
	dir := t.TempDir()
	kp := externalKey(t)
	signer := execSignerFor(t, kp, "fail")

	// Small enough that appending 12 records rotates the segment several times,
	// so the signer fails while the sealed segment is being attested to.
	s, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SegmentMaxBytes: 400, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 12)
	err = s.Close()
	if err == nil {
		t.Fatal("a failing signer was not reported as a store error")
	}
	if !strings.Contains(err.Error(), "no key on slot 3") {
		t.Errorf("the error does not say the signer failed: %v", err)
	}
	if s.Appended() != 12 {
		t.Errorf("Appended = %d, want 12", s.Appended())
	}

	res, err := evidence.Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 12 {
		t.Errorf("Records = %d, want 12: a signing failure at a rotation cost evidence", res.Records)
	}
	if !res.OK() {
		t.Errorf("the chain itself is damaged: %v", res.Problems)
	}
}

// A helper wired to the wrong key produces a signature that is well formed and
// worthless. Catching it at the moment it happens is the difference between a
// misconfiguration found in testing and one found in an audit.
func TestHelperSigningWithTheWrongKeyIsRefused(t *testing.T) {
	kp := externalKey(t)
	signer := execSignerFor(t, kp, "wrongkey")

	c := sampleCheckpoint()
	err := evidence.SignCheckpointWith(signer, &c)
	if err == nil {
		t.Fatal("a signature made with a different key was accepted")
	}
	if !strings.Contains(err.Error(), kp.ID) {
		t.Errorf("the error does not name the key that was expected: %v", err)
	}
	if c.Signature != "" {
		t.Error("the checkpoint carries a signature although signing failed")
	}
}

func TestHelperThatAnswersWithNonsenseIsRefused(t *testing.T) {
	kp := externalKey(t)
	signer := execSignerFor(t, kp, "garbage")

	c := sampleCheckpoint()
	if err := evidence.SignCheckpointWith(signer, &c); err == nil {
		t.Fatal("a helper that wrote prose instead of a signature was accepted")
	}
}

func TestNewExecSignerRefusesAnUnusableConfiguration(t *testing.T) {
	pubPath := filepath.Join(t.TempDir(), evidence.PublicKeyFile)
	kp := externalKey(t)
	writePublicKeyPEM(t, pubPath, kp.Public)

	cases := []struct {
		name    string
		command string
		pubPath string
	}{
		{"no command", "", pubPath},
		{"no public key", "/bin/true", ""},
		{"command that does not exist", filepath.Join(t.TempDir(), "no-such-helper"), pubPath},
		{"public key that does not exist", "/bin/true", filepath.Join(t.TempDir(), "absent.pem")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewExecSigner(tc.command, tc.pubPath); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The helper holds the signing key, which does not make it entitled to the
// upstream API key, the events token or the archive credentials. Handing a
// process a secret it has no use for is how secrets end up somewhere nobody
// meant them to be.
func TestTheHelperNeverSeesTheProxysOwnCredentials(t *testing.T) {
	t.Setenv("FLUGSCHREIBER_UPSTREAM_API_KEY", "sk-this-must-not-reach-the-helper")
	t.Setenv("FLUGSCHREIBER_EVENTS_TOKEN", "nor-this")
	// The archive credentials arrive under the standard AWS names, which is
	// what the chart injects and what internal/archive reads. Setting only the
	// prefixed variables is why this test passed while the claim was false.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-must-not-reach-the-helper")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "nor-this-either")
	t.Setenv("AWS_SESSION_TOKEN", "nor-this")

	kp := externalKey(t)
	signer := execSignerFor(t, kp, "env")

	c := sampleCheckpoint()
	if err := evidence.SignCheckpointWith(signer, &c); err != nil {
		t.Fatalf("the signing helper was handed this process's configuration: %v", err)
	}
	if err := evidence.VerifyCheckpointSignature(kp.Public, c); err != nil {
		t.Errorf("the checkpoint does not verify: %v", err)
	}
}

// A helper that reaches its key through a cloud service needs a credential this
// package strips by default, so the operator can name it. Guessing that a
// helper needs everything is how the archive credentials leaked in the first
// place; guessing it needs nothing would make an HSM behind KMS unusable.
func TestAHelperCanBeGivenNamedVariablesDeliberately(t *testing.T) {
	kp := externalKey(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(exe, " \t") {
		t.Skip("the exec signer splits its command on whitespace")
	}
	pubPath := filepath.Join(t.TempDir(), "pub.pem")
	writePublicKeyPEM(t, pubPath, kp.Public)

	t.Setenv(execHelperKeyEnv, hex.EncodeToString(kp.Private))
	t.Setenv(execHelperModeEnv, "hex")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-deliberate")

	signer, err := NewExecSignerWithEnv(exe+" -test.run=TestExecSignerHelperProcess", pubPath,
		[]string{"AWS_ACCESS_KEY_ID"})
	if err != nil {
		t.Fatal(err)
	}
	c := sampleCheckpoint()
	if err := evidence.SignCheckpointWith(signer, &c); err != nil {
		t.Fatalf("a helper given a named variable could not sign: %v", err)
	}

	// And the passthrough is exactly what was named, not a door held open.
	env := helperEnv([]string{
		"AWS_ACCESS_KEY_ID=yes",
		"AWS_SECRET_ACCESS_KEY=no",
		"FLUGSCHREIBER_EVENTS_TOKEN=no",
		"PATH=/usr/bin",
	}, []string{"AWS_ACCESS_KEY_ID"})
	joined := strings.Join(env, " ")
	if !strings.Contains(joined, "AWS_ACCESS_KEY_ID=yes") {
		t.Error("the named variable did not reach the helper")
	}
	for _, unwanted := range []string{"AWS_SECRET_ACCESS_KEY", "FLUGSCHREIBER_EVENTS_TOKEN"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("naming one variable let %s through as well", unwanted)
		}
	}
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Error("an ordinary variable was stripped, so the helper cannot find its own tools")
	}
}
