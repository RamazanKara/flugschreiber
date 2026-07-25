// Package custody holds the parts of key custody and timestamping that talk to
// something outside this process: an external signing helper, and a
// timestamping authority over HTTP.
//
// They live here rather than in internal/evidence on purpose. The evidence
// package is what a third party reads to satisfy themselves that a chain is
// intact, possibly years from now, and it is far easier to audit when its
// closure holds no HTTP client and no subprocess machinery. Evidence declares
// the Signer and Timestamper interfaces; this package implements them.
package custody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/RamazanKara/flugschreiber/internal/evidence"
)

// DefaultExecSignerTimeout bounds one call to an external signing helper. A
// smartcard or an HSM takes milliseconds; anything approaching this is a helper
// that is stuck, and a stuck helper must fail as a store error rather than
// hold the writer goroutine forever.
const DefaultExecSignerTimeout = 15 * time.Second

// execSignerMaxOutput bounds what a helper may write back. A signature is 64
// bytes raw or 128 characters hex, so this is four orders of magnitude of
// headroom and exists only so that a helper printing an endless stream cannot
// exhaust memory.
const execSignerMaxOutput = 64 << 10

// ExecSigner delegates checkpoint signing to an external command, which is how
// the private key stops living beside the evidence it signs. PKCS#11 tools,
// smartcards and SoftHSM all speak Ed25519, so custody can move off the host
// while the checkpoint stays byte-identical to one signed by the built-in key.
//
// The protocol is deliberately the smallest thing that can be written in any
// language:
//
//   - the preimage is written to the helper's standard input, which is then
//     closed, so a helper may read to EOF;
//   - the helper writes the detached Ed25519 signature to standard output,
//     either as 128 hex characters (with optional trailing whitespace) or as
//     the 64 raw bytes;
//   - exit status zero means the signature is good. Anything else is a
//     failure, and whatever the helper wrote to standard error is quoted in
//     the error the store reports.
//
// The helper inherits this process's environment except for the
// FLUGSCHREIBER_ variables, which carry the upstream API key, the events token
// and the archive credentials. A signing helper needs none of those, and the
// cheapest way to keep a credential out of another process is not to hand it
// over.
//
// The public key comes from a PEM file rather than from the helper, so that a
// helper cannot decide after the fact which key it signed with. Every
// signature is verified against that key before it is accepted.
type ExecSigner struct {
	name    string
	args    []string
	pub     ed25519.PublicKey
	keyID   string
	timeout time.Duration

	// passEnv names variables to let through that would otherwise be stripped,
	// for a helper that legitimately needs a cloud credential to reach the key.
	passEnv []string
}

// NewExecSigner returns a Signer backed by an external command.
//
// command is split on whitespace into a program and its arguments and is run
// directly: no shell is involved, so redirection, pipes and quoting do not
// work, and a program whose path contains a space needs a wrapper script.
// publicKeyPEMPath holds the PKIX public key the helper signs with; the pair
// is checked for consistency at every signature, and the file's key id is what
// the checkpoints record.
func NewExecSigner(command string, publicKeyPEMPath string) (evidence.Signer, error) {
	return NewExecSignerWithEnv(command, publicKeyPEMPath, nil)
}

// NewExecSignerWithEnv is NewExecSigner with an explicit passthrough list, for
// a helper that reaches its key through a cloud service and therefore needs a
// credential this package otherwise strips.
func NewExecSignerWithEnv(command string, publicKeyPEMPath string, passEnv []string) (evidence.Signer, error) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, errors.New("custody: exec signer: no command given")
	}
	if publicKeyPEMPath == "" {
		return nil, errors.New("custody: exec signer: the public key file is required, otherwise nothing can check what the helper signs")
	}

	program, err := exec.LookPath(fields[0])
	if err != nil {
		return nil, fmt.Errorf("custody: exec signer: %w", err)
	}
	pub, err := evidence.LoadPublicKeyPEM(publicKeyPEMPath)
	if err != nil {
		return nil, fmt.Errorf("custody: exec signer: %w", err)
	}

	return &ExecSigner{
		name:    program,
		args:    fields[1:],
		pub:     pub,
		keyID:   evidence.KeyID(pub),
		timeout: DefaultExecSignerTimeout,
		passEnv: passEnv,
	}, nil
}

// Public returns the key from the PEM file the signer was configured with.
func (s *ExecSigner) Public() ed25519.PublicKey { return s.pub }

// KeyID returns the id of that key.
func (s *ExecSigner) KeyID() string { return s.keyID }

// Sign runs the helper over preimage and returns the signature it produced.
//
// The result is checked against the configured public key here as well as in
// SignCheckpointWith, because this is the layer that knows what went wrong: a
// helper wired to the wrong slot produces a signature that is well formed and
// useless, and saying so at the moment it happens is the difference between a
// misconfiguration found in testing and one found in an audit.
func (s *ExecSigner) Sign(preimage []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.name, s.args...)
	// The timeout kills the helper, but Run also waits for the pipes carrying
	// its output to close, and a helper that leaves a background child holding
	// them keeps them open after it is gone. Without a bound on that wait the
	// writer goroutine stops here for good, which is the one way a signing
	// helper could cost records rather than checkpoints.
	cmd.WaitDelay = s.timeout
	cmd.Env = helperEnv(os.Environ(), s.passEnv)
	cmd.Stdin = bytes.NewReader(preimage)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: execSignerMaxOutput}
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: execSignerMaxOutput}

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("custody: signing helper %s did not answer within %s%s", s.name, s.timeout, quoted(stderr.Bytes()))
		}
		return nil, fmt.Errorf("custody: signing helper %s failed: %w%s", s.name, err, quoted(stderr.Bytes()))
	}

	sig, err := parseSignature(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("custody: signing helper %s: %w%s", s.name, err, quoted(stderr.Bytes()))
	}
	if !ed25519.Verify(s.pub, preimage, sig) {
		return nil, fmt.Errorf(
			"custody: signing helper %s produced a signature that does not verify against key %s; the helper is signing with a different key than the one it was configured with",
			s.name, s.keyID)
	}
	return sig, nil
}

// configEnvPrefix namespaces this tool's own environment variables. It is
// spelled out rather than imported from internal/config so that this package
// stays a leaf of the configuration graph.
const configEnvPrefix = "FLUGSCHREIBER_"

// credentialEnv names the variables a signing helper is not given.
//
// The FLUGSCHREIBER_ prefix covers this tool's own configuration: the upstream
// API key, the events token, the archive settings. The AWS variables are here
// because the archive credentials also arrive through the standard names, which
// is what the chart injects and what internal/archive reads, so stripping only
// the prefix handed the helper write credentials for the offsite copy that
// exists to survive compromise of this host. SECURITY.md claimed otherwise and
// the guard test passed because it set only prefixed variables.
//
// A helper that genuinely needs them, one talking to AWS KMS, is why
// ExecSignerPassEnv exists: the operator names what to let through rather than
// the tool guessing that everything is fine.
var credentialEnv = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
}

// helperEnv is the environment a signing helper is given: everything a program
// needs to find its module, its card reader and its own configuration, and none
// of this process's credentials.
func helperEnv(environ []string, pass []string) []string {
	allowed := make(map[string]bool, len(pass))
	for _, name := range pass {
		allowed[strings.TrimSpace(name)] = true
	}

	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if allowed[name] {
			out = append(out, kv)
			continue
		}
		if strings.HasPrefix(kv, configEnvPrefix) {
			continue
		}
		if slices.Contains(credentialEnv, name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// parseSignature accepts the two encodings a helper may reasonably produce.
// The raw form is checked first: 64 raw bytes and 128 hex characters are
// different lengths, so there is nothing to guess between.
func parseSignature(out []byte) ([]byte, error) {
	if len(out) == ed25519.SignatureSize {
		return out, nil
	}
	trimmed := strings.TrimSpace(string(out))
	if len(trimmed) == hex.EncodedLen(ed25519.SignatureSize) {
		sig, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("wrote %d characters that are not hex: %w", len(trimmed), err)
		}
		return sig, nil
	}
	if len(out) == 0 {
		return nil, errors.New("wrote nothing to standard output, expected a hex or raw Ed25519 signature")
	}
	return nil, fmt.Errorf(
		"wrote %d bytes, expected %d hex characters or %d raw bytes",
		len(out), hex.EncodedLen(ed25519.SignatureSize), ed25519.SignatureSize)
}

// quoted renders helper diagnostics for an error message, on one line and
// bounded, because it is written by a program the operator wrote and ends up
// in a log line.
func quoted(stderr []byte) string {
	text := strings.TrimSpace(string(stderr))
	if text == "" {
		return ""
	}
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return fmt.Sprintf(" (it reported: %s)", strings.Join(strings.Fields(text), " "))
}

// limitedWriter keeps a helper that never stops writing from filling memory.
// Output past the limit is discarded rather than treated as an error: the
// signature, if there is one, is in the first bytes.
type limitedWriter struct {
	w         *bytes.Buffer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	if len(p) > l.remaining {
		l.w.Write(p[:l.remaining])
		l.remaining = 0
		return len(p), nil
	}
	l.remaining -= len(p)
	return l.w.Write(p)
}
