# Security

## Reporting a vulnerability

Open a [private security advisory](https://github.com/flugschreiber/flugschreiber/security/advisories/new)
rather than a public issue. We will acknowledge within 72 hours and aim to have
a fix or a mitigation within 14 days for anything that lets an attacker forge,
alter or suppress evidence.

Please include what you were able to do, not just what looked wrong. A working
demonstration against a local `--mock-upstream` instance is ideal.

## Threat model

Flugschreiber sits on the path between an application and a model server. It
holds credentials in transit, evidence at rest, and it is a single point of
failure for both availability and truth.

### What it defends against

**Undetected modification of the log.** Every record carries the SHA-256 of its
predecessor and of its own contents. Editing, inserting or removing any record
breaks the chain at that point and at every point after it. `flugschreiber
verify` reads only the files on disk, so the check can be repeated by anyone
holding a copy, on a machine you do not control.

**Credential retention.** Caller credentials are hashed with a per-installation
salt and truncated; the credential itself is never written. The salt lives in
the data directory at mode 0600 and is excluded from evidence exports, so a
recipient of an evidence bundle cannot reverse identifiers even with a candidate
list of API keys.

**Accidental retention of personal data.** The default content mode records
digests, not text. Storing prompts is an explicit opt-in.

**Container compromise pivoting.** The image is distroless static: no shell, no
package manager, no libc. It runs as UID 65532 with a read-only root filesystem
and all capabilities dropped.

### What it does not defend against

These are real limitations, stated plainly because a security document that only
lists strengths is marketing.

**An attacker with write access to the whole evidence directory.** The hash
chain proves internal consistency, not authorship. Someone who can rewrite every
segment can recompute the chain from scratch and produce a log that verifies
perfectly. The guarantee today is *nobody edited this log without rewriting all
of it*.

Mitigations available now:
- store segments on append-only or object-lock storage (S3 Object Lock, WORM)
- replicate segments off-host as they are written
- record the chain head hash somewhere the proxy cannot reach, on a schedule

Ed25519-signed checkpoints (M2) narrow this to an attacker who also holds the
signing key. That is the right fix and it is not shipped yet.

**Traffic that does not pass through the proxy.** If an application can reach
the model server directly, Flugschreiber will not record it and will not know it
happened. Coverage is a network property. Use a `NetworkPolicy` or equivalent to
make the proxy the only route.

**A compromised or dishonest upstream.** `model_served` and `usage` are
self-reported by the upstream and are not independently verified. A model server
that lies about which model it ran produces a log that faithfully records the
lie.

**Loss of the last records on machine failure.** Each record is flushed to the
operating system immediately, so a process crash loses nothing already written.
`fsync` runs on a one-second timer, so a power loss can lose up to one second of
records. The chain will show the truncation rather than hiding it.

**Denial of service.** There is no rate limiting. Put the proxy behind whatever
already protects your model server.

**Clock manipulation.** Timestamps come from the host clock. An attacker who
controls it controls the timestamps. `seq` remains monotonic and is the reliable
ordering; the chain is unaffected.

### Trust boundaries

| Boundary | Assumption |
| --- | --- |
| Client to proxy | Client credentials pass through unmodified. Terminate TLS at or before the proxy. |
| Proxy to upstream | The proxy may inject a configured API key when the client sent none. That key is read from config or environment and never logged. |
| Proxy to evidence directory | The proxy needs write access. Nothing else should have it. |
| Evidence directory to auditor | An exported bundle contains segments and, from M2, checkpoints and the public key. It never contains the client salt or any credential. |

## Supply chain

- No external Go dependencies. `go.mod` has no `require` block.
- Builds are reproducible: `-trimpath`, pinned Go version, no cgo.
- Release images are distroless static and published with an SBOM.
- Release artifacts are signed with cosign (keyless, via GitHub OIDC).

To verify a release image:

```bash
cosign verify ghcr.io/flugschreiber/flugschreiber:VERSION \
  --certificate-identity-regexp 'https://github.com/flugschreiber/flugschreiber/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Hardening checklist for operators

- [ ] Run with `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`
- [ ] Mount the evidence directory as the only writable path
- [ ] Restrict read access to the evidence directory to the audit role
- [ ] Put the evidence directory on append-only or object-lock storage
- [ ] Make the proxy the only network route to the model server
- [ ] Terminate TLS at or before the proxy; do not send prompts over plaintext
- [ ] Record the chain head hash off-host on a schedule
- [ ] Decide the content mode deliberately, and document why
