# Security

## Reporting a vulnerability

Open a [private security advisory](https://github.com/RamazanKara/flugschreiber/security/advisories/new)
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

**Stored content outliving its lawful basis.** With `--content-encryption`, the
text is sealed under a per-session key held outside the chain, and
`flugschreiber erase` destroys that key. The content becomes unreadable to
everyone, the evidence record is untouched, and the chain still verifies from the
beginning. This is what lets a GDPR Article 17 request be answered without
deleting the AI Act evidence that the interaction happened.

**Container compromise pivoting.** The image is distroless static: no shell, no
package manager, no libc. It runs as UID 65532 with a read-only root filesystem
and all capabilities dropped.

### Where the boundary runs

Each boundary below is stated exactly, so the defences above can be relied on
for precisely what they cover.

**An attacker who holds the signing key.** The hash chain proves internal
consistency, not authorship: someone who can rewrite every segment can recompute
a chain that verifies. Signed checkpoints narrow that considerably. Verification
checks each checkpoint's signature *and* checks it against the chain, so an
attacker who rewrites the log without the key leaves behind checkpoints that are
validly signed and disagree with the records they attest to. That is reported at
high severity.

What is left is an attacker who holds the key, and by default the key lives on
the same host as the evidence. That is the security boundary. Reduce it:
- move the key off the host with `--signer exec:<command>`, so that signing
  happens in a process the proxy talks to but does not contain, and the private
  half can live on a smartcard or an HSM (see below)
- store segments on append-only or object-lock storage (S3 Object Lock, WORM)
- replicate sealed segments off-host as they rotate
- record the chain head hash somewhere the proxy cannot reach, on a schedule
- anchor checkpoints with `--tsa-url`, so their time is a third party's claim

Running with `--no-sign` drops back to the chain-only property. That is a
deliberate choice an operator can make, and it should be a considered one.

**What an external signer buys you.** `--signer exec:<command>`
runs a helper that holds the key; the proxy hands it a preimage and gets a
signature back. The private half never has to be on the host that holds the
evidence, so an attacker who takes that host can still rewrite the log but can no
longer produce checkpoints that agree with the rewrite. The rewrite then
contradicts its own attestations, which is what a verifier reports.

What it does not buy: an attacker with code execution on the proxy host can ask
the helper to sign whatever they like, for as long as they have that access. A
signing helper is a boundary against theft of the key, not against use of it
while the machine is compromised. If the helper requires a touch or a PIN per
signature, that boundary tightens; a helper that signs anything on demand is
closer to a key in a different file than to a key in a different building.

The proxy is told which public key to expect (`--signer-public-key`) and refuses a
signature that does not verify against it. Without that, a helper wired to the
wrong key would produce checkpoints that are well formed and worthless, and the
mistake would surface in an audit rather than at startup.

**What a timestamp anchor proves.** With `--tsa-url`, each checkpoint is anchored
to an RFC 3161 authority, which signs "this digest existed at this time". That
turns a checkpoint's time from a claim by the host that wrote it into a claim by
a third party, which is exactly what a host-clock attacker cannot forge.

Flugschreiber stores the token verbatim and checks that it covers the checkpoint
it is filed against. It does not validate the authority's CMS signature or its
certificate chain, and it deliberately does not decide which authorities count:
that is a trust decision belonging to whoever is doing the checking, and the
`VERIFY.md` in an evidence bundle gives the `openssl ts -verify` command that
makes it. An anchor whose authority you do not trust proves nothing; the token is
kept unaltered so that judgement stays available to a reader years from now.

An authority that is down costs anchors and nothing else. Checkpoints are signed,
fsynced and complete whether or not one answers.

**Traffic that does not pass through the proxy.** If an application can reach
the model server directly, Flugschreiber will not record it and will not know it
happened. Coverage is a network property. Use a `NetworkPolicy` or equivalent to
make the proxy the only route.

**A compromised or dishonest upstream.** `model_served` and `usage` are
self-reported by the upstream and are not independently verified. A model server
that lies about which model it ran produces a log that faithfully records the
lie.

**Deletion under retention.** `flugschreiber retention --enforce --confirm`
deletes whole segments. It writes and fsyncs `pruned.json` before unlinking
anything, so a crash mid-deletion leaves an anchor ahead of the log rather than a
log nobody can verify. Verification tells an interrupted prune apart from a
wholesale replacement by cross-checking the record the anchor attests to. A
`LEGAL_HOLD` file blocks deletion entirely while it exists.

A pruned log reports itself as pruned, never as intact from the beginning. Those
are different claims and only one of them is true after a prune.

**Loss of the last records on machine failure.** Each record is flushed to the
operating system immediately, so a process crash loses nothing already written.
`fsync` runs on a one-second timer, so a power loss can lose up to one second of
records. The chain will show the truncation rather than hiding it.

**Denial of service.** There is no rate limiting. Put the proxy behind whatever
already protects your model server.

**Clock manipulation.** Timestamps come from the host clock. An attacker who
controls it controls the timestamps. `seq` remains monotonic and is the reliable
ordering; the chain is unaffected. RFC 3161 anchoring is the answer where the
time matters: a checkpoint anchored by an authority carries a time that host
cannot forge.

**Loss of the content key.** With content encryption on, the keystore is as
critical as the signing key and fails differently: losing the signing key costs
future attestation, while losing the content keystore destroys stored content
exactly as thoroughly as an erasure would. Back it up on the same footing as the
signing key, and understand that a backup of it is a backup of every prompt it
can open.

**Erasure and existing copies.** It destroys the wrapped key in the keystore
this directory holds, and nothing else. Every backup, volume snapshot and
object-locked copy taken before the erasure still contains that key, and the
ciphertext is still in the segments, so anyone holding both can still read the
content. Backups and object-locked copies are part of the hardening checklist, so plan
the erasure procedure around them: destroy the keystore inside those copies on
your backup retention schedule, and state that timeline when answering the
request. `--content-keystore` puts the keystore somewhere other than the
snapshotted volume, which keeps that procedure small.

**Erasure scopes by session.** `erase` selects by `--session` or
`--request-id`. A session id exists only when the calling application sends
`X-Flugschreiber-Session`; without it the selector is the request id of each
record in turn. `client_hash` identifies a credential rather than a person and
is deliberately not offered as an erasure selector. If you expect to answer
erasure requests, send the session header from day one.

**Erasure as an attack.** `erase` is destructive by design and cannot be undone.
It requires an explicit confirmation, refuses while a `LEGAL_HOLD` is in force,
and writes what it did into the chain. It does not authenticate the request
behind it: whoever can run the binary against the evidence directory can erase
content. Treat that access as you treat write access to the directory itself.

### Trust boundaries

| Boundary | Assumption |
| --- | --- |
| Client to proxy | Client credentials pass through unmodified. Terminate TLS at or before the proxy. |
| Proxy to upstream | The proxy may inject a configured API key when the client sent none. That key is read from config or environment and never logged. |
| Proxy to evidence directory | The proxy needs write access. Nothing else should have it. |
| Proxy to signing helper | The helper is trusted to hold the key and to sign only preimages it is given. It is handed no `FLUGSCHREIBER_*` environment variable, so it never sees the upstream API key, the events token or the archive credentials. |
| Proxy to timestamping authority | The authority learns a stream of 32-byte digests and the times they were requested. It learns nothing about the traffic: the imprint is a checkpoint hash, not content. |
| Evidence directory to auditor | An exported bundle contains segments, checkpoints, timestamps and every public key, current and retired. It never contains the signing key, the client salt, the content keystore, or any credential. With content encryption on, a bundle therefore carries ciphertext the recipient cannot read, which is deliberate: handing over the content is a separate decision from handing over the evidence. |

## Supply chain

- No external Go dependencies. `go.mod` has no `require` block.
- Builds are reproducible: `-trimpath`, pinned Go version, no cgo.
- Release images are distroless static and published with an SBOM.
- Release artifacts are signed with cosign (keyless, via GitHub OIDC).

To verify a release image:

```bash
cosign verify ghcr.io/ramazankara/flugschreiber:VERSION \
  --certificate-identity-regexp 'https://github.com/RamazanKara/flugschreiber/.*' \
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
- [ ] Keep the signing key off the host that holds the evidence, if you can
      (`--signer exec:<command>` with `--signer-public-key`)
- [ ] Anchor checkpoints to a timestamping authority you would cite (`--tsa-url`)
- [ ] Keep every retired public key: rotation must never strand old checkpoints
- [ ] Place a LEGAL_HOLD file before any deletion that must not happen
- [ ] Decide the content mode deliberately, and document why
- [ ] With content encryption on, back up the keystore as carefully as the
      signing key, and remember a backup of it is a backup of every prompt
