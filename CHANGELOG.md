# Changelog

All notable changes to Flugschreiber are recorded here. The log schema has its
own compatibility policy in [docs/SCHEMA.md](docs/SCHEMA.md); a schema change
appears in both places or it did not happen.

## v0.5.0, 2026-07-25

An audit of what a 1.0 would have to promise, and the fourteen things that would
have broken it. None of them were missing features: they were what happens when
something goes wrong, and documents that promised more than the code delivered.

This is 0.5 rather than 1.0 because the contract is now written down but not yet
frozen. See [docs/STABILITY.md](docs/STABILITY.md) for what that means.

### Evidence integrity

- Checkpoints are chained: each carries an index, its predecessor's hash and a
  signature over both, so deleting attestations is detectable. Every checkpoint
  an attacker left behind used to verify, and nothing revealed the ones removed.
  The linkage sits outside the v1 signature, so verifiers already deployed
  validate these checkpoints unchanged instead of reporting them as forgeries.
- `verify --require-attestation` fails when nothing attests to the log, and
  `--expect-head` compares the head against a value recorded off-host.
- Two servers on one evidence directory are refused. The single-writer rule was
  enforced by the Helm chart and by nothing else; running two produced a chain
  that failed from the first concurrent append and looked exactly like
  tampering. A lock left by a dead process is still taken, because a crash must
  not cost an outage.
- `flugschreiber repair` finishes a write a power loss interrupted. A torn final
  record used to stop the server permanently with no way out, so a proxy that
  lost one record then recorded nothing at all. It refuses when a checkpoint
  attests past the damage, because then the bytes were signed evidence.
- Interactions still streaming at shutdown are recorded as truncated instead of
  vanishing. One replica is the supported topology, so every image bump and node
  drain passed through that window.
- The client salt is no longer silently regenerated when the file is short,
  which used to give every existing caller a new identity with nothing marking
  the boundary.

### Honesty

- `verify` distinguishes a damaged chain from one it could not check. A missing
  key exits 2 under a headline saying the chain is intact as far as it could be
  read, where it used to print VERIFICATION FAILED and exit 1.
- A checkpoint from a newer build is reported as unreadable rather than as a bad
  signature, which read as forgery for the ordinary act of upgrading.
- `inspect` shows truncation, incident severity, and the oversight attached to a
  session by request id. All three were recorded and none were displayed.
- A request over the parse cap keeps `model_requested`, which the router had
  already read from the same bytes.
- docs/SCHEMA.md states that the event digest covers the literal byte span in
  the file. A reimplementation that parsed and re-serialised computed a
  different digest and reported tampering on any prompt containing HTML, code or
  an ampersand.
- MAPPING.md documents the content tree, tool results and the lifecycle events,
  and a test now fails when a schema field has no entry there.

### Custody and operations

- The content keystore appends rather than rewriting, so minting a key costs the
  same at ten keys and at ten thousand. It is stated as internal to this
  implementation and outside the format promise.
- The signing helper no longer receives `AWS_ACCESS_KEY_ID` and its siblings,
  which SECURITY.md already claimed. A helper that needs one can be given it by
  name.
- `keys retire` files a public key so an external-signer rotation cannot strand
  the checkpoints it already signed.
- `serve --content-keystore` puts the content keys off the snapshotted volume,
  because a key inside a backup survives the erasure meant to destroy it.
- The chart mounts a scratch volume, so `export` works inside the pod, and the
  handover instructions no longer tell operators to run `kubectl cp` against a
  distroless image that has no tar. A bundle can be streamed to stdout.
- An evidence bundle's VERIFY.md specifies both preimages, so a recipient can
  check it without running software supplied by the party under audit.

### Documentation

- docs/STABILITY.md says what the command line promises: which surfaces are
  frozen, what the exit codes mean, and that boolean flags are one-way.
- testdata/conformance holds frozen evidence with its expected hashes, so a
  change that stops this build reading what an earlier one wrote fails the
  suite.

## v0.4.0, 2026-07-24

The three milestones below were planned as separate releases and built and
shipped together, so they carry one tag. The groupings are kept because they
say what each part is for.

### v0.2.0 Coverage

- The OpenAI Responses API (`/v1/responses`) is recorded like chat and
  completions, streamed and not, including `previous_response_id`.
- Multiple model servers behind one instance: `config.upstreams` routes by
  model glob and endpoint kind, each route with its own TLS and API key.
- Tool results are recorded on the inference event, digested in every content
  mode, with the hash-mode no-text guarantee extended to them.
- `report --lang en|de|both` selects the language editions. A full native German
  Annex IV skeleton (`technical-documentation-de.md`) ships alongside the
  English one; both render to HTML and PDF.
- The Helm chart's verify and retention CronJobs work in sidecar mode too, and
  refuse to install without an evidence claim they can mount.
- A Grafana dashboard and Prometheus alert rules ship under `deploy/observability`
  and through the chart.
- The record format is published as JSON Schema under `docs/schema`, kept in
  sync with the code by a test.

### v0.3.0 Custody

- `keys rotate` rotates the checkpoint signing key and keeps every retired
  public key under `keys/`, so checkpoints signed before a rotation stay
  verifiable. Exports and archives carry them.
- `--signer exec:<command>` signs checkpoints through an external helper, so
  the private key can live on a smartcard or an HSM instead of beside the
  evidence. `--signer-public-key` names the key the helper is supposed to hold,
  and a signature that does not verify against it is refused at startup.
  The helper is handed no `FLUGSCHREIBER_*` variable, so it never sees the
  upstream key or the events token. (It did receive the archive credentials,
  which arrive under the standard AWS names; corrected in the release above.)
- `--tsa-url` anchors checkpoints to an RFC 3161 timestamping authority, which
  turns their time from this host's claim into a third party's. Tokens are
  stored verbatim in `timestamps.jsonl`, checked against the checkpoint they
  cover, and reported by `verify` and in the generated documentation. An
  authority that is down costs anchors and never records.
- `archive-verify` checks that the offsite archive holds every sealed segment,
  and states which parts of a full verification an archive can and cannot
  support.
- `--retention-max-bytes` caps the evidence directory. It reports and never
  deletes below the retention floor, in the retention output, in the report and
  as `flugschreiber_evidence_bytes_over_cap`.
- The ASN.1, SigV4 and SSE parsers have fuzz targets, because all three read
  bytes from somewhere that is not us.
- Outward-facing custody moved to `internal/custody`, so `internal/evidence`
  reaches neither `net/http` nor `os/exec`, which is now checked against the
  transitive closure rather than only the internal edges.
- Shutdown drains the timestamping authority before the archive, so the anchor
  over a run's final checkpoint reaches the offsite copy even when the host
  never starts again.
- Two metrics, `flugschreiber_evidence_bytes_over_cap` and
  `flugschreiber_timestamps_total`, with a dashboard panel and an alert each.
- The Helm chart passes the signer, anchoring, size cap and content encryption
  settings through, and the chart check asserts each one reaches the container.

### v0.4.0 Erasure and reach

- `--content-encryption` encrypts stored content under keys held outside the
  chain, and `erase --session <id> --confirm` destroys those keys. The content
  becomes unreadable, the chain still verifies from the beginning, and the log
  gains a record of what was erased and when. Digests remain as written: after
  an erasure they are claims that can no longer be re-proven, and `inspect`,
  `export` and the report all say so rather than rendering erased content as
  empty.
- `incident` events with a `severity` of `suspected`, `serious` or `resolved`
  go into the same tamper-evident chain through the authenticated events
  endpoint, and the report's post-market section pre-fills from them. It is not
  the report to the authority, and the tool does not decide reportability or
  track deadlines.
- The full Annex IV skeleton and Article 50 pack ship in German as well as
  English, selected with `report --lang en|de|both`, defaulting to both.


- The generated Annex IV now tells the truth about the shipped product:
  section 3.4 reports signed checkpoints, attestation state and the key id;
  section 3.3 describes the real enforcement path and reports a pruned log as
  pruned; section 3.5 pre-fills observed human interventions by decision
  instead of opening with a blank TODO.
- `verify`'s text output states checkpoints, attestation and pruned state,
  matching what the JSON already carried.
- Sealed segments missed by the archive, for any reason, are queued again on
  the next start; segments the archive already holds are skipped, not
  overwritten.
- `--upstream-ca` trusts an internal CA bundle for the upstream connection,
  and `--upstream-tls-skip-verify` exists as the loudly warned last resort.
- The Helm chart gained a retention CronJob (off by default; it deletes
  evidence and says so) and pass-through for the upstream CA settings.

## v0.1.0, 2026-07-23

First release. Everything below is new.

### Recording

- Reverse proxy for OpenAI-compatible APIs (`/v1/chat/completions`,
  `/v1/completions`, `/v1/embeddings`) with full SSE streaming relay and
  capture of the assembled response, tool calls, finish reasons and token
  usage. Overhead is around half a millisecond at the median.
- Three content modes. The default, `hash`, records a SHA-256 of the exact
  wire bytes and no prompt or completion text, for GDPR data minimisation.
  `redact` retains text with configured patterns replaced; `store` retains it
  verbatim. The digest covers the full wire bytes in every mode.
- Caller identity as a salted hash, never a credential. The salt stays on the
  host.
- A built-in `--mock-upstream` so the quickstart, the demo and CI run with no
  model server, no GPU and no network.

### Evidence

- Append-only JSONL segments where every record carries the SHA-256 of its
  predecessor. Editing, inserting or removing any record breaks verification
  from that point on.
- Ed25519-signed checkpoints of the chain head, on by default: written on
  rotation, on a timer and at shutdown. Verification checks each signature and
  cross-checks it against the chain, which is what catches a log rewritten
  end to end by someone without the key.
- Archival of sealed segments to S3-compatible storage (AWS, MinIO, Ceph RGW)
  with hand-rolled SigV4 and optional Object Lock, or to a second directory.
  Never the write path: a broken bucket costs uploads, not records.
- Retention enforcement with a 180-day floor, whole-segment deletion only, a
  signed prune anchor recording where the surviving chain begins, and a
  `LEGAL_HOLD` file that blocks all deletion while it exists.
- An authenticated events endpoint for recording human oversight (approve,
  override, reject, escalate, halt, annotate) into the same chain as the
  interactions it concerns. It refuses to record inference events: callers may
  describe what a human did, never what a model did.

### Toolchain

- `verify`: offline chain, checkpoint and anchor verification. Reads files,
  needs no server, exits non-zero on any problem, and distinguishes an
  interrupted prune from a wholesale rewrite.
- `report`: an Annex IV-shaped technical documentation skeleton and an
  Article 50 transparency pack in German and English, pre-filled from observed
  traffic, as Markdown, self-contained HTML and, with `--pdf`, PDF. Every gap
  is a marked TODO, never plausible filler.
- `export`: a verification bundle for a third party, with a manifest, written
  instructions, and structurally enforced exclusion of the signing key and
  client salt.
- `inspect`: session reconstruction including the human decisions around it.
- `coverage`: what was captured, at what fidelity, and where the log is quiet.
- `retention`: report, dry-run, enforce with two flags, hold and release.

### Operations

- Prometheus metrics with bounded label cardinality and a scrape-time
  collector; structured JSON logs; startup verification of existing evidence.
- Distroless container (about 20 MB) running as nonroot on a read-only
  filesystem; a Helm chart with single-writer enforcement, a model-server
  NetworkPolicy, an hourly verify CronJob and install-time validation of the
  combinations that would otherwise fail at three in the morning.
- Zero Go dependencies, enforced by CI. Architecture enforced by a test.

### Known limits, stated rather than discovered

- The chain plus checkpoints prove integrity against everyone who does not
  hold the signing key; the key's custody is the security boundary, and by
  default it lives beside the evidence. `SECURITY.md` says what to do about
  that.
- Coverage is a network property. Traffic that bypasses the proxy is not
  recorded and nothing can say that it happened.
- `model_served` and token counts are the upstream's own claims.
- Nothing here makes anyone compliant. It produces evidence and documentation
  inputs.
