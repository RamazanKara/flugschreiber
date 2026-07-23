# Changelog

All notable changes to Flugschreiber are recorded here. The log schema has its
own compatibility policy in [docs/SCHEMA.md](docs/SCHEMA.md); a schema change
appears in both places or it did not happen.

## Unreleased

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
