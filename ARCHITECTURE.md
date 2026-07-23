# Architecture

Flugschreiber is a recording reverse proxy in front of an OpenAI-compatible
endpoint, an append-only evidence store behind it, and a toolchain that reads
the store. This page is the map; the dependency graph it describes is enforced
by `test/architecture_test.go`, so if the two ever disagree, the build fails
rather than the document quietly lying.

## Data flow

```
 application                    Flugschreiber                     model server
 ────────────                   ─────────────                     ────────────
 OPENAI_BASE_URL ──────────▶  proxy (tee, never buffer)  ──────▶  vLLM/Ollama/...
                                │
                                │ one event per interaction,
                                │ after the response completes
                                ▼
                              evidence store (single writer)
                                │  seg-*.jsonl   hash chain
                                │  checkpoints.jsonl  Ed25519 over the head
                                │  pruned.json  where a pruned chain begins
                                ▼
                 ┌──────────────┼──────────────────┐
                 ▼              ▼                  ▼
            archiver       flugschreiber       flugschreiber
            (sealed         verify | report     export | inspect
            segments        | coverage |        (bundle for a
            to S3/dir)      retention           third party)
```

Requests stream through untouched; capture happens on a tee. The evidence
record is assembled after the response body closes, so the store is never on
the client's critical path, and a slow disk becomes backpressure rather than
dropped evidence.

## Packages and the rules between them

```
cmd/flugschreiber, cmd/proxyd ──▶ internal/cli ──▶ everything below

internal/proxy ──▶ config, content, openai, evidence, metrics, version
internal/report ──▶ config, evidence          internal/audit ──▶ evidence
internal/config ──▶ content, evidence         internal/openai ──▶ evidence
internal/content ──▶ evidence

foundations, no internal imports at all:
  evidence   archive   metrics   pdf   mockupstream   version
```

Three of those edges are rules, not accidents:

**`internal/evidence` imports nothing internal.** `flugschreiber verify` is
the command a third party runs against a copy of the log, possibly years from
now, possibly after reimplementing it from `docs/SCHEMA.md`. The package that
defines what the evidence *is* must be readable and auditable on its own, with
no HTTP client, no S3 signer and no metrics registry in its closure.

**`internal/archive` does not import `internal/evidence`.** The store declares
the `Archiver` interface it needs; the archive backends satisfy it
structurally. The dependency points from the thing that must always work to
nothing at all, so a bug in SigV4 signing cannot be in the same import graph as
chain verification.

**`cmd/*` contains no logic.** Both binaries are thin wrappers over
`internal/cli`, which is why the proxy that recorded the evidence and the
verifier an auditor downloads are provably the same code.

## Invariants

These are the properties the design defends. Each is tested, most of them
adversarially.

1. **Zero dependencies.** `go.mod` has no `require` block and CI fails if one
   appears. Every dependency would be a party able to change what lands in an
   evidence file (`DECISIONS.md` D1).
2. **The chain hashes bytes, not structs.** A verifier compiled today checks a
   log written by a future schema, because `event` is hashed as the bytes that
   were written (D2). The preimage is published in `docs/SCHEMA.md` and the
   acceptance suite reimplements it from that document, so spec drift fails the
   build.
3. **One writer, one total order.** A single goroutine owns the chain state.
   The Helm chart refuses `replicas > 1` at install time for the same reason.
4. **Capture is off the hot path.** Bodies are teed with a bounded parse
   prefix; the digest covers the full stream; streamed responses relay frame by
   frame, with a test that fails if buffering creeps in (D5, D6).
5. **Backpressure, never dropped evidence.** A full queue slows the proxy; it
   never drops a record (D7). A failing archive backend costs uploads, never
   appends, and never holds shutdown open past its window (D22, D28).
6. **Secrets stay home.** `signing-key.pem` and `client-salt` never leave the
   host; `export` enforces an allowlist twice and CI greps the produced bundle
   (D8, D18).
7. **Verification tells the truth about itself.** A pruned log reports as
   pruned, an unattested log as unattested, a checkpoint that contradicts the
   chain as the signature of a rewrite (D21, D26).
8. **Parsers are tolerant, writers are strict.** A malformed frame costs a
   field, never the record (D12). Config files reject unknown keys.
9. **No caller-controlled cardinality.** Nothing a caller sends becomes a
   metric label; model names pass through a bounded set (D25).
10. **Honest framing.** No generated document, README line or log message
    claims the tool confers compliance. CI greps for the phrasings we know;
    review catches the ones we do not.

## Where things are decided

- `docs/SCHEMA.md` is the on-disk contract and its compatibility policy.
- `MAPPING.md` maps every recorded field to the AI Act provision it supports,
  with the caveats.
- `SECURITY.md` is the threat model, including what is *not* defended.
- `DECISIONS.md` records every choice above with its cost, numbered D1 to D32.
