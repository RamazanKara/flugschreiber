# Roadmap

The implementation plan for everything currently known to be missing. Items
are grouped into three milestones by a simple rule: gaps in *recording*
compound daily, because traffic that was not captured is gone forever, so they
come first. Hardening what is recorded comes second. The deepest schema work
comes last, where it benefits from everything else being stable.

Every item follows the standing rules: zero Go dependencies, schema changes
are additive or they are a version bump, the architecture test gates new
imports, every behaviour gets a test that fails without it, and no copy ever
claims the tool confers compliance. Each shipped item adds its entry to
`DECISIONS.md` and `CHANGELOG.md`.

Effort labels: S is about half a day, M one to two days, L two to three, XL a
week-class change.

## v0.2.0, "Coverage": record everything that talks to the model

### 1. Responses API capture (M)

`/v1/responses` currently passes through unrecorded, which is a silent
coverage hole on an API shape that is increasingly the default.

- `internal/openai`: add `EndpointResponses` to `ClassifyPath` (suffix
  `/responses`). Request parser maps `input` (string or item list),
  `instructions`, sampling parameters and `tools` onto the existing
  `evidence.Params`/`Message` shapes. Response parser maps `output` items
  (`message` text, `function_call`, reasoning) onto text, tool calls and
  finish state; `usage.input_tokens`/`output_tokens` map onto the existing
  token fields.
- Streaming: prefer the `response.completed` event, which embeds the full
  final response, and fall back to accumulating `response.output_text.delta`.
  The existing SSE scanner already ignores `event:` lines, so only the
  assembly layer changes.
- Schema: one additive field, `upstream_previous_id`, for
  `previous_response_id`, since it is the API's own session linkage.
- `internal/metrics`: extend the closed endpoint label set with `responses`.
- `internal/mockupstream`: a deterministic `/v1/responses` handler, streamed
  and not, so tests and the demo need no real server.
- Tests: parser tables from real payload shapes, stream assembly, proxy
  integration, one acceptance touch.
- Done when: a streamed Responses call produces one inference record with
  text, tool calls, usage and finish state, and the chain verifies.

### 2. Multi-upstream routing (L)

One upstream per instance forces anyone with a chat server and a separate
embeddings server to run two proxies and two chains.

- Config: `upstreams` as a list of routes `{name, url, api_key, ca_file,
  tls_skip_verify, models: [globs], endpoints: [kinds], default: bool}`. The
  existing `upstream` string keeps working as the single default route;
  setting both is a validation error, as is zero or two defaults.
- Routing needs the model name before dialling, so recorded endpoints gain a
  bounded body peek: read up to 1 MiB looking for `model`, then reconstruct
  the body as peeked-bytes-then-rest. Streaming after the peek is untouched.
  This amends decision D5 (bodies are teed, never buffered) with a bounded
  exception, recorded as its own decision with the measured latency cost.
- One transport and reverse proxy per route, so per-route TLS settings work.
  The evidence record's `upstream` field already carries the label.
- No model match and no default is a 502, recorded as evidence like any other
  upstream failure.
- Chart: `config.upstreams` list with schema validation mirroring the binary's.
- Tests: routing table units, two distinguishable mock upstreams end to end,
  fallback, ambiguity refusals at validation time.
- Done when: chat and embeddings route to different upstreams in one instance,
  each record naming the upstream that served it.

### 3. Tool results inside the inference record (S-M)

Tool *calls* are captured; the results coming back as `role:"tool"` messages
are only part of the raw request content.

- Not separate chain events: chat clients resend the whole conversation every
  turn, so per-message events would duplicate one result into the chain once
  per subsequent turn. Instead the inference event gains an additive
  `tool_results` array: `{call_id, sha256, bytes}` always, content following
  the active content mode, built from the tool-role messages present in the
  request. The duplication across turns is contained in each record and
  documented.
- `internal/openai` retains `tool_call_id` from tool-role messages;
  `internal/content` applies the mode to result content the same way it does
  to tool arguments.
- Done when: a call carrying a tool response yields a record whose
  `tool_results` entry links `call_id` to the digest of what came back, in
  every content mode, with the hash-mode disk-leak test extended to cover it.

### 4. Sidecar scheduled verify and retention (S)

Both CronJobs are gated on `mode: central`, so sidecar deployments silently
lose "a broken chain pages someone".

- Chart: drop the central-only gate; in sidecar mode require
  `persistence.existingClaim` and fail at install with an explanation
  otherwise, since the chart cannot guess the application pod's volume.
- Done when: `helm template` renders both CronJobs in sidecar mode with a
  resolvable claim and refuses cleanly without one.

### 5. Grafana dashboard and alert rules (S-M)

The metrics exist; nothing ships that reads them.

- `deploy/observability/grafana-dashboard.json`: request rate by endpoint and
  status class, duration and TTFB percentiles from the histograms, token rate
  by model, evidence growth, capture errors, checkpoint and archive rates.
- Chart: optional dashboard ConfigMap with the Grafana sidecar label, and an
  optional PrometheusRule (CRD-guarded): capture errors rising, archive
  failure ratio, and evidence bytes flat while request rate is not, which is
  the shape of a capture stall.
- Done when: the dashboard imports clean against a scrape of the mock demo.

### 6. Published JSON Schema for the record format (S)

`docs/SCHEMA.md` is prose; a third party writing their own verifier wants a
schema file.

- Hand-maintained `docs/schema/record.schema.json` and `event.schema.json`,
  served by Pages. A reflection test walks the Go structs' JSON tags and
  fails when a field exists in code but not in the schema or the reverse, so
  the two cannot drift.
- Done when: the sync test passes and the schema URL renders on the site.

## v0.3.0, "Custody": harden what is recorded

### 7. Signing key rotation (M)

One key forever is not an operational posture.

- `flugschreiber keys rotate --dir`: generates a new pair, moves the old
  public key to `keys/retired-<keyid>.pem`, deletes the old private key, and
  appends a `config_change` event recording old and new key ids, so the log
  documents its own custody history.
- Verification builds a key-id map from the current key plus every retired
  one; `unknown_key` now means genuinely unknown. Export bundles include the
  retired public keys; the secret allowlist is unchanged.
- Rotation requires the server stopped, documented plainly; the single-writer
  rule already makes concurrent mutation of the directory an error of
  operation, not a new mechanism.
- Done when: rotate, restart, verify shows old checkpoints verified under the
  retired key and new ones under the current key, and the acceptance suite
  covers the full cycle.

### 8. External signer hook (M)

Key custody is the documented security boundary, and today the key must sit
beside the evidence.

- Not cloud-KMS first: AWS KMS does not sign Ed25519, and changing the
  checkpoint algorithm is a contract change. Instead an exec-signer:
  `--signer exec:/path/to/helper` sends the preimage on stdin and reads a hex
  signature on stdout, with the public key supplied as a file. PKCS#11 tools,
  YubiKeys and SoftHSM all speak Ed25519, so custody moves off-host while the
  checkpoint contract stays byte-identical.
- Failure behaviour matches the current signer: a signing failure is a store
  error, never a dropped record.
- Done when: the acceptance suite runs a stub helper binary end to end and a
  chain signed through it verifies unchanged.

### 9. Archive verification (M)

Nothing checks the bucket copy; upload counters are the only signal.

- `flugschreiber archive-verify --dir ... [--deep]`: derive the expected key
  set from local sealed segments, checkpoints and public keys; `Exists` each;
  with `--deep`, fetch and compare SHA-256. Requires one additive `Get`
  method on the archive backends, exposed to the evidence layer through the
  same structural-interface pattern as `Put`.
- Output mirrors `verify`: text and `--json`, non-zero exit on gaps, so the
  chart can run it as a third CronJob later.
- Done when: deleting one object from a dir-backend archive makes the command
  exit non-zero naming the missing key, and `--deep` catches a corrupted one.

### 10. RFC 3161 timestamp anchors (M-L)

Checkpoint times are host-clock claims.

- Phase one, anchoring only: build the TSQ with `encoding/asn1` over the
  checkpoint hash, store the returned token verbatim in
  `timestamps.jsonl` beside the checkpoint it covers, and verify structurally
  that the token's message imprint matches. Full CMS validation is explicitly
  out of scope for the built-in verifier; `VERIFY.md` documents the
  `openssl ts -verify` command that does it, which keeps the zero-dependency
  rule intact while making the anchors real.
- Off by default; `--tsa-url` plus an interval enables it.
- Done when: a checkpoint gains a token whose imprint the verifier confirms,
  and the export bundle carries the tokens.

### 11. Size-based retention pressure valve (S-M)

Retention is age-based only.

- `RetentionPolicy` gains `MaxBytes`. It never overrides the 180-day floor:
  when the directory exceeds the cap but everything is within retention, the
  tool refuses to delete and says so loudly, because disk pressure against a
  legal floor is the operator's decision, not the tool's. Beyond-retention
  segments are deleted oldest-first until under the cap.
- Surfaced in `retention` output, the report's section 3.3, and a metric.
- Done when: the refusal case and the trim case both have tests.

### 12. Fuzzing the parsers (S-M)

The security posture is otherwise strong; the parsers have no fuzz coverage.

- Native Go fuzz targets: SSE stream assembly, request and response parsing,
  the Markdown renderer, SigV4 canonicalisation (properties: no panics,
  deterministic output), and the record-line verifier. Seed corpora from
  existing testdata.
- CI: a scheduled workflow runs each target briefly; findings become ordinary
  regression tests.
- Done when: all targets run clean for a sustained local session and the
  scheduled job exists.

## v0.4.0, "Erasure and reach": the deep cuts

### 13. Crypto-shredding for stored content (XL)

`store` and `redact` modes collide with GDPR Article 17: the only deletion is
whole-segment retention. This is the item to finish before anyone runs
`store` mode at scale.

- Opt-in `--content-encryption`. Text-bearing payload fields are encrypted
  with AES-GCM under a content-encryption key per session (falling back to
  per-record), keys wrapped by a master content key in a separate keystore
  file. The chain hashes the event bytes as written, ciphertext included, so
  erasure never touches the chain.
- `flugschreiber erase --session S --confirm` deletes the wrapped keys and
  appends a `system_event` documenting the erasure, so the log records that
  content was removed, when, and under what request. Digests over the
  original wire bytes remain as claims that can no longer be re-proven, and
  the documentation says exactly that.
- `inspect`, `export` and the report render erased content as erased, with
  the date, never as empty.
- Touches content, evidence schema (additive envelope fields), keystore,
  CLI, docs, MAPPING and the DE/EN packs. Ships with its own threat-model
  section in `SECURITY.md`.
- Done when: store-mode content is unreadable after erasure, the chain still
  verifies, the erased state renders honestly everywhere, and the master
  content key never appears in an export.

### 14. German Annex IV skeleton (M)

The transparency pack is bilingual; the technical documentation is not, and
the audience is German-speaking DPOs.

- `technical-documentation-de.md.tmpl` as a full native translation, not a
  string swap; `report --lang en|de|both`, default unchanged. Golden files
  for the German rendering; the HTML chrome already switches language.
- The translation gets flagged for native review the way the transparency
  pack was.
- Done when: `--lang both` produces both skeletons from one evidence pass,
  byte-stable under `--now`.

### 15. Article 73 incident records (S-M)

Serious-incident obligations have no home in the schema.

- New recordable event type `incident` with a closed severity set
  (`suspected`, `serious`, `resolved`), `actor` required, `ref_request_id`
  optional, submitted through the existing authenticated events endpoint
  under the existing rule: callers describe what humans concluded, never what
  models did.
- The report's post-market section pre-fills observed incidents; MAPPING
  gains an Article 73 section with the usual caveats about what a log can and
  cannot evidence.
- Done when: an incident round-trips endpoint to chain to report, and the
  forgery protections (token, no inference type) still hold.

## Explicitly not planned

Multi-writer or HA chains (a single total order is the design), rate limiting
(belongs in front of the proxy), Anthropic `/v1/messages` (the positioning is
OpenAI-compatible; revisit only with demand), and automatic retention inside
`serve` (deletion stays behind an explicitly scheduled job with two explicit
flags).

## Order of work inside v0.2.0

Responses API first (mock, then parsers, then proxy), because it closes a
live coverage hole and its parser work feeds item 3. Multi-upstream routing
second, since it introduces the bounded-peek mechanism and the largest config
surface. The chart and schema items are independent and can land between.
