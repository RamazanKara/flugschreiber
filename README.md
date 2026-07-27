# Flugschreiber

**Tamper-evident audit logs and EU AI Act documentation for self-hosted LLMs. One base URL change, no application code.**

[![CI](https://github.com/RamazanKara/flugschreiber/actions/workflows/ci.yml/badge.svg)](https://github.com/RamazanKara/flugschreiber/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/RamazanKara/flugschreiber.svg)](https://pkg.go.dev/github.com/RamazanKara/flugschreiber)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Somebody asked you what evidence you have of what your AI did last quarter. You
run vLLM behind an internal API. You have Grafana dashboards and 30 days of
application logs that were never designed to answer that question, and the
teams whose code calls the model are not going to add an SDK because compliance
asked nicely.

Flugschreiber is a reverse proxy you put in front of any OpenAI-compatible
endpoint. It records every model interaction to an append-only, hash-chained
log, and it generates the technical documentation and transparency artifacts
that AI Act preparation needs as inputs, pre-filled from traffic it actually
observed.

![The 30 second demo: serve, call, verify, tamper, report](docs/media/demo.gif)

<sub>The same recording as an [mp4](docs/media/demo.mp4). Rendered from
[scripts/demo.sh](scripts/demo.sh) against the built-in mock upstream, so what
it shows is exactly what the quickstart below does.</sub>

## Sixty seconds

```bash
docker run -d --name flugschreiber \
  -p 8080:8080 -v fs-evidence:/var/lib/flugschreiber \
  ghcr.io/ramazankara/flugschreiber:latest serve --mock-upstream
```

Point an app at it and make a few calls:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=anything

curl $OPENAI_BASE_URL/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"llama-3.1-8b","messages":[{"role":"user","content":"hello"}]}'
```

Then ask what it recorded:

```bash
docker exec flugschreiber flugschreiber verify --dir /var/lib/flugschreiber
```

```
hash chain intact

  directory   /var/lib/flugschreiber
  segments    1
  records     3
  sequence    1 to 3
  head hash   dbbbf2ff9f5ab06a06de9002235539b3d0735b443b0f5a2c4f8964315ab3a5ae
  checked in  175.208µs
```

And generate the documents:

```bash
docker exec flugschreiber flugschreiber report \
  --dir /var/lib/flugschreiber --out /tmp/reports \
  --organisation "Muster GmbH" --system-name "Support Assistant"
```

You get an Annex IV-shaped technical documentation skeleton and an Article 50
transparency pack in German and English, each as Markdown and as a
self-contained HTML page with no external requests, suitable for emailing to
someone who will open it offline.

`--mock-upstream` runs a built-in fake model server so the quickstart needs no
GPU and no network. For real traffic, drop it and pass `--upstream
http://vllm:8000`.

## What is actually in the log

One record per interaction, one line of JSON, appended and never rewritten:

```json
{
  "seq": 2,
  "timestamp": "2026-07-22T23:50:23.874242586Z",
  "prev_hash": "99f3f6b4f7f1f4385c76f8b96ebc3a23dd6c30883bbacc3295868446bf1dc827",
  "record_hash": "ab3757a507d89eddfc5d26a679d3a614abf604bfd038c3f243b1a8d15684cba4",
  "event": {
    "event_type": "inference",
    "request_id": "ce71fbc95de75029d96bfcbfbce7ec4b",
    "session_id": "sess-42",
    "client_hash": "c140d1009bb9f591c084a684502297e7",
    "endpoint": "/v1/chat/completions",
    "upstream": "http://vllm:8000",
    "model_requested": "llama-3.1-8b",
    "model_served": "llama-3.1-8b-awq",
    "params": { "temperature": 0.2, "max_tokens": 512 },
    "usage": { "prompt_tokens": 180, "completion_tokens": 64, "total_tokens": 244 },
    "stream": true,
    "finish_reasons": ["stop"],
    "status": 200,
    "latency_ms": 812.4,
    "ttfb_ms": 1.2,
    "content": {
      "mode": "hash",
      "input":  { "sha256": "a06eaac6...", "bytes": 141 },
      "output": { "sha256": "6a00471259...", "bytes": 4550 }
    }
  }
}
```

Every record carries the hash of the one before it. Change a byte anywhere and
verification fails at that record and every record after it:

```
HASH CHAIN VERIFICATION FAILED

1 problem(s) found:

  seg-00000001.jsonl:1: hash_mismatch: record_hash is 99f3f6b4f7f1…, contents hash to 73dcc8520bdb…
```

`verify` reads files and nothing else. No server, no database, no network. Hand
someone a copy of the directory and this binary and they can check it
themselves, on their own machine.

Note `model_requested` and `model_served` in that record. The application asked
for `llama-3.1-8b` and the upstream served an AWQ quant. That divergence is the
kind of thing nobody notices until someone asks.

Chat completions, completions, embeddings and the Responses API
(`/v1/responses`) are all recorded the same way, streamed or not, including the
`previous_response_id` that links one turn to the last. Tool calls the model
requested are recorded, and so are the tool results your application sends back,
digested in every content mode.

## By default it stores no prompts

The default content mode is `hash`: a SHA-256 of the request and response bytes,
and no prompt or completion text at rest.

This is deliberate. A proxy that stores every prompt by default turns every
deployment into a fresh copy of whatever users type into a chat box, sitting in
a system nobody scoped for it. GDPR Article 5(1)(c) has an opinion about that,
and defaults are policy, because most people run what ships.

The digest covers the exact wire bytes in every mode, including `hash`. So if
you hold a transcript from somewhere else, you can prove it is the transcript of
the interaction this log attests to, without the log ever having held the text.

| Mode | Digest | Text at rest | Use when |
| --- | --- | --- | --- |
| `hash` (default) | yes | none | you need proof an interaction happened, not what was said |
| `redact` | yes | with patterns replaced | you need readable transcripts and can accept best-effort masking |
| `store` | yes | verbatim | you have a legal basis, retention policy and access controls for it |

`store` and `redact` keep text, which means someone will eventually ask you to
delete it. `--content-encryption` encrypts stored content under a key held
outside the chain, so `flugschreiber erase` can destroy the key rather than the
evidence: the content becomes unreadable, the hash chain still verifies from the
beginning, and the log gains a record saying what was erased and when. The
digests stay as written, and erased content is always labelled as erased, never
rendered as empty.

```bash
flugschreiber serve --upstream http://vllm:8000 \
  --content-mode redact --redact-patterns email,iban,credit_card
```

Pattern-based redaction is best-effort by nature and the generated
documentation says so. Free text carries personal data in shapes no regular
expression will match.

## Keeping the signing key somewhere else

The chain plus signed checkpoints means the log cannot be rewritten by anyone
who does not also hold the signing key. By default that key sits on the same
host as the evidence. Take the host, take both.

```bash
flugschreiber serve --upstream http://vllm:8000 \
  --signer exec:/usr/local/bin/pkcs11-sign \
  --signer-public-key /etc/flugschreiber/hsm-public-key.pem \
  --tsa-url https://freetsa.org/tsr
```

The helper reads a preimage on standard input and writes the detached Ed25519
signature back, as 64 raw bytes or 128 hex characters. That is the whole
protocol. A shell script around `pkcs11-tool` qualifies, and so does a small
client talking to whatever holds your keys. The helper is handed none of the
`FLUGSCHREIBER_` environment, so it never sees the upstream key or the events
token, and every signature is checked against the public key you named. That last
part is what catches a helper wired to the wrong slot at startup instead of in an
audit.

`--tsa-url` anchors each checkpoint to an RFC 3161 authority, so its time becomes
a third party's claim rather than this host's clock. Tokens are stored verbatim.
Flugschreiber checks that each one covers the checkpoint it is filed against, and
deliberately does not decide which authorities you should trust. An authority
that is down costs anchors and never records.

Rotating is `flugschreiber keys rotate`. It keeps every retired public key,
because checkpoints signed before a rotation are still evidence. With an
external signer the rotation happens at the helper, so run
`flugschreiber keys retire --key <old public key>` before you repoint
`--signer-public-key`, or the checkpoints that key already signed become
unverifiable.

Checkpoints are chained to each other, so removing one is detectable. On a log
you know is signed, `verify --require-attestation` and `--expect-head <hash>`
close the loop: record the head somewhere the proxy cannot write to, and a
wholesale replacement has nowhere to hide.

## What it does not do

The boundaries are as deliberate as the features. Knowing where they run is
part of evaluating the tool.

It does not make you compliant with anything. It produces evidence and
documentation inputs. The rest is work that people do.

It is not legal advice, and an LLM is not high-risk in itself. Obligations under
the AI Act attach to the use case, not to the technology. Whether Annex III
applies to your system is a determination you have to make.

The hash chain on its own proves the log is internally consistent, not who wrote
it. Signed checkpoints close most of that gap: verification checks each
signature *and* checks it against the chain, so rewriting the log without the
signing key leaves behind checkpoints that are validly signed and disagree with
the records they attest to. What remains is custody of the signing key, and an external signer moves that
off the host entirely. [SECURITY.md](SECURITY.md) maps the boundary.

It only sees traffic that goes through it. If an application can reach your
model server directly, Flugschreiber will not record it and will not know it
happened. Coverage is a network property, which is why the Helm chart ships a
NetworkPolicy.

It cannot see anything above the API boundary: which human made a request, what
your application did with the answer, whether anyone reviewed it. It cannot see
inside the model either. `model_served` and `usage` are self-reported by the
upstream. A model server that lies produces a log that faithfully records the
lie.

## Why not just use an observability tool

Langfuse, Helicone, Phoenix and friends are good, and if you are debugging a RAG
pipeline you should use one. They are built for a different job.

Observability answers "why did this request behave strangely," so it optimises
for sampling, fast search, and rich traces. Evidence answers "prove this is what
happened and that nobody changed it since," which needs different properties:
completeness rather than sampling, tamper-evidence, retention floors, and an
independent verifier a third party can run without your infrastructure.

The features that overlap are usually the ones behind the enterprise plan:
audit logging, retention controls, data residency, compliance exports. Here
they are the product, Apache-2.0, self-hosted, with no telemetry and no
phone-home of any kind.

You can run both. They are not competing for the same slot.

## Kubernetes

```bash
helm install flugschreiber ./deploy/helm/flugschreiber \
  --set config.upstream=http://vllm:8000 \
  --set networkPolicy.modelServer.enabled=true
```

The chart runs one replica by default and makes it hard to run more, because each
replica owns its own hash chain and two sharing a volume would interleave records
and break both. It ships a NetworkPolicy that permits ingress to your model
server only from the proxy, which is what turns "we record our model calls" into
a claim you can defend, and a CronJob that runs `verify` on a schedule against a
read-only mount so a broken chain pages someone.

Or run it directly. It runs as UID 65532 on a read-only root filesystem with all
capabilities dropped:

```bash
docker run -d --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt=no-new-privileges \
  -p 8080:8080 -v fs-evidence:/var/lib/flugschreiber \
  ghcr.io/ramazankara/flugschreiber:latest serve --upstream http://vllm:8000
```

The image is distroless static, 20 MB, with no shell and no package manager. It
needs `--tmpfs /tmp` only so that `report` and `export` have somewhere to write;
`serve` itself writes nothing outside the evidence volume.

## Configuration

Flags beat environment variables, which beat the config file. Everything has a
`FLUGSCHREIBER_`-prefixed environment variable.

| Flag | Environment | Default | What it does |
| --- | --- | --- | --- |
| `--listen` | `FLUGSCHREIBER_LISTEN` | `:8080` | Listen address |
| `--upstream` | `FLUGSCHREIBER_UPSTREAM` | | Upstream base URL |
| `--mock-upstream` | `FLUGSCHREIBER_MOCK_UPSTREAM` | `false` | Built-in fake model server |
| `--data-dir` | `FLUGSCHREIBER_DATA_DIR` | `/var/lib/flugschreiber` | Evidence directory |
| `--content-mode` | `FLUGSCHREIBER_CONTENT_MODE` | `hash` | `store`, `hash` or `redact` |
| `--redact-patterns` | `FLUGSCHREIBER_REDACT_PATTERNS` | | `email`, `iban`, `credit_card`, `ipv4`, `phone`, or `label=regexp` |
| `--retention-days` | `FLUGSCHREIBER_RETENTION_DAYS` | `180` | Minimum retention, floor of 180 |
| `--tls-cert`, `--tls-key` | `FLUGSCHREIBER_TLS_CERT_FILE`, `..._KEY_FILE` | | Serve TLS |
| `--events-token` | `FLUGSCHREIBER_EVENTS_TOKEN` | | Enables the oversight events endpoint; it stays off while empty |
| `--no-sign` | `FLUGSCHREIBER_SIGNING_DISABLED` | `false` | Stop signing checkpoints |
| `--checkpoint-interval` | | `5m` | How often to sign the chain head |
| `--signer` | `FLUGSCHREIBER_SIGNER` | | `exec:<command>` signs checkpoints through an external helper, so the private key never has to live beside the evidence |
| `--signer-public-key` | `FLUGSCHREIBER_SIGNER_PUBLIC_KEY` | | The key that helper is supposed to hold; a signature that does not verify against it is refused at once |
| `--tsa-url` | `FLUGSCHREIBER_TSA_URL` | | RFC 3161 timestamping authority to anchor checkpoints to |
| `--tsa-interval` | `FLUGSCHREIBER_TSA_INTERVAL` | `1h` | How often to anchor; an authority is somebody else's rate-limited service |
| `--retention-max-bytes` | `FLUGSCHREIBER_RETENTION_MAX_BYTES` | | Size cap on the evidence directory. It reports; it never deletes below the retention floor |
| `--content-encryption` | `FLUGSCHREIBER_CONTENT_ENCRYPTION` | `false` | Encrypt stored content, so an erasure can destroy a key rather than the chain |
| `--content-keystore` | | beside the evidence | Where the content keys live. Put them off the snapshotted volume: a key inside a backup survives the erasure meant to destroy it |
| `--force-writer-lock` | | `false` | Take the directory when another writer appears to hold it. Only for a holder on another host that is known to be stopped |
| `--upstream-ca` | `FLUGSCHREIBER_UPSTREAM_CA_FILE` | | Extra roots trusted for the upstream connection |
| `--organisation`, `--system-name`, `--purpose`, `--contact` | `FLUGSCHREIBER_ORGANISATION`, … | | Pre-fill the generated documentation |

Multiple model servers behind one proxy are a config-file matter rather than a
flag: `upstreams` is a list of routes, each with its own URL, API key, TLS
settings and a set of model globs and endpoint kinds it serves. One route is
marked `default`. It is file-only because a route is structured, and flattening
it into an environment variable would produce a syntax nobody could read back.

The proxy refuses to start with retention under 180 days. Article 19 expects at
least six months of automatically generated logs where they are under the
provider's control, and a warning in a startup log is a warning nobody reads.
[DECISIONS.md](DECISIONS.md) explains that and every other choice, including the
ones that cost something.

Client credentials pass through untouched. If a caller sends no `Authorization`
header, the proxy can inject a configured key. The caller's credential is hashed
with a per-installation salt and truncated before it is written, so the log
tells you which caller made a request without holding the key.

## Overhead

p50 round trip through the proxy is around 0.5 ms against the mock upstream,
measured over 200 requests, including the mock's own work. Time to first byte on
a streamed response is roughly 0.3 ms.

```bash
make overhead
```

Streaming is relayed frame by frame, not buffered, and there is a test that
fails if that regresses. Bodies are teed rather than buffered, so the digest
covers a 100 MB request without holding it in memory. The evidence record is
written after the response finishes, so the store is never on the client's
critical path.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) is the package map and the invariants, enforced by a test
- [ROADMAP.md](ROADMAP.md) is what shipped, what is deliberately not planned, and the gaps that remain
- [docs/tamper-evident-llm-audit-logs-on-kubernetes.md](docs/tamper-evident-llm-audit-logs-on-kubernetes.md) is the Kubernetes guide
- [MAPPING.md](MAPPING.md) maps every schema field to the provision it supports (Articles 12, 19, 26, 50, 73) and says where the support runs out
- [docs/SCHEMA.md](docs/SCHEMA.md) is the log format and the compatibility policy
- [docs/STABILITY.md](docs/STABILITY.md) is what the command line promises: which surfaces are frozen, and what the exit codes mean
- [DECISIONS.md](DECISIONS.md) is why things are the way they are
- [SECURITY.md](SECURITY.md) is the threat model, including what it does not defend against
- [CONTRIBUTING.md](CONTRIBUTING.md)

## Timeline

Dates below follow the timeline after the Digital Omnibus agreement. Check them
against the current text before you plan around them.

| Date | What applies |
| --- | --- |
| 2 August 2026 | Article 50 transparency obligations |
| 2 December 2026 | New prohibitions |
| 2 December 2027 | Annex III high-risk obligations |
| 2 August 2028 | Annex I obligations |

Within the first row, one duty starts later: Article 50(2) machine-readable marking
applies from 2 December 2026 for systems already on the market on 2 August 2026. The
50(1) interaction disclosure is not deferred.

## Building from source

Go 1.25 or later. There are no dependencies to fetch.

```bash
git clone https://github.com/RamazanKara/flugschreiber
cd flugschreiber
make build          # binaries in ./dist
make test           # everything, with the race detector
make acceptance     # the quickstart above, as a test
```

`go.mod` has no `require` block, and CI fails if one appears without a
corresponding entry in DECISIONS.md.

### Recording the demo

`scripts/demo.sh` is the exact sequence in the demo animation; `DEMO_SPEED=0`
runs it without the typing pauses. The committed GIF and mp4 under `docs/media`
are rendered from its transcript, so re-recording after a change is: run the
script, re-render, commit.

## Commands

| Command | What it does |
| --- | --- |
| `serve` | Run the recording proxy |
| `verify` | Check chain integrity and checkpoint signatures, offline |
| `report` | Generate the Annex IV skeleton and Article 50 packs in English and German, as Markdown and HTML, plus PDF with `--pdf` |
| `export` | Package the evidence for a third party, without the signing key |
| `inspect` | Reconstruct a session, including the human decisions around it |
| `coverage` | Report what was captured, at what fidelity, and where the log is quiet |
| `retention` | Report on retention, enforce it, or place a legal hold |
| `keys` | Show or rotate the checkpoint signing key, keeping every retired public key |
| `archive-verify` | Check that the offsite archive holds every sealed segment |
| `erase` | Destroy the stored content of a session, leaving the chain intact |
| `repair` | Finish a write a power loss interrupted, so the server can start again |

Three are worth calling out.

`export` produces a tarball containing the segments, the signed checkpoints, the
public key, a manifest of SHA-256 digests, and a `VERIFY.md` written for someone
who has never heard of this tool. It refuses to include the signing key or the
client salt, so a recipient can verify everything and reverse nothing.

`report` writes both language editions by default. `--lang en` or `--lang de`
narrows it. The German Annex IV skeleton is a full translation using the official
Anhang IV terminology rather than a string swap, because the person who has to
fill in the TODOs is often a German-speaking DPO, and a machine-flavoured
translation of a legal document is worse than none.

`retention` will not delete anything without two flags. `--enforce` prints the
plan; `--enforce --confirm` carries it out. It removes whole segments only,
oldest first, and only when every record in them is beyond retention. A
`LEGAL_HOLD` file blocks it entirely. Afterwards the log reports itself as
*pruned*, never as intact from the beginning, because those are different claims
and only one is true.

## Answering an erasure request

Storing prompts means someone will eventually ask you to delete one person's
data, and the obvious implementation, going back and blanking the fields, breaks
the chain from that record onwards. So it is not the implementation.

With `--content-encryption`, prompts and completions are sealed under a
per-session key held in a keystore beside the evidence but outside the chain.
Erasing destroys the key:

```bash
flugschreiber erase --dir /var/lib/flugschreiber --session sess-42 \
  --requester dpo@muster.example --reason "Article 17 request" --confirm
```

Nothing is rewritten and no segment is deleted. The chain verifies afterwards
exactly as before, the content is unreadable to everyone including you, and the
erasure is itself appended to the log, so the record says what was destroyed,
when, and on whose request. Without `--confirm` the command prints what it would
destroy and changes nothing.

The digests stay as written, so the record still proves which interaction it
was, and `inspect`, `export` and the generated documentation label erased
content as erased, with the date. The precise evidentiary weight of a digest
after an erasure is spelled out in [MAPPING.md](MAPPING.md), where an auditor
will look for it.

## Recording human oversight

Article 14 asks for oversight that works in practice. Proving that later needs a
record of what a person actually did, in the same tamper-evident log as the
interaction they did it about.

```bash
curl $BASE/flugschreiber/v1/events -H "Authorization: Bearer $TOKEN" \
  -d '{"event_type":"human_intervention","ref_request_id":"ce71fbc9...",
       "actor":"alice@muster.example","decision":"override",
       "note":"Model advised refusing. Agent approved the refund under policy 4.2."}'
```

The endpoint returns 404 until you set `--events-token`, because an
unauthenticated writer to an evidence log lets anyone forge an oversight record,
and the chain would make the forgery look authoritative. It also refuses
`event_type: inference`: callers may describe what a human did, never what a
model did.

The same endpoint records serious incidents, which Article 73 asks providers to
report to the market surveillance authority:

```bash
curl $BASE/flugschreiber/v1/events -H "Authorization: Bearer $TOKEN" \
  -d '{"event_type":"incident","severity":"serious","ref_request_id":"ce71fbc9...",
       "actor":"alice@muster.example",
       "note":"Model output led to a wrongly denied claim. Ticket INC-4471."}'
```

`severity` is one of `suspected`, `serious` or `resolved`. This is the durable,
tamper-evident note that an incident was seen and how serious someone judged it,
and the report pre-fills the post-market section from it. It is not the report to
the authority, and Flugschreiber does not decide reportability or track the
deadlines. Those are a human and legal process.

## Status

Everything on the roadmap through v0.5.0 is shipped. v0.5.0 hardened the
failure paths on the way to 1.0: checkpoints chain to each other so a removed
attestation is detectable, the single-writer rule is enforced by the binary, a
crash-damaged log is repairable in one command, and a frozen conformance
fixture pins the evidence format for the long term.
[docs/STABILITY.md](docs/STABILITY.md) states the stability contract.

Recording: proxy with streaming capture across chat, completions, embeddings and
the Responses API, tool calls and tool results, multi-upstream routing by model
and endpoint kind, three content modes with optional encryption at rest.

Evidence: hash-chained store, Ed25519-signed checkpoints, key rotation that keeps
every retired public key, external signing helpers for off-host key custody, RFC
3161 timestamp anchoring, S3 archival of sealed segments with `archive-verify`,
retention with a legal hold and a size cap that reports rather than deletes.

Output: `verify`, `report` in Markdown, HTML and PDF in English and German,
`export`, `inspect`, `coverage`, `keys`, `erase`, the oversight and incident
events endpoint, Prometheus metrics with a Grafana dashboard and alert rules, a
Helm chart, and the Docker quickstart.

Issues and pull requests welcome, particularly from anyone who has been through
an actual audit and can tell us what a regulator asked for.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

Flugschreiber is German for flight recorder. The black box does not fly the
plane, and it does not stop crashes. It just means that afterwards, you know
what happened.
