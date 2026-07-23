# Field mapping: log schema to AI Act provisions

This document says which recorded field supports which obligation, and, more usefully,
where the support runs out.

Read this first: A field appearing in this table does not mean the
obligation is met. It means Flugschreiber records something an assessment of
that obligation would need. Article 12 asks for logging "appropriate to the
intended purpose"; only you know your intended purpose, so only you can judge
appropriateness. Nothing here is legal advice.

Schema version: **1**. See [docs/SCHEMA.md](docs/SCHEMA.md) for the
compatibility policy.

---

## Article 12: record-keeping

> High-risk AI systems shall technically allow for the automatic recording of
> events (logs) over the lifetime of the system.

| Field | What it records | Caveat |
| --- | --- | --- |
| `timestamp` | RFC3339 (nanosecond) time the record was written | The proxy's clock. If the host clock is wrong or moves, the timestamp is wrong. `seq` is the reliable ordering. |
| `seq` | Monotonic sequence number across the whole log | Ordering is by write completion, not by request arrival. Two concurrent requests are ordered by which finished first. |
| `event_type` | `inference`, `tool_call`, `tool_result`, `human_intervention`, `session_start`, `session_end`, `config_change`, `system_event` | The proxy writes `inference`; the authenticated events endpoint records the human and lifecycle types. `tool_result` has no writer yet and is reserved. |
| `request_id` | Unique per interaction, also returned to the caller as `X-Flugschreiber-Request-Id` | The link between an evidence record and anything your application logged about the same request. |
| `session_id` | Groups related interactions | Only populated when the caller sends `X-Flugschreiber-Session`. The proxy cannot infer a session it is not told about. |
| `schema_version` | Schema version of the record | |
| `endpoint`, `method`, `upstream` | Where the request went | `upstream` is scheme, host and path only; any credential in the configured URL is not recorded. |
| `status`, `error`, `latency_ms`, `ttfb_ms` | Outcome and timing | `latency_ms` is measured at the proxy, so it includes upstream time. |

Where this runs out: Article 12(3) contemplates logging over the *lifetime*
of the system, including events outside inference: deployment, configuration
change, model replacement. Flugschreiber sees the API boundary. Changes to
prompts, retrieval corpora, tool definitions and thresholds happen elsewhere and
have to be recorded elsewhere.

---

## Article 19: automatically generated logs

> Providers shall keep the logs ... for a period appropriate to the intended
> purpose of the high-risk AI system, of at least six months.

| Mechanism | What it does | Caveat |
| --- | --- | --- |
| Append-only JSONL segments | Records are only ever appended; nothing rewrites a written line | Enforced by the writer, not by the filesystem. Use append-only or object-lock storage if you need this enforced below the application. |
| `prev_hash` / `record_hash` | SHA-256 chain over every record | Detects modification, insertion and deletion. Does **not** prove authorship on its own; see below. |
| `checkpoints.jsonl` | Ed25519-signed attestations of the chain head, written on rotation, on a timer and at shutdown | Only as strong as the custody of `signing-key.pem`. A key stored beside the evidence protects against much less than a key stored elsewhere. |
| `public-key.pem` | Lets any third party check those signatures | Standard PKIX, readable with openssl. Always included in an export. |
| `retention_days` with a 180-day floor | Refuses to start below six months, and enforces deletion on request | Deletion removes whole segments only, oldest first, and only when every record in them is beyond retention. |
| `pruned.json` | Records what retention deleted and where the surviving chain begins | A pruned log verifies as *pruned*, never as intact from the beginning. |
| `LEGAL_HOLD` | Blocks all deletion while present | Checked at enforcement time, not cached. Its contents are the stated reason. |
| Segment rotation | Bounded files, chain continues across boundaries | |
| S3 archival of sealed segments | Ships rotated segments to object storage, with optional Object Lock | Archival, not the write path. S3 cannot append, so the local segment is always primary. |

Where this runs out, and this is the one to read carefully. The hash chain proves the log
is internally consistent. On its own it does not prove who wrote it: someone with
write access to the entire evidence directory could recompute the whole chain
from scratch and produce a log that verifies perfectly.

Signed checkpoints narrow that considerably. An attacker who rewrites the log
but does not hold the signing key cannot produce checkpoints whose signatures
verify *and* whose recorded head hashes match the rewritten chain. Verification
checks both, and a checkpoint that is validly signed but disagrees with the chain
is reported as a high-severity problem, because that combination is the signature
of a rewrite.

What remains: an attacker who holds the signing key can forge everything. So the
key's custody is the security boundary. Keep it off the host that holds the
evidence where you can, put segments on object-lock storage, and record the chain
head somewhere the proxy cannot reach. `SECURITY.md` has the rest.

---

## Article 26: obligations of deployers

> Deployers shall monitor the operation of the high-risk AI system on the basis
> of the instructions for use ... and keep the logs generated by that system.

| Field | What it records | Caveat |
| --- | --- | --- |
| `client_hash` | Salted SHA-256 of the caller's credential, truncated to 128 bits | Identifies a *credential*, not a person. Mapping it to a human needs your own identity system. The salt never leaves the host and is excluded from evidence exports. |
| `model_requested` / `model_served` | What was asked for and what the upstream reported serving | When these differ, the upstream substituted a model. Both are self-reported by the upstream and are not independently verified. |
| `params` | Generation parameters present in the request | Only parameters the caller sent explicitly. Upstream defaults are invisible to the proxy and have to be documented separately. |
| `usage` | Token accounting as reported by the upstream | Absent when the upstream does not report it, which is common for streaming without `stream_options.include_usage`. |
| `tool_calls` | Function calls the model requested, with name and index | The *request* to call a tool. Whether it was executed, and what it returned, happens in your application. |
| `finish_reasons` | Why generation stopped | `length` here is often the more interesting signal: it means output was cut off. |

Where this runs out: Article 26 also covers human oversight, input data
relevance, and informing affected persons. Flugschreiber records the
`human_intervention` event type once you send interventions to its events endpoint, but it
cannot design or perform oversight.

---

## Article 50: transparency

| Artifact | What it gives you | Caveat |
| --- | --- | --- |
| `transparency-article-50-en.md` | Chatbot disclosure snippets, placement checklist, guidance on marking AI-generated content | Drafting starting points. Not approved copy, not reviewed by a lawyer, not yours until someone signs off on them. |
| `transparency-article-50-de.md` | The same in German | Same caveat. |
| Observed traffic summary | Evidence that generation is happening and at what volume | Flugschreiber cannot see whether output reaches a natural person directly, which is what actually triggers 50(1). |

Where this runs out: Article 50(2) requires machine-readable marking of
synthetic output. Flugschreiber does not mark content. It is a proxy, and the
marking has to happen where content leaves your system. The guidance note in the
pack explains the practical options. `request_id` is offered as the key that
ties a marked artefact back to the evidence log.

---

## Annex IV: technical documentation

`flugschreiber report` generates a skeleton shaped like Annex IV. What can be
filled in from evidence is filled in; the rest is marked `TODO` with one
sentence on what belongs there.

| Annex IV section | Pre-filled from evidence? |
| --- | --- |
| 1. General description | Partly. Models, endpoints, interfaces and traffic shape are observed. Intended purpose, deployment form and hardware are not. |
| 2. Elements and development process | Partly. Generation parameters and tool definitions are observed. Training data, validation and development process are not. |
| 3. Monitoring, functioning and control | Mostly, for the logging and integrity parts. Human oversight and accuracy targets are not. |
| 4. Performance metrics | No. Traffic volume is not a quality metric. |
| 5. Risk management (Art. 9) | No, deliberately. A generated risk assessment would be worse than none, because it would look like one. |
| 6. Lifecycle changes | Partly. Model changes visible in traffic; everything else is not. |
| 7. Harmonised standards | No. |
| 8. Declaration of conformity | No. |
| 9. Post-market monitoring | No. The evidence log is an input to the plan, not the plan. |

---

## What Flugschreiber structurally cannot see

Worth stating plainly, because the gaps matter more than the coverage:

- **Anything above the API.** Which end user made a request, what the
  application did with the answer, whether a human reviewed it.
- **Anything inside the model.** Weights, training data, fine-tuning, and
  whether the upstream is serving the model it claims to.
- **Whether the output was correct**, useful, harmful, or acted upon.
- **Retrieval context**, unless it was injected into the prompt the proxy saw.
- **Traffic that does not pass through it.** Coverage is a deployment property.
  `flugschreiber coverage` reports what share of observed traffic was
  captured and in which mode, but it cannot report on traffic that bypassed the
  proxy entirely. If an application talks to the model server directly,
  Flugschreiber will not know and will not say so.

The last point is the one most likely to produce a false sense of coverage.
Network policy, not this proxy, is what makes the proxy unavoidable; the Helm
chart ships a `NetworkPolicy` for exactly this reason.
