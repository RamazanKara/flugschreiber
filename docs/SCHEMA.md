# Evidence log schema

Schema version: **1**

## File layout

An evidence directory contains numbered segments and a salt file:

```
/var/lib/flugschreiber/
  seg-00000001.jsonl
  seg-00000002.jsonl
  client-salt          # 32 random bytes, mode 0600, never exported
```

Each segment is newline-delimited JSON, one record per line, appended only.
Segments roll at 64 MiB by default. The chain continues across segments: the
first record of a segment carries the `record_hash` of the last record of the
previous one.

## Record envelope

```json
{
  "seq": 42,
  "timestamp": "2026-05-04T08:31:00.123456789Z",
  "prev_hash": "9f2c...",
  "record_hash": "a17b...",
  "event": { }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `seq` | integer | Monotonic, starts at 1, contiguous across the whole log |
| `timestamp` | string | RFC3339 with nanoseconds, UTC |
| `prev_hash` | string | `record_hash` of the previous record; 64 zeros for the first |
| `record_hash` | string | SHA-256 over the preimage below |
| `event` | object | The payload; hashed as raw bytes |

## Hash construction

```
preimage = "flugschreiber-record-v1\n"
         + "seq:"   + decimal(seq)            + "\n"
         + "ts:"    + timestamp               + "\n"
         + "prev:"  + prev_hash               + "\n"
         + "event:" + hex(sha256(event_bytes)) + "\n"

record_hash = hex(sha256(preimage))
```

Three properties of this construction are deliberate.

The domain string means a hash from this context can never be replayed as a hash
from another.

`event` is hashed as bytes rather than as a re-marshalled struct, so a verifier
compiled today can check a log written by a future version whose event fields it
does not understand. Hashing a parsed struct would make every schema change look
like tampering in historical logs.

No field can contain a newline: `seq` is decimal, `timestamp` is RFC3339, and
the hashes are hex. The delimiter is therefore unambiguous without length
prefixes.

Verification is `flugschreiber verify --dir <path>`. It reads only files, needs
no server, and exits non-zero if anything fails.

## Event payload

```json
{
  "schema_version": 1,
  "event_type": "inference",
  "request_id": "ce71fbc95de75029d96bfcbfbce7ec4b",
  "session_id": "sess-42",
  "client_hash": "c140d1009bb9f591c084a684502297e7",
  "endpoint": "/v1/chat/completions",
  "method": "POST",
  "upstream": "http://vllm:8000",
  "model_requested": "llama-3.1-8b-instruct",
  "model_served": "llama-3.1-8b-instruct",
  "upstream_response_id": "chatcmpl-8d768b29abbc8b42",
  "params": { "temperature": 0.2, "max_tokens": 512 },
  "usage": { "prompt_tokens": 180, "completion_tokens": 64, "total_tokens": 244 },
  "stream": true,
  "finish_reasons": ["stop"],
  "tool_calls": [
    { "index": 0, "id": "call_1", "name": "lookup_order", "arguments_sha256": "..." }
  ],
  "status": 200,
  "latency_ms": 812.4,
  "ttfb_ms": 1.2,
  "content": {
    "mode": "hash",
    "input":  { "sha256": "...", "bytes": 412 },
    "output": { "sha256": "...", "bytes": 903 }
  }
}
```

Absent fields are omitted rather than zero-filled, so a reader can distinguish
"not observed" from "observed as zero". Field meanings and their caveats are in
[MAPPING.md](../MAPPING.md).

### Content modes

`content.mode` records the fidelity in force when the record was written.

| Mode | `sha256`, `bytes` | `text`, `messages` | `redactions` |
| --- | --- | --- | --- |
| `hash` (default) | yes | no | no |
| `redact` | yes | yes, with matches replaced | yes |
| `store` | yes | yes, verbatim | no |

`sha256` is computed over the exact bytes that crossed the wire in **every**
mode, including `hash`. That is what lets a transcript held elsewhere be proven
to be the transcript of the interaction this log attests to.

For streamed responses, `output.sha256` covers the raw SSE bytes as received;
`output.text` (in `store` and `redact`) is the reassembled message the client
saw, not the frames.

## Compatibility policy

`schema_version` is an integer on every event.

Within a major version we will:

- add new optional fields
- add new `event_type` values
- add new fields inside `params`, `usage` and `content`

We will not, without bumping the version:

- remove a field
- change the type or meaning of an existing field
- change the hash construction or the envelope

A reader must ignore fields it does not recognise. Because the envelope hashes
the event as opaque bytes, adding fields never invalidates an existing chain,
and a verifier from any version can check a log from any other.

If the hash construction ever has to change, the domain string changes with it
(`flugschreiber-record-v2`), old segments keep verifying under the old rule, and
`verify` will handle both.
