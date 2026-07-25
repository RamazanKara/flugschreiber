# Evidence log schema

Schema version: **1**

## File layout

```
/var/lib/flugschreiber/
  seg-00000001.jsonl    # chained records, append-only
  seg-00000002.jsonl
  checkpoints.jsonl     # signed attestations of the chain head over time
  timestamps.jsonl      # RFC 3161 tokens anchoring checkpoints, if anchoring is on
  public-key.pem        # Ed25519 public key, PKIX, always exported
  keys/retired-*.pem    # public halves of rotated-out keys, always exported
  signing-key.pem       # Ed25519 private key, PKCS#8, mode 0600, NEVER exported
  client-salt           # 32 random bytes, mode 0600, NEVER exported
  content-keys.json     # wrapped content keys, mode 0600, NEVER exported
  pruned.json           # present only once retention has deleted segments
  LEGAL_HOLD            # present only while a hold is in force
```

The private files never leave the host. `signing-key.pem`, `client-salt` and
`content-keys.json` are excluded from every export twice over: the collector
only ever gathers known-good filenames, and anything in the secret set is then
refused with an error rather than skipped, so a future bug in the first layer
cannot become a leaked key. A recipient of an evidence bundle can verify everything
and reverse nothing.

Every public key is exported, including retired ones. A checkpoint signed before
a rotation is still evidence, and a bundle that carried only the current key
would strand it.

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

**`event_bytes` means the exact byte span the `event` member occupies in the
line, as it appears in the file.** Not a re-serialisation of the parsed value.
Take the substring and hash it; do not parse it and print it again. This is the
one rule a reimplementation has to get right, and getting it wrong produces a
false accusation of tampering rather than an obvious failure, so it is worth
being blunt about.

Two properties of the file make the distinction bite. Go's JSON encoder escapes
`<`, `>` and `&` as `\u003c`, `\u003e` and `\u0026`, so a prompt containing
HTML, XML, code or an ampersand is stored escaped, and a reader that parses and
re-serialises will emit the literal characters instead and compute a different
digest. Whitespace inside the object is equally load-bearing: a record written
by hand with spaces between the members hashes differently from the same value
written compactly, and both are valid JSON for the same event.

In Python that is `raw[line.index(b'"event":') + 8:-1]` territory rather than
`json.dumps(json.loads(line)["event"])`. Most JSON libraries expose the raw span
somehow: Go has `json.RawMessage`, Rust's serde has `&RawValue`, and in the
worst case a byte scan for the member and a brace-matching walk is a dozen lines
and exact.

`testdata/conformance/` in the repository holds a small evidence directory with
its expected head hash, written specifically so a reimplementation can check
itself against bytes rather than against prose. It includes content with
escaped characters and non-ASCII text for this reason.

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
  "upstream_previous_id": "resp-4b1a0c",
  "params": { "temperature": 0.2, "max_tokens": 512 },
  "usage": { "prompt_tokens": 180, "completion_tokens": 64, "total_tokens": 244 },
  "stream": true,
  "finish_reasons": ["stop"],
  "tool_calls": [
    { "index": 0, "id": "call_1", "name": "lookup_order", "arguments_sha256": "..." }
  ],
  "tool_results": [
    { "call_id": "call_1", "sha256": "...", "bytes": 214 }
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
[MAPPING.md](../MAPPING.md), and the machine-readable form is
[event.schema.json](schema/event.schema.json), which a test keeps in step with
the code.

`tool_calls` is what the model asked for. `tool_results` is what your application
sent back on the next turn, digested in every content mode on the same rule as
prompts and completions. `upstream_previous_id` is the Responses API's
`previous_response_id`, which is how a multi-turn conversation is stitched
together when the turns are separate HTTP requests.

Events other than `inference` carry a different subset. A `human_intervention`
carries `actor`, `decision`, `ref_request_id` and `note`; an `incident` carries
`severity`, one of `suspected`, `serious` or `resolved`, alongside the actor and
the interaction it concerns. Both are written through the authenticated events
endpoint, never by the proxy, because only a person can conclude that something
went wrong.

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

### Encrypted content and erasure

With content encryption on, the text-bearing fields are replaced by
`payload.ciphertext` and the record carries a `content.encryption` object naming
the algorithm and the key that wraps it. The digest is unchanged: it is still
over the plaintext wire bytes, so an encrypted record proves exactly what an
unencrypted one proves.

Erasure destroys the key, never the record. `flugschreiber erase` deletes the
wrapped key from the keystore and appends a `system_event` saying what was
erased and when; the ciphertext stays where it is, so the chain verifies from the
beginning exactly as before. `content.encryption.erased` and `erased_at` are how
a reader is told the difference between content that was never captured and
content that was captured and then destroyed.

The digest survives the erasure and this is the part to be exact about. It
remains a true statement about bytes that once existed, and it can no longer be
checked against them by anyone, including you. It is a claim that can no longer
be re-proven, and nothing in the tool will present it as more than that.

## Signed checkpoints

The hash chain proves a log is internally consistent. It does not prove who
wrote it: anyone who can rewrite the whole directory can recompute a chain that
verifies. Checkpoints close that gap by periodically signing the chain head with
a key that lives outside the log.

`checkpoints.jsonl`, one object per line, append-only:

```json
{
  "version": 1,
  "segment": "seg-00000002.jsonl",
  "seq": 4210,
  "record_hash": "a17b...",
  "records": 4210,
  "timestamp": "2026-05-04T08:31:00.123456789Z",
  "key_id": "3f9a1c04b7e25d18",
  "signature": "9c2e..."
}
```

The signature is Ed25519 over this preimage, newline-delimited and
domain-separated so it can never be confused with a record hash:

```
flugschreiber-checkpoint-v1
version:<decimal>
segment:<name>
seq:<decimal>
record_hash:<hex>
records:<decimal>
timestamp:<rfc3339nano>
key_id:<hex>
```

Checkpoints are written on every segment rotation, on a timer, and on clean
shutdown. `key_id` is the first 16 hex characters of the SHA-256 of the PKIX DER
public key.

Verification does two things, and the second one is the point:

1. Check the signature against `public-key.pem`.
2. Check the checkpoint against the actual chain. The record at `seq` must carry
   `record_hash`. A checkpoint whose signature is valid but whose hash does not
   match the chain means the log was rewritten after that checkpoint was signed.

An attacker who rewrites the directory but does not hold the signing key cannot
produce checkpoints that satisfy step 2. That is the whole value of the
mechanism, and it is why the private key should not live on the same host as the
evidence for anything you care about.

The key is only as good as its custody. Everything in `SECURITY.md` about that
still applies.

## Pruning anchor

Retention deletes whole segments from the front of the log, which breaks the
walk from the genesis hash. Deletion therefore leaves an anchor recording where
the surviving chain legitimately begins.

`pruned.json`:

```json
{
  "version": 1,
  "pruned_at": "2026-11-02T03:00:00.000000000Z",
  "last_pruned_seq": 1203,
  "last_pruned_hash": "77c1...",
  "segments": ["seg-00000001.jsonl", "seg-00000002.jsonl"],
  "records": 1203,
  "reason": "retention policy: 180 days",
  "key_id": "3f9a1c04b7e25d18",
  "signature": "4b81..."
}
```

When it exists, verification expects the first surviving record to carry
`prev_hash == last_pruned_hash` and `seq == last_pruned_seq + 1`, rather than the
genesis hash and sequence 1.

A pruned log is reported as pruned, never as intact from the beginning. The
distinction matters: "this log is complete and unaltered" and "this log is
unaltered since we deleted the first 1203 records under a stated retention
policy" are different claims, and only one of them is true after a prune.

## Legal hold

A file named `LEGAL_HOLD` in the evidence directory. Its contents are a
human-written reason. While it exists, retention enforcement deletes nothing and
says so.

It is checked at enforcement time rather than cached, so dropping the file in
place stops the next scheduled deletion without restarting anything.

## Archive layout

When an archive backend is configured, the store ships a copy offsite. It is
archival and never the write path: object stores cannot append, so the local
segment is always primary.

```
segments/seg-XXXXXXXX.jsonl                     sealed segments, final
open/seg-XXXXXXXX.seq-NNNNNNNNNNNN.jsonl        the segment still being written
checkpoints/checkpoints.seq-NNNNNNNNNNNN.jsonl  snapshot at that chain head
timestamps/timestamps.bytes-NNNNNNNNNNNN.jsonl  snapshot at that file length
public-key.pem
keys/retired-<key id>.pem                       every key a checkpoint names
```

Only sealed segments have final names. Everything that is still growing goes up
as a snapshot under a key naming what that snapshot covers, so an archive with
Object Lock never has to overwrite an object.

`pruned.json` and `LEGAL_HOLD` stay on the host: they describe this
installation's deletions and holds rather than the evidence. A directory
reassembled from the archive alone therefore verifies, but it is not a complete
evidence directory, and `flugschreiber archive-verify` says which parts of a
full check it could and could not perform.

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
