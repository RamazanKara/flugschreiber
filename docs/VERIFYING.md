# Verifying a Flugschreiber log independently

You do not need Flugschreiber to check a Flugschreiber log, and if you are an
auditor holding evidence produced by the party you are auditing, you should not
want to: software supplied by that party is not what you validate their evidence
with. This document is the whole format, written so you can reimplement the
check in any language in an afternoon.

The reference implementation at the end uses only the Python standard library.

## What you are checking

A Flugschreiber evidence directory, or an exported bundle, contains:

| File | What it is |
| --- | --- |
| `seg-*.jsonl` | The records, one JSON object per line, appended and never rewritten |
| `checkpoints.jsonl` | Ed25519 signatures over the chain head at points in time |
| `public-key.pem` | The key those signatures verify against, PKIX format |
| `keys/retired-*.pem` | Public keys a rotation replaced; earlier checkpoints verify against these |
| `timestamps.jsonl` | RFC 3161 tokens, present only if anchoring was on |
| `pruned.json` | Present only if retention deleted the start of the log |

There are three independent checks, in increasing order of what they establish.

1. **The hash chain.** Every record commits to the one before it. Altering a
   record breaks the chain unless the affected hashes are recomputed. A valid
   chain alone cannot detect a full rewrite or removal of its tail.
2. **The checkpoint signatures.** Each checkpoint is signed and names a chain
   head. A log rewritten without the signing key cannot produce checkpoints that
   both verify and agree with the rewritten records.
3. **The checkpoint chain.** Checkpoints commit to each other, exposing gaps
   between retained checkpoints. Detecting removal of the tail needs an
   independently retained head.

You can perform check 1 with nothing but SHA-256. Checks 2 and 3 add Ed25519.

## Check 1: the hash chain

Each line of a `seg-*.jsonl` file is a record:

```json
{"seq":2,"timestamp":"2026-03-01T12:00:02Z","prev_hash":"...","record_hash":"...","event":{...}}
```

For each record, in file order, recompute `record_hash`:

```
preimage = "flugschreiber-record-v1\n"
         + "seq:"   + decimal(seq)             + "\n"
         + "ts:"    + timestamp                + "\n"
         + "prev:"  + prev_hash                + "\n"
         + "event:" + hex(sha256(event_bytes)) + "\n"

record_hash == hex(sha256(preimage))
```

`decimal(seq)` is the sequence number in base ten with no padding. `timestamp`
and `prev_hash` are the strings as they appear in the record.

**`event_bytes` is the exact byte span the `event` member occupies in the line,
taken from the file as it is.** This is the one rule to get right, and getting it
wrong produces a false accusation of tampering rather than an obvious failure, so
it is worth stating three times:

- Do not parse the event and re-serialise it. Take the raw substring.
- The writer escapes `<`, `>` and `&` as `\u003c`, `\u003e` and `\u0026`. A
  reader that decodes and re-encodes will produce the literal characters instead
  and compute a different digest, and will then report tampering on any prompt
  that contained HTML, code or an ampersand.
- Whitespace inside the object is part of the bytes. Two records that carry the
  same value with different internal spacing hash differently, and both are
  valid.

Most JSON libraries expose the raw span: Go has `json.RawMessage`, Rust's serde
has `&RawValue`, and Python's `json` gives you positions through `raw_decode`.
A manual scanner must distinguish top-level members and handle escaped quotes
and braces inside strings.

Then check the links:

- The first record's `prev_hash` is 64 zeros, unless `pruned.json` is present, in
  which case it is the `last_pruned_hash` that file records.
- Every later record's `prev_hash` equals its predecessor's `record_hash`.
- `seq` starts at 1 (or at the pruned-through sequence plus one) and increases by
  one with no gaps, across segment boundaries.

If all of that holds, the log is internally consistent. Establishing who wrote
it, or detecting a rewrite with recomputed hashes, requires checkpoint signatures
and a trusted public key. Detecting a removed tail also needs a retained head.

## Check 2: the checkpoint signatures

Each line of `checkpoints.jsonl` is a checkpoint:

```json
{"version":1,"segment":"seg-00000001.jsonl","seq":5,"record_hash":"...","records":5,
 "timestamp":"...","key_id":"...","signature":"...","index":0,"prev_checkpoint_hash":"...","chain_signature":"..."}
```

The signature covers this preimage:

```
"flugschreiber-checkpoint-v1\n"
+ "version:"     + decimal(version)     + "\n"
+ "segment:"     + segment              + "\n"
+ "seq:"         + decimal(seq)         + "\n"
+ "record_hash:" + record_hash          + "\n"
+ "records:"     + decimal(records)     + "\n"
+ "timestamp:"   + timestamp            + "\n"
+ "key_id:"      + key_id               + "\n"
```

`signature` is Ed25519 over that preimage, hex-encoded. The key is
`public-key.pem`, or the file under `keys/` named for the checkpoint's `key_id`
if a rotation has happened since it was signed. Verify each one.

Then cross-check it against the log: the checkpoint's `record_hash` must equal
the `record_hash` of the record at its `seq`. A checkpoint that verifies but
names a hash the log does not hold is the signature of a rewrite, and it matters
more than one that simply fails to verify.

If `version` is not 1, this build's preimage layout does not apply. Do not treat
that as a bad signature; it means the checkpoint was written by a newer format
than this document describes.

## Check 3: the checkpoint chain

A signature makes a checkpoint unforgeable and leaves it deletable: an attacker
who cannot sign can still remove attestations, and every one left behind still
verifies. The checkpoint chain closes that.

Each checkpoint carries an `index` counting from zero and a
`prev_checkpoint_hash`, and `chain_signature` is Ed25519 over:

```
"flugschreiber-checkpoint-chain-v1\n"
+ "checkpoint:"           + checkpoint_hash        + "\n"
+ "index:"                + decimal(index)         + "\n"
+ "prev_checkpoint_hash:" + prev_checkpoint_hash   + "\n"
```

where `checkpoint_hash` is:

```
hex(sha256( checkpoint_preimage + "signature:" + signature + "\n" ))
```

that is, the Check 2 preimage with the checkpoint's own signature appended. So a
successor commits to both what its predecessor said and who signed it.

Verify each `chain_signature`, then confirm the sequence has no holes: the first
checkpoint's `index` accounts for however many precede it, each later `index` is
one more than the last, and each `prev_checkpoint_hash` equals the previous
checkpoint's `checkpoint_hash`. A gap in the index, or a link that names a
checkpoint that is not there, is a deletion.

Checkpoints written before this field existed have no `chain_signature`. They are
still valid attestations of the heads they name; they simply predate deletion
detection.

## The timestamps

If `timestamps.jsonl` is present, each line carries an RFC 3161 token in
`token_base64` that covers the `record_hash` of the checkpoint at that sequence.
Base64-decode it and settle it with your own trust store:

```
openssl ts -verify -in token.tst -token_in -CAfile your-tsa-ca.pem -digest <record_hash>
```

Which authorities you trust is your decision, not the log's, which is why this
step is deliberately left to your tools.

## A reference implementation

This checks only the hash chain, using the Python standard library. It does not
verify checkpoint signatures, the checkpoint chain, prune-anchor signatures or
timestamp tokens; those require the additional checks described above.

```python
import glob, hashlib, json, os, sys

def record_hash(seq, ts, prev, event_bytes):
    inner = hashlib.sha256(event_bytes).hexdigest()
    pre = (b"flugschreiber-record-v1\n"
           b"seq:" + str(seq).encode() + b"\n"
           b"ts:" + ts.encode() + b"\n"
           b"prev:" + prev.encode() + b"\n"
           b"event:" + inner.encode() + b"\n")
    return hashlib.sha256(pre).hexdigest()

def event_span(line):
    text = line.decode("utf-8")
    decoder = json.JSONDecoder()
    i = text.index("{") + 1
    while True:
        while text[i].isspace() or text[i] == ",":
            i += 1
        if text[i] == "}":
            break
        key, i = decoder.raw_decode(text, i)
        while text[i].isspace():
            i += 1
        if text[i] != ":":
            raise ValueError("missing member separator")
        i += 1
        while text[i].isspace():
            i += 1
        start = i
        _, i = decoder.raw_decode(text, i)
        if key == "event":
            return text[start:i].encode("utf-8")
    raise ValueError("missing event member")

def check_chain(directory):
    prev = "0" * 64
    anchor = os.path.join(directory, "pruned.json")
    expect_seq = 1
    if os.path.exists(anchor):
        a = json.load(open(anchor))
        prev = a["last_pruned_hash"]
        expect_seq = a["last_pruned_seq"] + 1
    for seg in sorted(glob.glob(os.path.join(directory, "seg-*.jsonl"))):
        for raw in open(seg, "rb"):
            raw = raw.rstrip(b"\n")
            if not raw.strip():
                continue
            rec = json.loads(raw)
            if rec["seq"] != expect_seq:
                sys.exit(f"sequence gap: expected {expect_seq}, found {rec['seq']}")
            if rec["prev_hash"] != prev:
                sys.exit(f"broken link at seq {rec['seq']}")
            want = record_hash(rec["seq"], rec["timestamp"], rec["prev_hash"], event_span(raw))
            if rec["record_hash"] != want:
                sys.exit(f"hash mismatch at seq {rec['seq']}")
            prev = rec["record_hash"]
            expect_seq += 1
    print(f"hash chain intact through seq {expect_seq - 1}, head {prev}")

if __name__ == "__main__":
    check_chain(sys.argv[1])
```

## A frozen example to test your implementation against

The repository holds a frozen evidence directory at
[`testdata/conformance`](https://github.com/RamazanKara/flugschreiber/tree/main/testdata/conformance),
written by a released version and never regenerated. Its `EXPECTED.json` records
the head hash and every record hash. It deliberately contains HTML-escaped
characters, non-ASCII text, an embedded newline and a quote, because those are
exactly the inputs a re-serialising reader gets wrong. Run your implementation
against it and compare to `EXPECTED.json`; if your head hash matches, your event
handling is correct.
