# Decisions

Every choice here was made deliberately and can be revisited. The point of
writing them down is that the next person, including future us, can tell the
difference between a decision and an accident. Each entry says what was decided,
why, and what it cost, because a decision record that only lists benefits is a
sales page.

## D1. Zero external dependencies

The module has no `require` block. Standard library only.

This is a tool whose entire value is that you can trust what it wrote. Every
dependency is a party that can change what ends up in an evidence file, and a
supply-chain question an auditor is entitled to ask. A `go.mod` with no
dependencies answers that question in one line. It also means `go build` works
offline, the container has nothing to scan, and there is no upgrade treadmill on
a tool that should still verify a 2026 log in 2032.

The cost is real but small. No YAML config, so config is JSON. No Prometheus
client, so metrics will be hand-rolled text exposition in M2. No CLI framework,
so flag parsing is `flag`. Each of these is slightly more code than the library
version, and all of them are boring code.

Worth revisiting if the Helm chart or the S3 backend genuinely cannot be built
without one. The AWS SDK is the most likely first exception, and a plain
SigV4-signed `net/http` client is the alternative.

## D2. The event is hashed as opaque bytes, not as a parsed struct

Each line is an envelope holding `seq`, `timestamp`, `prev_hash`, `record_hash`
and `event`, where `event` is carried and hashed as raw JSON.

The obvious design is to hash the marshalled struct. That works until someone
adds a field, changes an `omitempty`, or reorders a declaration. At that point
every historical log fails to verify against the new binary, and the failure
looks exactly like tampering. Hashing the bytes as they were written means a
verifier compiled today can check a chain written by a version whose schema it
has never seen.

The cost is one extra level of nesting in the file format, and unmarshalling
twice to read a record.

## D3. SHA-256 chain now, Ed25519 signed checkpoints in M2

M1 ships hash chaining only. Signing lands in M2.

The chain alone detects any modification, insertion or deletion within the log,
which is the failure mode that actually occurs: a well-meaning engineer editing
a file, a partial restore, a corrupted copy. Signed checkpoints defend against a
harder and rarer threat, someone with write access to the whole directory
rewriting it end to end. That defence is worth building and it is not what
stands between a user and the five-minute demo.

The cost is that until M2 the chain proves internal consistency, not authorship.
This is stated in the generated documentation at section 3.4 and in
`SECURITY.md`, rather than left for a reader to work out.

## D4. `hash` is the default content mode

By default Flugschreiber records a SHA-256 of request and response bytes and no
prompt or completion text.

Defaults are policy. Most operators run whatever ships, so the shipped default
has to be the one that is defensible without a conversation. A proxy that stores
every prompt by default turns each deployment into a fresh copy of whatever
users type into a chat box, held in a system nobody scoped for it, and GDPR
Article 5(1)(c) has an opinion about that.

The digest is computed over the exact wire bytes in every mode. That is what
makes hash mode useful rather than merely safe: an operator holding a transcript
from elsewhere can prove it is the transcript of the interaction the chain
attests to, without the log ever having held the text.

The cost is that out of the box you cannot read back what was said. Operators
who need transcripts set `--content-mode store` or `redact`, and take on the
retention and access-control obligations that follow.

## D5. Bodies are teed, not buffered

Request and response bodies stream through the proxy while a tap hashes the full
stream and retains a bounded 8 MiB prefix for parsing.

Buffering the response would break streaming, which is the thing chat UIs depend
on and the thing a naive recording proxy gets wrong. Buffering the request would
put a large multimodal upload into memory twice. Teeing gives a correct digest
over the complete body regardless of size, at the cost of parsing metadata only
from the prefix.

For a body larger than 8 MiB the parsed metadata comes from that prefix. Since
`model` and `stream` sit at the top of a request object this has no practical
effect, and the record is marked `truncated` when it happens, so it is never
silent.

## D6. Records are appended after the response completes

The evidence record is written when the response body is closed, inside the same
handler invocation, not before the client is served.

The record has to describe what actually happened, including the finish reason,
token usage and assembled output, none of which exist until the response is
done. Writing on the request path would also add the store's latency to every
call.

The cost is a small window: a request that has completed from the client's point
of view may be recorded microseconds later, and a process killed in that window
loses that one record. Records are flushed to the OS individually, so a crash
cannot lose anything already written. `fsync` runs on a one-second timer and on
shutdown, so only a machine-level failure loses the last second.

If an operator ever needs a synchronous durability guarantee per request, that
should be a config option rather than a new default.

## D7. Backpressure, never dropped evidence

`Append` blocks when the writer queue is full.

An evidence tool that silently drops records under load is worse than no
evidence tool, because the gap is invisible and the log still looks complete.
Slowing down is a symptom an operator can see and act on.

The cost is that a pathologically slow disk becomes proxy latency. The queue is
4096 records deep, so reaching that requires sustained failure rather than a
spike.

## D8. Client identity is a salted hash

The caller's credential is hashed with a per-installation salt, truncated to 128
bits, and stored as `client_hash`. The salt lives at `<data-dir>/client-salt`,
mode 0600, generated on first start.

Attribution needs a stable identifier per caller. Nobody needs the API key. An
unsalted hash of an API key is reversible by anyone with a list of candidate
keys, and a per-installation salt additionally stops identifiers being
correlated across two deployments.

The salt is excluded from evidence exports, so a regulator receiving a bundle
can distinguish callers but cannot map an identifier back to a person without
the operator's help. That is the intended property rather than a shortcoming.

## D9. One binary, two entrypoints

`flugschreiber` has `serve`, `verify` and `report` subcommands. `proxyd` is a
second binary that is only `serve`.

The brief named a `proxyd` proxy and a `flugschreiber` CLI. Shipping one
artifact means the binary that recorded the evidence is the binary that verifies
it, and an auditor needs to obtain exactly one thing. `proxyd` exists for
deployments that want an entrypoint which structurally cannot read the evidence
directory. Both compile from `internal/cli`, so they cannot drift apart.

The cost is a marginally larger proxy image, which distroless makes irrelevant.

## D10. The Article 50 pack ships in M1, ahead of its milestone

`report` generates the transparency pack in German and English now, although the
milestone plan places it in M2.

The acceptance demo is the definition of done and it lists the transparency pack
as an output of `flugschreiber report`. The pack is static prose with a few
substitutions, it cost about an hour, and it completes the demo. Milestone
discipline exists to prevent scope creep, not to prevent the headline
deliverable from working.

Nothing material was given up. M2 still owns the HTML render of these documents.

## D11. Retention below 180 days is refused

`Validate` returns an error rather than a warning when `retention_days` is under
180.

Article 19 expects at least six months of automatically generated logs where
they are under the provider's control. A warning in a startup log is a warning
nobody reads. Refusing to start forces the decision to be made by a person, at a
moment when they can still change it.

The cost is friction for an operator who deliberately wants shorter retention,
who has to change the floor in the source to get it. That friction is the point.
Retention is recorded as configuration in M1; automated enforcement and legal
hold are M3.

## D12. Parsing failures never cost a record

Every parser returns a best-effort result and no error. A malformed request body,
an unparseable SSE frame, or an unfamiliar response shape costs a field, never
the record.

A recording proxy that refuses to log traffic it does not fully understand fails
precisely when it matters most, in front of an upstream that is behaving
strangely. The metadata is a convenience. The digest, the timestamp and the
chain position are the evidence, and those are computed from bytes rather than
from a successful parse.

The cost is that a record can have an empty `model_requested`. An honest gap in
one field beats a hole in the log.

## D13. The mock upstream announces itself in its output

Every mock response contains the sentence "No model was involved in producing
this text."

The mock exists so the quickstart runs with no GPU. Its output ends up in
evidence files and, from there, potentially in a generated document. Text that
could be mistaken for a model's output inside a compliance artifact is a
liability, and making it self-identifying costs nothing.

## D14. Module path is provisional

`github.com/flugschreiber/flugschreiber`.

Something had to be chosen in order to build. The name is a working title and
the organisation does not exist yet.

Settle this before the first tagged release. Changing it later is a breaking
change for anyone importing the packages, though nothing outside `cmd/` is
exported today.
