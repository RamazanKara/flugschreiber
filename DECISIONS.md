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

`github.com/RamazanKara/flugschreiber`.

Something had to be chosen in order to build. The name is a working title and
the organisation does not exist yet.

Settle this before the first tagged release. Changing it later is a breaking
change for anyone importing the packages, though nothing outside `cmd/` is
exported today.

## D15. The events endpoint is off until an operator sets a token

`POST /flugschreiber/v1/events` records human oversight into the chain. It
returns 404 until `--events-token` is set.

An unauthenticated endpoint that appends to the evidence log would let anyone who
can reach the proxy fabricate an oversight record. A forged "reviewed and
approved by Alice" in a tamper-evident log is worse than no record at all,
because the chain makes it look authoritative. Requiring a token forces the
operator to make a decision about who may write oversight events.

The cost is one more thing to configure before the feature works. The 404 names
the flag, so the discovery cost is one error message.

## D16. The events endpoint cannot write inference records

`event_type: inference` is rejected with 400 and an explanation.

Inference records describe what a model did, and the only honest source for that
is traffic the proxy observed. If a caller could post one, anyone holding the
events token could fabricate a model interaction that verifies perfectly. The
API therefore accepts statements about what a human did and refuses statements
about what a model did.

## D17. A human_intervention must name an actor and a decision

Both are required, and the decision has to be one of approve, override, reject,
escalate, halt or annotate.

Free text is where oversight evidence goes to die. "Looked at it, seemed fine"
in a note field cannot be counted, filtered or reported on. A closed set of
outcomes means `coverage` can tell you how many model outputs a human actually
overrode, which is the question Article 14 conversations turn on.

The cost is that the vocabulary will be wrong for somebody. Adding a value is a
one-line change and, per the schema policy, not a breaking one.

## D18. Export is an allowlist, enforced twice

`flugschreiber export` collects only known filename shapes, then refuses with an
error if anything in the resulting list is a secret.

The signing key and the client salt are the two files that would let a recipient
forge evidence or reverse a caller identity. A denylist that silently skips them
turns a future bug (a renamed file, a new secret) into a leaked key. Collecting
by allowlist and then asserting the negative means a mistake produces a loud
failure rather than a quiet disclosure.

The test that proves this writes real sentinel values into both secret files and
greps the decompressed bundle for them.

## D19. Coverage reports quiet stretches, and says what they do not mean

`coverage` flags any period longer than the threshold in which nothing was
recorded.

This is the only signal a log can give about its own completeness. A gap means
either nothing was happening or the proxy was not recording, and the tool cannot
tell which. So it reports the gap and says exactly that, rather than either
hiding it or implying downtime.

What the command must never do is imply that captured traffic is all traffic.
Coverage of a system is a network property. The output says so on every run.

## D20. `inspect` explains an empty transcript rather than showing one

In the default hash mode there is no prompt or completion text to display.

A reconstruction that renders as an empty conversation reads as "nothing
happened". The renderer instead states that the content mode was hash, that a
digest of each request and response is recorded, and that the digests still
prove which interaction each record describes.

## D21. Checkpoint signing is on by default

`serve` generates an Ed25519 key on first start, alongside the client salt and
at the same mode 0600, and signs the chain head on every segment rotation, every
five minutes, and at clean shutdown. `--no-sign` turns it off.

The hash chain alone proves that nobody edited the log without rewriting all of
it. Checkpoints raise that to: nobody rewrote it without also holding the signing
key. That is a materially stronger claim and it costs one signature every few
minutes, so making an operator opt in would mean most deployments run with the
weaker property by accident. Defaults are policy.

Verification does two things with a checkpoint, and the second is the one that
matters: it checks the signature, and it checks the checkpoint against the actual
chain. A checkpoint that is validly signed but whose recorded head hash does not
match the record at that sequence is reported as high severity, because that
combination is the fingerprint of a rewrite.

The cost is a private key on the same host as the evidence, which bounds how
much the mechanism can prove. `SECURITY.md` says so, and says what to do about
it. An operator who wants the weaker property states that with `--no-sign`.

## D22. S3 is an archival target, not the write path

Sealed segments are uploaded to object storage when they rotate. The local
segment is always primary and is always written first.

S3 cannot append. Pretending otherwise means either buffering records until a
segment closes, which loses evidence on a crash, or one object per record, which
is slow and expensive and still not atomic with the chain. Uploading sealed
segments matches how object lock and WORM buckets actually work: the object
becomes immutable precisely because nothing will append to it again.

Uploads never block the writer goroutine and an upload failure never fails an
append. A proxy that stops recording because an object store is unreachable has
turned a storage outage into an evidence gap.

## D23. The evidence store defines the archiver interface, not the archive package

`internal/evidence` declares the interface it needs and `internal/archive`
happens to satisfy it. The evidence core does not import the S3 client.

Otherwise the package that must keep working when everything else is broken
would depend on an HTTP client, a signing implementation and a retry policy.
Verification would inherit that dependency too, and `flugschreiber verify` is
the one command that has to work on an auditor's laptop years from now.

## D24. Verification runs at startup and never blocks it

`serve` verifies the existing evidence directory before it begins recording, logs
the result, and starts either way.

An operator otherwise discovers a damaged log at the worst possible moment. The
check costs one pass over files that are about to be appended to anyway.

It does not block startup, and that is deliberate: a proxy that refuses to record
because yesterday's records are damaged turns one problem into two. It logs every
problem at error level with its severity and carries on.

## D25. Metrics collect always, and are exposed at scrape time

Samples are recorded whether or not `/metrics` is served, and gauges that
describe the evidence directory are refreshed by a collector that runs
immediately before each scrape.

A background ticker reports whatever the last tick saw, which for a gauge read
by a scraper is the wrong answer by up to one tick interval. Running the
collector at scrape time is the Prometheus-native shape.

No label may carry a caller-controlled value. Model names come from a bounded
set that stops growing after 64 distinct values; prompts, session identifiers
and client hashes never appear at all. That is enforced by the typed API rather
than by a comment, and there is a test that posts a secret and greps the whole
scrape for it.

## D26. An interrupted prune and a replaced log are told apart by a deferred check

When a log still contains records that `pruned.json` says were deleted, there
are two explanations: a prune interrupted between two unlinks, or the log being
replaced wholesale with the anchor left behind. The first is an operational
hiccup; the second is the shape of an end-to-end rewrite.

They are identical at the first surviving record. They differ at exactly one
later point: the record whose sequence the anchor attests to must hash to the
value the anchor recorded. So the benign diagnosis is entered provisionally and
upgraded to a high-severity `anchor_mismatch` if that record disagrees, or if it
never arrives because the log is shorter than the anchor claims.

The first version of this check only recognised the case where nothing had been
unlinked yet, so a crash between the second and third unlink produced an
unreadable cascade of broken links, and a wholesale replacement was reported as
a medium-severity "re-run retention". Both are now covered by tests that
reproduce the exact on-disk shapes.

## D27. The archive key prefix is applied in exactly one place

Both `evidence.Options.ArchivePrefix` and `archive.Config.Prefix` can prepend a
prefix. The CLI sets only the first.

If both were set they would concatenate into a path nobody chose, and the
failure is silent: the evidence lands somewhere, just not where the operator
expects, and they find out when they go looking for it. One owner means the
question never arises.

## D28. A wedged archive backend cannot hold shutdown open

`Close` waits up to `ArchiveShutdownTimeout` for uploads to drain, then cancels
them, then waits a two-second grace period, then gives up.

The first timeout assumes the backend honours context cancellation. `Archiver`
is an interface, so that assumption belongs to whoever implements it, and a
blocking client library would otherwise hand a third-party backend a veto over
process shutdown. The evidence directory holds the complete log either way, so
abandoning an upload costs a copy and nothing else.

## D29. `/metrics` is refused rather than proxied when metrics are off

With metrics disabled the route is still claimed and returns 404.

Without that, the path falls through to the catch-all proxy handler and is
forwarded upstream, so a Prometheus scrape of Flugschreiber would return the
model server's own metrics under Flugschreiber's name. Serving someone else's
numbers under your own is worse than serving none.

## D30. The image needs a writable /tmp only for report and export

`serve` writes nothing outside the evidence volume, so it runs on a read-only
root filesystem unchanged. `report` and `export` write files where they are
told, and on a read-only root that has to be a mounted path.

The documented run command therefore carries `--tmpfs /tmp`, and CI runs the
commands inside a read-only container so that this cannot regress into a README
that only works on a writable filesystem.

## D31. The module path is github.com/RamazanKara/flugschreiber

D14 left the path provisional. It is now settled, from evidence rather than
preference: every sibling project of this repository lives under the
maintainer's GitHub account, the account is what the local tooling is
authenticated as, and no flugschreiber organisation exists. A module path must
name a repository that exists on the day the first tag is pushed.

Moving the repository into an organisation later stays cheap: GitHub redirects
the old location, so clones, remotes and `go get` keep working. The module path
itself is identity and should then stay as it is, which is the usual outcome
for projects that started under a personal account.

The container image namespace is the lowercase `ghcr.io/ramazankara/`, because
GHCR requires lowercase; the module path keeps the account's casing because Go
treats it as an opaque identifier and the sibling repositories already use it.

## D32. PDF output ships, behind an explicit flag

`flugschreiber report --pdf` renders each document with the built-in base
fonts. It is off by default.

The brief made PDF optional and the case for it is narrow but real: the person
a compliance document is finally handed to often accepts nothing else, and an
operator told to "just convert it" at that moment reaches for whatever is
closest. The case against shipping it as a default is also real: a PDF is the
rendering most likely to be treated as the original, and the Markdown is the
original. A flag keeps the decision with the operator.

Characters outside the base fonts are printed as visible [U+XXXX] markers and
reported as warnings, never silently dropped, because a compliance document
that quietly loses a character is worse than one that shows a seam. The PDF
inherits the report timestamp, so --now produces byte-identical PDFs the way
it does for Markdown and HTML.

## D33. Routing peeks a bounded prefix of the request body

Multi-upstream routing selects a model server by the requested model name, which
lives in the request body. The proxy otherwise tees bodies without buffering
(D5). Routing needs the model before it dials, so it reads a bounded prefix
(1 MiB, a named constant), extracts the model with a tolerant scan, and then
replays the peeked bytes followed by the untouched remainder.

This is a deliberate, bounded exception to D5, not a reversal of it. The peek is
capped, so a large or streamed body is never held in memory beyond the cap;
streaming after the peek is unaffected; and the teed digest still covers the
complete wire bytes because the reconstructed reader yields exactly what came
in. When the model is not found within the cap, the record is marked truncated
rather than routed on an empty model. The cost is one prefix read on a recorded
request, which sits far under the proxy's existing latency budget.

Single-upstream deployments do not peek at all: with no routes to choose
between, there is nothing to read the model for.

## D34. Tool results are recorded on the inference event, digested in every mode

The results a tool returns come back as role:"tool" messages (chat) or
function_call_output items (Responses). They are recorded as a tool_results
array on the inference event, not as separate chain events, because chat clients
resend the whole conversation each turn and a per-message event would duplicate
one result into the chain once per subsequent turn.

Each result carries a SHA-256 and byte count over its content in every content
mode, exactly as tool-call arguments do, and the content text only in store
mode, redacted in redact mode, absent in hash mode. Tool output is as sensitive
as a prompt, so the hash-mode no-text guarantee extends to it, with a test that
fails if a result's text reaches disk in hash mode.

The digest is over the flattened content string the parser surfaces, which for
an ordinary string-valued result is the wire content and for an array-valued
result is the concatenated text parts. That basis is documented so a holder of
the original can reproduce it.

## D35. The Responses API is a recorded endpoint

/v1/responses is captured like chat and completions: request input (string or
item list), instructions, sampling parameters, tools, and previous_response_id
(recorded as upstream_previous_id, the API's own turn linkage); response output
text, function calls, usage and status. Streaming prefers the terminal
response.completed event, which embeds the full final response, and falls back
to accumulating output_text and function-call-argument deltas.

An unrecorded endpoint on an increasingly default API shape is a silent coverage
hole, which is the exact failure the tool exists to prevent. The audio and image
endpoints remain out of scope: they are not the interaction an AI Act evidence
log is usually about, and their bodies are binary.

## D36. Both language editions are produced by default

report generates the Annex IV skeleton and the Article 50 pack in English and
German. --lang en or --lang de narrows the output; the default, both, emits
every edition. The German technical documentation is a full native translation
using the official Anhang IV terminology, not a string swap, and every character
in it is representable in the PDF base fonts, so the PDF renders with no
substitutions.

Default-both keeps the historical behaviour a superset: nothing that was
produced before stops being produced. The audience for the transparency pack and
the technical documentation is often a German-speaking DPO, so German is a first
class edition rather than an afterthought.

## D37. The record schema is published as JSON Schema, kept honest by a test

docs/schema/record.schema.json and event.schema.json describe the on-disk format
for a third party writing their own verifier. A reflection test compares the
struct json tags against the schema field names and fails on drift in either
direction, so the published schema cannot fall behind the code. The test checks
the field set, which catches the add-and-forget mistake; it does not assert
every field's exact type or nesting, which the prose in docs/SCHEMA.md covers.

## D38. Outward-facing custody lives in internal/custody, never in evidence

Two features need the outside world: signing through an external helper, so the
key can sit on a smartcard rather than beside the evidence, and anchoring
checkpoints to an RFC 3161 authority, so their time is a third party's claim
rather than this host's. Both were built inside internal/evidence first, which
put os/exec and net/http into the closure of the one package that has to stay
readable on its own.

They now live in internal/custody. Evidence declares Signer and Timestamper;
custody implements them. The split runs along a specific line: custody carries
bytes and nothing else, so it posts a prepared request and returns whatever came
back, while every decision about whether an answer is acceptable, including all
the ASN.1 and the check that a token covers the right digest, stays with the
verifier. A regulator reading internal/evidence years from now reads no TLS
stack and no subprocess machinery, and test/architecture_test.go checks the
transitive closure rather than just the internal edges, because that is the
invariant and the internal edges were only ever a proxy for it.

## D39. The size cap reports; it never deletes evidence early

RetentionPolicy.MaxBytes caps the evidence directory. Enforcement already
deletes every segment that is beyond the retention floor, oldest first, so by
the time the cap is consulted there is nothing further it is permitted to take:
what remains is either inside the floor or held by a legal hold. Being over the
cap at that point is reported, in the retention output, in the report and as
flugschreiber_evidence_bytes_over_cap, and nothing is deleted.

The alternative would be a tool that quietly deletes evidence below the Article
19 six-month floor because a disk filled up at three in the morning. Disk
pressure against a legal floor is an operator's decision. The cap's job is to
make sure they find out in time to make it.

## D40. Erasure destroys keys, never records

`store` and `redact` modes retain text, and text attracts deletion requests. The
obvious implementation, going back and blanking the fields, is the one thing
this design cannot do: the chain hashes each record as it was written, so
rewriting one breaks verification from that point onwards, and a log that stops
verifying because somebody exercised a data subject right is worse than useless.

So content encryption seals the text-bearing fields under a per-session key,
wrapped by a master key in a keystore beside the evidence but outside the chain,
and `erase` destroys the wrapped key. The record is untouched, the chain still
verifies from the beginning, and the content is unreadable to everyone including
us. Erasure is documented by appending a new record rather than by editing an
old one; the erased state a reader sees is derived at read time from the
keystore, which is why a bundle without the keystore reports its content as
sealed rather than as erased. Those are different facts.

The digest is the part worth being exact about. It is computed over the
plaintext wire bytes in every mode, so an encrypted record proves exactly what
an unencrypted one proves. After an erasure it survives as a true statement
about bytes nobody can produce any more: a claim that can no longer be
re-proven. `evidence.ErasedDigestCaveat` is that sentence, and every renderer
prints it, because "content not retained" would imply it was never stored and
silence would let a reader take the digest for something still testable.

Encryption is opt-in. It adds a key an operator has to look after, and losing
that key destroys content exactly as thoroughly as an erasure does. That trade
belongs to whoever runs it.


## D41. Shutdown drains the timestamper before the archive

Anchors are appended by the timestamping goroutine, not by the writer, so the
anchor over a run's last checkpoint lands in timestamps.jsonl after the shutdown
flush has already snapshotted that file for the archive. With the archive
drained first, that anchor stayed on the host until the next start.

The next start ships it, and the archive object is keyed by the file's length
rather than by the chain head so that a longer file always asks for a key the
archive does not hold yet. That covers every restart. It does not cover the last
shutdown an installation ever performs, and a decommissioned host is exactly the
case where the offsite copy is all that is left.

So Close drains the timestamper, offers the anchors to the archive once more,
and only then drains the archive. Both drains are bounded, so the worst case is
a slower shutdown rather than one that does not finish. The test that pins this
makes the authority answer slowly on purpose: an instant answer lands before the
snapshot and would pass against the bug.

## D42. The archive carries everything a verification needs, keyed so nothing is overwritten

An archive that holds the segments and the checkpoints but not the keys those
checkpoints were signed with is an archive nobody can verify. After a rotation
that is exactly what it was, and the failure only shows up in somebody else's
hands, weeks later, with nothing to explain it. So the layout is:

```
segments/seg-XXXXXXXX.jsonl                     sealed segments, final
open/seg-XXXXXXXX.seq-NNNNNNNNNNNN.jsonl        the segment still being written
checkpoints/checkpoints.seq-NNNNNNNNNNNN.jsonl  snapshot at that chain head
timestamps/timestamps.bytes-NNNNNNNNNNNN.jsonl  snapshot at that file length
public-key.pem, keys/retired-<key id>.pem       every key a checkpoint names
```

Only sealed segments have final names. Everything that grows goes up as a
snapshot under a key that says what the snapshot covers, so an object store with
a lock never has to overwrite anything, and a run that added nothing offers a key
the bucket already holds and is skipped after one HEAD.

The anchors are keyed by the file's length rather than by the chain head, and
that difference is load-bearing. Anchors are appended by the timestamping
goroutine, so one can land after a head-keyed snapshot has gone up; the next run
would offer the same key, the bucket would answer "already there", and those
anchors would stay on the host for good. Length changes whenever an anchor is
added, so a file that has gained one always asks for a key nothing holds yet.
See D41 for the shutdown ordering that covers the case with no next run.

`pruned.json` and `LEGAL_HOLD` stay on the host. They describe this
installation's deletions and holds, not the evidence.

## D43. Checkpoints are chained, and the linkage sits outside the v1 signature

A signature makes a checkpoint unforgeable and leaves it deletable. An attacker
who cannot produce a signature can still remove the attestations: every one left
behind verifies, nothing reveals the ones that went, and verify reported the log
intact and attested. Deleting checkpoints.jsonl outright was a clean exit 0.

Checkpoints now carry an index, the hash of their predecessor, and a signature
over both. The linkage is deliberately not folded into the existing preimage.
Doing that would have been cleaner to read and would have made every checkpoint
this version writes fail signature verification in every verifier already
deployed, which reports as forgery. Manufacturing a false accusation of
tampering is the one failure this tool must never produce, so the v1 signature
covers exactly the bytes it always did and the linkage is a second signature
over a second domain. A v0.4.0 verifier validates these checkpoints unchanged
and ignores fields it does not know.

Deleting the whole file stays undecidable from the files alone. A public key can
sit beside a log written with signing off, so an empty checkpoint file cannot be
told from a log that was never attested, and guessing would accuse honest
operators. `--require-attestation` is how somebody who knows their log is signed
turns that into a failure, and `--expect-head` compares against a value recorded
where the proxy cannot reach it.

## D44. Verify distinguishes a broken chain from one it could not check

`OK()` meant zero problems of any severity, so a medium "this checkpoint names a
key I do not have" printed `HASH CHAIN VERIFICATION FAILED` and exited 1 over a
chain the next line of the same output called intact and attested. A bundle
forwarded without a retired key, a PVC that failed to mount, and a genuine
rewrite were one number.

There are now three: 0 for a clean check, 1 for a chain that is damaged, and 2
for a check that could not be completed. A scheduled job can tell an outage from
an attack, which it could not before, and the headline for exit 2 says the chain
is intact as far as it could be read. `Intact()` is the narrower predicate;
`OK()` still means everything passed.

## D45. Open refuses a second writer, and repair finishes an interrupted write

Two servers on one directory both started, because Open wrote the lock file
rather than consulting it. The single-writer rule was enforced by the Helm chart
and nowhere else, so Docker, systemd and bare metal had none. Two servers
against one directory produce nineteen high-severity problems, sequence numbers
repeating, links broken throughout, permanently and shaped exactly like
tampering.

The refusal is conditional, because the original reasoning was right as far as
it went: a proxy that will not start because of a stale lock has turned a crash
into an outage. So a lock whose process is gone is taken, a lock held by a live
process on this host is refused, and a lock from another host is refused because
liveness cannot be checked across a shared volume. `--force-writer-lock` is for
the operator who knows the other host is stopped and cannot prove it to us.

The mirror image is a torn final record, which is what a power loss leaves
inside the fsync window. It stopped the writer permanently, with no repair
command, so a proxy that lost one record went on to record nothing at all.
`flugschreiber repair` removes the fragment and appends a system_event saying
what it removed. It refuses when a checkpoint attests past the damage: the
premise of the command is that the fragment was never a complete record, and a
signature over it says otherwise, so truncating would destroy signed evidence.

## D46. The content keystore is outside the format promise, and appends

Minting a content key rewrote the whole keystore, and a key is minted per
request whenever the caller sends no session header, so writing one cost 3 ms at
five hundred keys and 14 ms at seven and a half thousand, on the request path,
under the lock. Total cost quadratic, and a large store needed more memory to
open than the chart grants the container.

Keys are now appended to a journal and folded in every few hundred, which is
flat at 1.2 ms whatever the store holds. The fsync per key stays: a key that is
not on disk when the machine dies cannot decrypt the record already written
under it.

The keystore and its journal are stated in docs/SCHEMA.md as internal to this
implementation, outside the compatibility promise. They hold wrapped key
material, they are never exported or archived, and no third party reads them, so
their layout may change with a one-way migration. Everything a third party does
read is covered by the promise.

## D47. The endpoints that are not recorded, and why

Two endpoints come up often enough to state the position rather than leave it to
be inferred.

**Image generation (`/v1/images/generations`).** Not recorded. There is a real
argument for it: its output is synthetic content, which is exactly what Article
50(2) asks providers to mark, so an evidence log of it would have a clear
purpose. What holds it back is the shape of the data. The output is an image,
returned inline as base64 or as a URL to fetch, and the digest-over-wire-bytes
model that makes the text endpoints cheap turns into either buffering megabytes
per request or recording a digest of a URL whose contents can change. Neither is
the clean guarantee the rest of the log provides, so the endpoint stays out until
the recording model for it is designed rather than bolted on. The request is
recorded when it passes through as an ordinary POST is not; it is proxied and not
classified, and `coverage` and MAPPING.md say so.

**Anthropic's Messages API (`/v1/messages`).** Not recorded, because the
positioning is OpenAI-compatible and the request and response shapes differ
enough that treating them as chat completions would mis-record them. It is the
single most likely "why is this not supported" question, and the honest answer is
that it is a deliberate scope line, not an oversight: adding it is a parser and a
mapping, waiting on demand from somebody who runs it. Until then, traffic to it
is proxied and not classified, the same as any other unrecognised POST.

Both are named in MAPPING.md's list of what the proxy forwards but does not
record, so an operator sees the boundary rather than discovering it.
