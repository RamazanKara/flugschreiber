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
