# Roadmap

Everything the original version of this file planned has shipped, and v0.5.0
hardened the failure paths on the way to 1.0. What follows is what that was,
what is deliberately not being built, and what would come next if the gaps below
turn out to matter to somebody.

The standing rules constrain anything added here: zero Go dependencies, schema
changes are additive or they are a version bump, the architecture test gates new
imports, every behaviour gets a test that fails without it, and no copy anywhere
claims the tool confers compliance. Each shipped item adds its entry to
`DECISIONS.md` and `CHANGELOG.md`.

## Shipped

**v0.2.0, "Coverage": record everything that talks to the model.** The Responses
API (`/v1/responses`) is recorded like chat and completions, streamed and not,
including `previous_response_id`. One instance routes to several model servers
by model glob and endpoint kind, each route with its own TLS and API key. Tool
results are recorded on the inference event, digested in every content mode. The
chart's scheduled verify and retention work in sidecar mode. A Grafana dashboard
and Prometheus alert rules ship under `deploy/observability`. The record format
is published as JSON Schema, kept in step with the code by a test.

**v0.3.0, "Custody": harden what is recorded.** `keys rotate` rotates the
signing key and keeps every retired public half, so old checkpoints stay
verifiable and exports and archives carry them. `--signer exec:<command>` moves
signing to an external helper, so the private key can live on a smartcard or an
HSM. `--tsa-url` anchors checkpoints to an RFC 3161 authority. `archive-verify`
checks the offsite copy and states what an archive cannot support.
`--retention-max-bytes` caps the directory, reporting rather than deleting. The
ASN.1, SigV4 and SSE parsers have fuzz targets.

**v0.4.0, "Erasure and reach": the deep cuts.** `--content-encryption` seals
stored content under keys held outside the chain, and `erase` destroys them, so
a GDPR Article 17 request costs the content and never the evidence. `incident`
events with a closed severity set record what a person concluded went wrong, and
the report's post-market section pre-fills from them. The Annex IV skeleton and
the Article 50 pack ship in German as well as English, selected with
`report --lang`.

**v0.5.0, hardening towards 1.0.** Checkpoints chained so deleting an
attestation is detectable, the single-writer rule enforced by the binary rather
than only by the chart, `repair` for a write a power loss interrupted, the
content keystore made flat instead of quadratic, the hash construction pinned to
bytes with a frozen conformance fixture, and the stability contract written down
in `docs/STABILITY.md`.

## Explicitly not planned

Multi-writer or HA chains: a single total order is the design, and the chart
refuses `replicas > 1` for the same reason.

Rate limiting: it belongs in front of the proxy, alongside whatever already
protects the model server.

Anthropic `/v1/messages`: the positioning is OpenAI-compatible. Worth revisiting
only with demand from somebody who actually runs it.

Automatic retention inside `serve`: deletion stays behind an explicitly
scheduled job with two explicit flags. A proxy that deletes evidence as a side
effect of running is a proxy nobody should trust.

Risk management, human-oversight design and model evaluation: this is the work
the AI Act asks people to do. A tool that generated it would produce something
that looked like the work and was not, which is worse than a section marked
TODO.

## Towards 1.0

The engineering for 1.0 is in place: the failure paths hold, the guarantees are
pinned by tests, and `docs/STABILITY.md` states the contract a 1.0 will freeze.
What remains between here and 1.0 is soak time in real deployments, so the
contract binds from experience rather than from optimism.

The items below are known gaps somebody will eventually hit.

## What would come next

Nothing here is committed. Each would need somebody with the problem.

**Content encryption for tool arguments and results.** Schema version 1 gives
them no ciphertext field, so encryption drops their text rather than sealing it.
That is the right call within the version and it costs a reader the arguments a
model was called with. Doing it properly means schema version 2.

**A verifier that validates timestamp tokens end to end.** Flugschreiber checks
that a token covers the checkpoint it is filed against and delegates CMS
signature and certificate-chain validation to `openssl ts -verify`, because
which authorities count is a policy decision. A built-in check with a
configurable trust store would be convenient, and would need care not to imply
more assurance than the trust store deserves.

**Erasure authorisation.** `erase` does not authenticate the request behind it:
whoever can run the binary against the directory can erase content. That is the
same boundary as write access to the directory, which may be too coarse for some
deployments.

**Coverage attestation.** `coverage` reports on traffic that reached the proxy
and structurally cannot report on traffic that did not. Something that
reconciles the log against the model server's own request count would close the
gap most likely to produce a false sense of completeness.
