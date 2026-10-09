# Contributing

Thanks for looking. This project is most useful when people who have been
through a real audit tell us what a regulator actually asked for, so issues
describing that are as valuable as code.

## Getting set up

Go 1.27.2 or later, GNU Make and a POSIX shell. The race detector also needs a C
compiler. There are no external Go module dependencies. On Windows, use WSL or
a shell and compiler toolchain such as Git Bash with MinGW-w64.

```bash
git clone https://github.com/RamazanKara/flugschreiber
cd flugschreiber
make check          # formatting, dependencies, vet, lint, staticcheck, tests, vulnerabilities, build
make fuzz           # each parser target for 30 seconds
make acceptance     # the quickstart, as a test
```

`make help` lists the rest.

## Before you open a pull request

```bash
make check
make fuzz
```

The single CI workflow mirrors these targets on Linux. `make test` includes
acceptance tests and enables the race detector only when `go env CGO_ENABLED`
is 1. GitHub Actions is currently unavailable because of billing; local results
are the gate. Install golangci-lint (which includes staticcheck) and govulncheck as described in
[docs/RELEASING.md](docs/RELEASING.md). Container and Helm checks are separate
local targets. Releases and site publication are manual.

## What we are strict about

**Nothing that produces evidence gets a silent failure path.** If a record
cannot be written, that surfaces. Dropping evidence under load, swallowing a
write error, or logging a warning nobody reads are all worse than stopping.

**Never claim compliance.** Not in the README, not in a doc template, not in a
log message. Flugschreiber produces evidence and documentation inputs. Review
documentation changes for claims the implementation cannot support.

**The five-minute demo stays working.** `test/acceptance_test.go` is the
definition of done. A change that breaks it needs a very good reason.

**No new dependency without an entry in DECISIONS.md.** See D1 for why. The
`make deps` target rejects external modules, so adding a
dependency also requires a deliberate change to that gate.

**Generated documents mark their gaps.** If the generator cannot fill a section
from evidence, it emits a `TODO` with a sentence on what belongs there. Never
fill a gap with plausible text. A generated risk assessment is worse than no
risk assessment, because it looks like one.

## Tests

New behaviour needs a test. The suite is organised around properties rather than
functions:

- `internal/evidence` proves the chain detects tampering. If you touch hashing or
  the store, the byte-flip, forgery, deletion and truncation tests are the ones
  that matter. It imports nothing internal and must not reach `net/http` or
  `os/exec`, even transitively: anything that talks to another process or host
  goes in `internal/custody`, behind an interface evidence declares.
- `internal/proxy` proves capture is correct and that content modes keep their
  promises. `TestHashModeStoresNoText` and `TestStreamingIsNotBuffered` encode
  claims the README makes.
- `internal/report` uses golden files. If your change alters generated output,
  run `make golden` and **read the diff** before committing it. A golden test you
  update without reading is a test that has stopped working.
- `internal/custody` proves that signing through an external helper and
  anchoring to a timestamping authority produce evidence indistinguishable from
  the built-in path. The helper is this test binary run again in helper mode, so
  a real process really is started and really answers over a pipe.
- `test/` builds the binary and runs the quickstart over real HTTP, and enforces
  the dependency graph. `TestFoundationsHoldNoOutwardFacingMachinery` checks the
  transitive closure of `internal/evidence`, not just its internal edges,
  because the ways to grow that closure are all convenient.

Tests use the built-in mock upstream and local HTTP servers. No test needs a
GPU, an external model server or internet access. The reference-verifier test
needs `python3` and skips when it is unavailable.

Write tests that fail when the feature is removed. Before you push, break the
implementation on purpose and watch the test go red. A test that passes against
a stubbed-out function is worse than no test, because it reports coverage of
something it never checked, and this project has shipped two of those.

## Style

Match the surrounding code. A few things worth knowing:

Comments explain why, not what. `// increment the counter` above `i++` is noise.
`// Flush per record so that a process crash cannot lose an event the proxy has
already reported as captured` is the kind of thing worth writing down, because
the next person will otherwise remove the flush.

Errors say what failed and what to do. `config: retention of 30 days is below
the 180-day floor` beats `invalid configuration`.

Parsers are tolerant, writers are strict. See D12.

## Changing the log schema

Read the compatibility policy in [docs/SCHEMA.md](docs/SCHEMA.md) first.

Adding an optional field is fine and needs no version bump, because the envelope
hashes the event as opaque bytes. Removing a field, changing what one means, or
changing the hash construction is a version bump and needs a migration story for
logs already on disk. People will still be verifying today's logs in 2032.

Update [MAPPING.md](MAPPING.md) in the same pull request. A field with no entry
there is a field nobody can justify keeping.

## Reporting bugs

Include the version (`flugschreiber version`), the command, and what happened.
For anything involving evidence, a reproduction against `--mock-upstream` is
ideal, and please do not paste real prompts or real evidence files into an
issue.

Security issues go to a [private advisory](SECURITY.md), not a public issue.

## Licence

Contributions are accepted under Apache-2.0.
