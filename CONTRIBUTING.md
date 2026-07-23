# Contributing

Thanks for looking. This project is most useful when people who have been
through a real audit tell us what a regulator actually asked for, so issues
describing that are as valuable as code.

## Getting set up

Go 1.25 or later. There is nothing to download, because there are no
dependencies.

```bash
git clone https://github.com/RamazanKara/flugschreiber
cd flugschreiber
make check          # format, vet, test
make acceptance     # the quickstart, as a test
```

`make help` lists the rest.

## Before you open a pull request

```bash
make check
make lint           # needs golangci-lint
```

CI runs the same things plus the acceptance demo on Linux, macOS and Windows,
a container build that exercises the documented `docker run` command, and a grep
that fails the build if any copy claims to confer compliance.

## What we are strict about

**Nothing that produces evidence gets a silent failure path.** If a record
cannot be written, that surfaces. Dropping evidence under load, swallowing a
write error, or logging a warning nobody reads are all worse than stopping.

**Never claim compliance.** Not in the README, not in a doc template, not in a
log message. Flugschreiber produces evidence and documentation inputs. CI greps
for this, but the grep only catches phrasings we thought of.

**The five-minute demo stays working.** `test/acceptance_test.go` is the
definition of done. A change that breaks it needs a very good reason.

**No new dependency without an entry in DECISIONS.md.** See D1 for why. CI fails
if `go.mod` grows a `require` block. Adding one is allowed; adding one silently
is not.

**Generated documents mark their gaps.** If the generator cannot fill a section
from evidence, it emits a `TODO` with a sentence on what belongs there. Never
fill a gap with plausible text. A generated risk assessment is worse than no
risk assessment, because it looks like one.

## Tests

New behaviour needs a test. The suite is organised around properties rather than
functions:

- `internal/evidence` proves the chain detects tampering. If you touch hashing or
  the store, the byte-flip, forgery, deletion and truncation tests are the ones
  that matter.
- `internal/proxy` proves capture is correct and that content modes keep their
  promises. `TestHashModeStoresNoText` and `TestStreamingIsNotBuffered` encode
  claims the README makes.
- `internal/report` uses golden files. If your change alters generated output,
  run `make golden` and **read the diff** before committing it. A golden test you
  update without reading is a test that has stopped working.
- `test/` builds the binary and runs the quickstart over real HTTP.

Everything runs against the built-in mock upstream. No test needs a GPU, a model
server, or a network.

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
