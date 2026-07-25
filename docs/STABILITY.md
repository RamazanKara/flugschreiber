# What the command line promises

The log format has its own policy in [SCHEMA.md](SCHEMA.md). This document is
about the other surface people build on: the commands, their flags, the exit
codes and the `--json` shapes.

It exists because the project tells operators to automate against exactly those
things. The Kubernetes guide says to ship `head_hash` out of `verify --json` and
calls it the only real answer to an attacker who holds the volume. The chart's
CronJob alerts on `verify`'s exit status. A promise of stability that never says
which surfaces it covers either freezes everything by accident or breaks
somebody's monitoring in a minor release and calls it a bugfix.

## What is promised at 0.x, and what is not

This is a 0.x release, and under semantic versioning that means a minor version
may still break any of it. Read what follows as the contract 1.0 will freeze,
written down now so that it is settled by argument rather than by accident, and
so that the shape of it can be criticised before it is binding.

Concretely: everything below is what the project intends to keep, and a break
before 1.0 will be a considered decision recorded in `CHANGELOG.md` rather than
a surprise. After 1.0 it is a promise and a break needs a major version. If you
are automating against this today, pin a version and read the changelog on
upgrade; that is good advice for any 0.x and it is honest advice for this one.

The log format is the exception and is stricter already. `docs/SCHEMA.md`
governs it, evidence written today has to stay verifiable for years whatever the
tool does next, and `testdata/conformance` holds a frozen log that fails the
build if this stops being true.

Within a major version, once there is one:

- A command is not removed or renamed.
- A flag is not removed, renamed, or given a different meaning.
- A default does not change in a way that records less, keeps evidence for less
  time, or weakens an integrity guarantee.
- A `--json` object gains keys and never removes one or repurposes it. Parse it
  as an open object and ignore what you do not recognise.
- A config key is not removed or repurposed. Unknown keys are still rejected at
  startup, deliberately: a typo that silently disables checkpointing is worse
  than a refusal to start, and the error names the key.
- An exit code keeps its meaning, and the meanings are below.

New commands, new flags, new keys and new fields are additive and may arrive in
any release.

## Exit codes

`verify` and `archive-verify` distinguish three outcomes, because a scheduled
job has to tell an attack from an outage and they used to be the same number.

| Code | Meaning | What an operator should do |
| --- | --- | --- |
| 0 | Every check completed and passed | Nothing |
| 1 | A check completed and failed: the chain is damaged, or something signed contradicts it | Preserve the directory before touching it, then read the problems |
| 2 | Verification could not be completed: the directory is unreadable, or a key or token a check needs is absent | Treat as an outage or a missing file, not as tampering |

The distinction matters because a bundle forwarded without a retired public key,
a PVC that failed to mount, and a genuine rewrite all used to print
`HASH CHAIN VERIFICATION FAILED` and exit 1. Exit 2 says the tool could not
finish, and prints a headline that says the chain is intact as far as it could
be read.

Every other command exits 0 on success and 1 on failure. `--quiet` on `verify`
prints nothing and reports through the status alone.

## Flags, the environment and the config file

Flags beat environment variables, which beat the config file.

For strings and numbers that is exact. For booleans it is one-way: a flag can
turn something on, and cannot turn it off again if a lower layer turned it on.
`--no-sign=false` against a config file holding `"signing_disabled": true`
leaves signing off. This is a known limitation rather than a design: making them
tri-state would change observable behaviour on a frozen flag, so it is written
down here instead and will be revisited only in a major version. Where it
matters, set the value in one place.

Every setting has an environment variable, except the `upstreams` routing list,
which is a structured list of objects and would need a syntax nobody could read
back. It is config-file only.

## The Go packages

Everything is under `internal/`, so nothing here is an importable API and none
of it is covered by this document. The binary is the interface. That is
deliberate: an evidence tool that other programs link into gains a second way to
write a log, and the guarantee that one writer owns one directory is easier to
keep when there is one way in.

## The generated documents

The Annex IV skeleton and the Article 50 pack are drafting starting points. Their
wording changes between releases as the templates improve, and a `report` run is
not reproducible across versions. Where you need a fixed artefact, keep the
output rather than the command that produced it.
