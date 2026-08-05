# What the command line promises

The log format has its own policy in [SCHEMA.md](SCHEMA.md). This document is
about the other surface people build on: the commands, their flags, the exit
codes and the `--json` shapes.

It exists because the project tells operators to automate against exactly those
things. The Kubernetes guide says to ship `head_hash` out of `verify --json` and
calls it the only real answer to an attacker who holds the volume. The chart's
CronJob alerts on `verify`'s exit status. A useful stability promise names the
surfaces it covers, so this document does.

## Where this stands

The log format is already held to the strictest standard: evidence written today
has to verify years from now, [SCHEMA.md](SCHEMA.md) governs it, and a frozen
log under `testdata/conformance` fails the build if any change stops this tool
reading what an earlier version wrote.

The contract below is what 1.0 freezes formally. It is published ahead of that
release so it can be reviewed and argued with before it binds. Until then, a
change to it is a deliberate decision recorded in `CHANGELOG.md`; pin a version
and read the changelog on upgrade, as with any 0.x tool.

The contract:

- A command is not removed or renamed.
- A flag is not removed, renamed, or given a different meaning.
- A default does not change in a way that records less, keeps evidence for less
  time, or weakens an integrity guarantee.
- A `--json` object gains keys and never removes one or repurposes it. Parse it
  as an open object and ignore what you do not recognise.
- A config key is not removed or repurposed. Unknown keys are rejected at
  startup with the offending key named, so a typo surfaces immediately instead
  of changing behaviour quietly.
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

Exit 2 is what lets a scheduled job separate operational conditions, a volume
that did not mount or a key that is not present, from integrity findings, which
are reserved for exit 1. Its headline states that the chain is intact as far as
it could be read.

Every other command exits 0 on success and 1 on failure. `--quiet` on `verify`
prints nothing and reports through the status alone.

## Flags, the environment and the config file

Flags beat environment variables, which beat the config file.

For strings and numbers that is exact. For booleans the layering is one-way: a
flag can enable a setting, and a setting a lower layer enabled stays enabled,
so set boolean values in one place. Tri-state flags are on the list for the
next major version.

Every setting has an environment variable, except the `upstreams` routing list,
which is a structured list of objects and would need a syntax nobody could read
back. It is config-file only.

The reading commands follow the same layering for the one flag they all share:
`--dir` names the evidence directory, and when the flag is absent it comes from
`FLUGSCHREIBER_DATA_DIR`, the same variable `serve` reads for `--data-dir`. Set
it once in a container or a shell profile and every command from `verify` to
`erase` acts on the same directory.

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
