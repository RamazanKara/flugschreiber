# Deployment checks and audit automation

## Validate before starting

Use the same arguments and environment as the intended `serve` invocation:

```bash
flugschreiber serve --config config.json --check-config
flugschreiber serve --mock-upstream --content-mode redact --check-config
```

Success prints `configuration valid` and exits 0. Invalid configuration exits 1.
The check merges defaults, the JSON file, supported environment variables and
flags exactly as startup does. It checks configuration constraints, route
settings, signing options and redaction patterns. It does not print the
effective configuration or credentials.

It does not open listeners, contact upstreams, execute signing helpers, create
keys or touch evidence. It does not check external certificates, key files,
archive access, port availability or evidence integrity; these still need the
normal startup and verification checks.

For a file containing:

```json
{
  "mock_upstream": true,
  "retention_dayz": 180
}
```

The diagnostic includes `config.json:3:3: json: unknown field "retention_dayz"`.
Syntax, type, duration and nested unknown-field errors have one-based line and
byte-column positions. These locations also appear when other commands load a
config file. Cross-field validation errors refer to the effective settings,
which may have come from environment variables or flags.

## Export verification findings

```bash
flugschreiber verify --dir ./evidence --format sarif > verify.sarif
flugschreiber verify --dir ./evidence --format json > verify.json
```

SARIF output follows [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
Each problem becomes a result with its existing problem kind as `ruleId`, a
message and, where available, a file and line location. File URIs are escaped
and relative to the `EVIDENCE` base URI, which names the evidence directory.
Findings without a known line omit the region. The run's properties retain the
record count, head hash, attestation state, pruned state and verification notes.

Integrity findings have level `error`. Incomplete checks, such as an absent
public key, have level `warning` and set `executionSuccessful` to false. A
completed scan that detects damage sets it to true: the scan completed and its
findings failed. The invocation's `exitCode` matches the command's status:

| Exit | Meaning |
| --- | --- |
| 0 | All checks completed and passed |
| 1 | At least one integrity finding |
| 2 | Checks were incomplete, with no integrity findings |

A mixed result retains both kinds of findings and exits 1. Before a scan can
produce a report, setup errors such as a missing directory still go to stderr
and exit 1, with no SARIF document. Keep the command's exit status when
redirecting output or using pipelines.

Text remains the default. `--format json` is an alias of `--json`; their JSON
shape is unchanged. `--quiet` suppresses all report formats. Conflicting
`--json` and `--format` selections are rejected.

## Shell completion

Bash, including Git Bash on Windows:

```bash
flugschreiber completion bash > ~/.flugschreiber-completion.bash
source ~/.flugschreiber-completion.bash
```

Add the `source` line to `~/.bashrc` to load it in new shells.

PowerShell:

```powershell
flugschreiber completion powershell | Set-Content "$HOME/.flugschreiber-completion.ps1"
. "$HOME/.flugschreiber-completion.ps1"
```

Add the dot-source line to `$PROFILE` to load it in new shells.

Complete commands, `keys` subcommands, the completion shell name and flags such
as `flugschreiber verify --fo<Tab>`. Flags are read from command help, so they
stay in step with the installed binary. Completion only invokes help for known
commands; it never passes the typed configuration or other flag values to them.
