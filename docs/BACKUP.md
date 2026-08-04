# Backup and restore

An evidence directory is only as durable as its worst copy. This is what to back
up, how to restore it, and the one result that looks alarming and is not.

## What to back up

Back up the whole evidence directory. It is append-only, so an incremental backup
copies only the segment being written and whatever rotated since the last run.

| Path | Back up? | Why |
| --- | --- | --- |
| `seg-*.jsonl` | Yes | The records. The evidence itself. |
| `checkpoints.jsonl` | Yes | The signatures. Without them the log verifies as unsigned. |
| `timestamps.jsonl` | Yes, if present | The RFC 3161 anchors. |
| `public-key.pem`, `keys/` | Yes | The keys checkpoints verify against, current and retired. |
| `pruned.json` | Yes, if present | Where a pruned chain begins. Without it a pruned log will not verify. |
| `LEGAL_HOLD` | Yes, if present | A hold in force must survive a restore. |
| `signing-key.pem` | Separately, and guard it | Whoever holds it can forge. Keep it off the host where you can; an external signer removes it from the directory entirely. |
| `client-salt` | Separately | Losing it changes every caller's pseudonym. It is deliberately excluded from exports. |
| `content-keys.json`, `content-keys.jsonl` | Separately, if content encryption is on | These open every sealed prompt. Losing them destroys stored content as thoroughly as an erasure. Back them up with the same care as the signing key, and remember a backup of them is a backup of every prompt they can open. |

The three files in the second group are what an export deliberately withholds, so
an evidence bundle is never a backup of them. Treat their backup as a separate,
tighter procedure than the segments.

## Restoring

Stop any running proxy, copy the directory back, and start again. The proxy
verifies the chain at startup and continues appending from the head it finds, so
a restored directory needs no import step.

Two things to check after a restore:

- **Verify before trusting.** Run `flugschreiber verify --dir <path>`. A clean
  result means the copy is intact. If you recorded the head hash somewhere out of
  the proxy's reach, confirm it with `--expect-head <hash>`; if you know the log
  was signed, add `--require-attestation`.
- **Do not run two copies.** The binary refuses a second writer on a directory a
  live one holds, but a restored copy on a different host cannot be checked across
  a shared volume. Point exactly one proxy at the restored directory. If a stale
  `writer.lock` from the crashed original blocks startup and you are certain the
  original is stopped, `--force-writer-lock` takes it over.

## The result that looks wrong and is not

Restore a **partial** copy of a directory, a subset of the segments, next to a
**complete** `checkpoints.jsonl`, and `verify` reports a high-severity
`checkpoint_mismatch`. This is correct. From the files alone, a checkpoint that
attests to a record the segments no longer contain is indistinguishable from
records having been deleted, which is exactly what verification exists to catch.

The fix is to restore the whole directory as one unit, not the segments and the
checkpoints from different backup generations. If you only have the segments,
restore them without the newer `checkpoints.jsonl`; the log then verifies as far
as it goes and reports as unsigned past that point, which is the honest state.

## Disaster recovery for the write path

A crash or a full disk can leave a partial final record, which stops the proxy
from establishing the chain head. `flugschreiber repair` removes the fragment and
records the repair in the chain; the [Kubernetes guide](tamper-evident-llm-audit-logs-on-kubernetes.md)
covers running it in a pod. A repair never touches anything a checkpoint attests
to, so it cannot remove signed evidence.

Off-host archival (`archive.backend`) is a second copy on the write path rather
than a scheduled backup: sealed segments, checkpoints, anchors and every public
key are shipped as they rotate. It complements a backup and does not replace one,
because it never carries `pruned.json`, `LEGAL_HOLD`, the salt or the keystore, so
a directory rebuilt from the archive alone verifies but is not complete.
`flugschreiber archive-verify` reports which parts an archive can and cannot
account for.
