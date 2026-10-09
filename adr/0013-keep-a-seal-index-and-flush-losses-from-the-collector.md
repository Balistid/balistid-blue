# 0013 — Keep a seal index beside the shards and flush losses from the collector

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-09
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`internal/shard` seals a shard and returns its SHA-256; a shard counts as sealed only once that hash is
recorded (ADR 0005, point 3). The store above it (cap, reserve, loss records; branch `feat/store`) failed
two critic rounds on the same gap: on restart it could tell a sealed shard from a crashed one only by the
SQLite header, which a crash after the journal switch also leaves, and it wrote a loss record only when
another record or Close arrived, so drops counted in memory could outlive `crash_loss_ms` (1000 ms).
The ledger runs as its own uid (ADR 0007) and logs hashes and ranges (ADR 0006); the collector may read
its status but not its files. ADR 0005 point 6 leaves the recovery protocol to code with crash tests.

## Decision

1. The collector is the store's only caller and runs it on one goroutine. A ticker on the monotonic
   clock calls `Store.Flush` every 250 ms; Flush writes the pending loss and health records, so a crash
   loses at most the drops of one interval, inside `crash_loss_ms`.
2. The store keeps `seals`, an append-only index in its directory: a `schema_version` header, then one
   line per sealed shard with its name, first seq, last seq and SHA-256. A seal counts only once its line
   is written and fsynced; then the collector hands the same line to the ledger as a log entry.
3. Open trusts a `.db` only through its index line and hash. Any other `.db` is recovered: every row's
   leaf and the seq order are checked, the shard is sealed, indexed and a recovery health record stored.
   A shard that fails the check stays where it is, the store is UNKNOWN and the maintainer decides.
4. The next seq on Open is one past the highest seq in the index and the recovered shards; no separate
   counter exists that could disagree with the data.
5. An index that is malformed, out of order or of another major version makes Open fail; a missing
   index with shards present is recovery of every shard, never trust.

## Alternatives considered

- Ask the ledger at Open: makes recording wait for another process and couples their failures.
- Trust the SQLite header: a crash between the journal switch and the hash leaves a sealed-looking file.
- Flush from Append only: an idle collector would hold drop counts without bound.

## Consequences

- `internal/store` gains `Flush`, the index and recovery; the collector gains the ticker; the ledger
  gains a `shard-seal` entry type with test vectors (ADR 0006, point 1).
- Tests: crash after the journal switch, after the seal but before the index line, and after the index
  line but before the ledger entry; each restarts with every stored record readable or the store UNKNOWN.
