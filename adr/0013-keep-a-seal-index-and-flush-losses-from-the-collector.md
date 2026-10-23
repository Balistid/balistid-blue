# 0013 — Keep a seal index beside the shards and flush losses from the collector

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-09, amended 2026-10-10 (torn-write loss in commits, crash_loss_ms), 2026-10-24 (full filesystem)
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`internal/shard` seals a shard and returns its SHA-256. The store above it (cap, reserve, loss records;
branch `feat/store`) failed two critic rounds on the same gaps: on restart it could tell a sealed shard
from a crashed one only by the SQLite header, which a crash after the journal switch also leaves, and it
wrote a loss record only when another record or Close arrived, so drops counted in memory could outlive
`crash_loss_ms` (1000 ms). The ledger runs as its own uid (ADR 0007); ADR 0005 point 6 asks for
at-least-once delivery to it with de-duplication and leaves the mechanism to this decision and its tests.

## Decision

1. The collector is the store's only caller and runs it on one goroutine. A ticker on the monotonic
   clock calls `Store.Flush` every 250 ms; Flush writes pending loss records and health records that
   changed. Pending loss records are also written before every seal, because hashing a 2 GiB shard
   takes about a second (0.93 s measured in review).
2. The store keeps `seals`, an append-only index in its directory, created through a temporary file,
   fsync, rename and a directory fsync: a `schema_version` header, then one line per sealed shard with
   its name, first seq, last seq and SHA-256. A seal counts only once its line is written and fsynced.
3. The collector sends each index line to the ledger as a `shard-seal` entry. On Open it re-sends every
   line after the last seal the ledger reports; the ledger accepts the same name and hash once and
   refuses a known name with another hash.
4. Open trusts a `.db` that has an index line. `Read` refuses an indexed shard whose hash does not
   match and the reader reports UNKNOWN health; that shard is never sealed again.
5. Any other `.db` is recovered. Before any open, a WAL whose damage would drop a committed transaction, or a zero-byte `.db`
   beside frames (SQLite would delete them), fails recovery; damage SQLite cannot tell from a torn write loses at most the last
   two commits (each one Flush batch). Whether a hard reset does this is measured by `crash_loss_ms`, which stays strict (every
   acknowledged commit must survive); a miss is the maintainer's decision. The rest are opened read-write, so SQLite applies
   their WAL; one with no `records` table or rows is removed with its `-wal` and `-shm`. Every other has each leaf and the seq
   order checked, then is sealed, indexed and a health record stored. A shard that fails stays where it is and Open fails, so
   no seq is issued past an unknown range; the maintainer decides, and that decision records its seq range as a loss.
6. The last index line without its newline is a torn append: it is ignored and its shard recovered.
   Any other malformed line, lines out of order or another major version make Open fail; a missing
   index with shards present means recovering every shard, never trusting one.
7. The next seq on Open is one past the highest seq in the index and the recovered shards. A `.db`
   name other than 20 digits at most 2^63-1 makes Open fail.
8. The reserved headroom also covers index lines, and own records when the filesystem runs short before the cap: free space (statfs f_bavail; quotas are not seen) is a second cap that drops new records, and what the reserve gave back is kept for own records (T10). Recovery short of space makes Open fail (point 5).

## Alternatives considered

- Ask the ledger at Open: makes recording wait for another process and couples their failures.
- Trust the SQLite header: a crash between the journal switch and the hash leaves a sealed-looking file.
- Flush from Append only: an idle collector would hold drop counts without bound.
- Hash every indexed shard at Open: about 70 s for a 150 GiB store, while the sensor blocks.

## Consequences

- `internal/store` gains `Flush`, the index and recovery; `internal/shard` gains opening an unsealed
  shard for recovery; the collector gains the ticker; the ledger gains a `shard-seal` entry type with
  test vectors (ADR 0006, point 1).
- Crash tests (kill -9): while dropping at the cap, also during a rotation seal; inside Create; after
  the journal switch; after the seal but before the index line; with a torn index line; after the index
  line but before the ledger entry. Each restart leaves every stored record readable or the store
  UNKNOWN, and loses at most `crash_loss_ms` of drop counts.
