# 0050 — Read a shard from the copy it hashed

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: claude/opus-5.5 (delegated by alex, 2026-11-02)
- Agent: claude/opus-5.5
- Amends: ADR 0005 point 3 (how `shard.Read` checks a sealed shard); closes the C1 open decision and issue #206.

## Context

`shard.Read` hashed a sealed shard through one descriptor, then had SQLite open it again by path. The collector's
uid owns every shard file, so a collector broken through T18 could swap the path or rewrite the inode in place
between the hash and the read, or during the read, and its readers (the range judge now, the normalizer later)
would take the forged records as the sealed ones. A test that rewrites the file in place during the read got
forged records from the old code without any error. Shards are at most 512 MiB plus a WAL (`shardMax`).

## Decision

1. `shard.Read` copies the shard into an unnamed file (`O_TMPFILE`) in a directory the caller gives, hashing exactly
   the bytes it writes, checks the header and the hash on the copy, and reads only the copy, through
   `modernc.org/sqlite/vfs` (a read-only VFS over a Go `fs.FS`; same module as the driver, ADR 0003). SQLite cannot
   open an unnamed file by `/proc/self/fd`, and a named copy would need a private directory and cleanup after a crash.
2. The caller gives the directory and the largest shard it copies (`shard.Scratch`); a larger file is refused before
   the copy, a file that shrinks during it fails. The copy disappears with its descriptor, crash included.
3. The copy is never on the store's filesystem: its free space is the collector's headroom. The range guest copies
   to its `/tmp`, never the scratch disk that full-fs trials fill. The normalizer chooses its space in its own ADR.
4. `shard.Leaves` (the ledger's stream) stays without a hash: the ledger anchors what it streams (ADR 0027).

## Alternatives considered

- Open `/proc/self/fd/<n>` of the hashed descriptor: SQLite resolves it to the deleted name and fails; it would also
  leave the in-place rewrite open.
- Hash again after the read: a rewrite undone between the two hashes still passes.
- Read the whole shard into memory: up to 512 MiB of resident memory against `rss_mib`.
- A named copy in a reader-only directory: needs its permissions checked and leftovers of a crash removed.

## Consequences

Each read costs one more pass over the shard and up to 512 MiB in the reader's space while it reads. The guest's
`/tmp` holding the largest shard is checked by the range runs, not by a test.
