# 0005 — Store raw records in sealed SQLite day shards; derive OCSF views

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The store must keep exact evidence, survive crashes and have a cap and retention (R5); the Merkle log
(ADR 0006) proves what was stored. OCSF 1.9.0 (2026-08-03) changes every few months and defines no
canonical form, so a hash over normalized events breaks with every normalizer change.
modernc.org/sqlite v1.60.1 is pure Go. Readers opening a database with `immutable=1` do not see
records still in its WAL file (SQLite probe during review).

## Decision

1. Evidence is the bytes the sensor delivered (ADR 0004) with our gap-free `seq`, the provider, its
   sequence number and the receive time. The collector is the only writer (ADR 0007).
2. Each record has a leaf hash over a versioned, length-prefixed byte encoding of all those fields
   (SHA-256, label `kordon/raw/v1`). The exact encoding lives in code with test vectors; a change
   gets a new label.
3. One SQLite database per day, or earlier at a size limit; WAL with `synchronous=FULL`. A shard is
   sealed (WAL checkpointed, journal mode switched, file and directory fsynced, file hashed) before
   anyone else may open it, and is never written again. A failed seal leaves it unpublished and the
   store UNKNOWN.
4. When the cap is reached, new records are dropped and a loss event is stored in reserved headroom;
   stored evidence is never evicted to make room, so a flood cannot push it out. The collector deletes
   a shard only when the ledger reports its seal anchored and cosigned and it is older than the
   minimum age.
5. Normalized events (OCSF 1.9.0) are a derived view rebuilt from raw shards. Every row carries
   `schema_version` and `normalizer_version`; readers reject an unknown major version. The class
   mapping is decided in the normalizer ADR.
6. The recovery protocol between the store and the log (batches, restart, at-least-once with
   de-duplication, no `seq` gaps between anchored ranges) is designed in code with crash tests in the
   range before floor 0 is called done; this ADR fixes its requirements, not its mechanism.

## Alternatives considered

- One growing database: retention needs `DELETE` and `VACUUM`, which rewrite live evidence.
- Hash chain over normalized OCSF: breaks on every normalizer change.
- Evicting the oldest shard when full: lets a flood of events push evidence out.
- immudb: BSL licence and a database server; DuckDB: analytics only, never in the write path.

## Consequences

- Laurel's output is evidence: if Laurel alters a record, we anchor the altered bytes.
- Known gap stated in `THREAT_MODEL.md`: root on the host can delete evidence, and on floor 0 that
  is not reliably distinguishable from retention off the host.
- Tests: leaf test vectors; unknown major version refused; failed seal stays unpublished; retention
  never deletes an ineligible shard; a full store drops new records with a loss event; every store
  the floor creates (shards, ledger state, tiles, mirror) has a cap and retention test (R5).
- Rates, sizes, ages and the crash-loss bound are numbers in `acceptance/0.toml`.
