# 0005 — Store raw records in sealed SQLite day shards; derive OCSF views

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The store must keep exact evidence, survive crashes and have a cap and retention (R5), while the
Merkle log (ADR 0006) proves what was stored. OCSF 1.9.0 (2026-08-03) changes every few months and
defines no canonical form, so a hash over normalized events breaks with every normalizer change.
modernc.org/sqlite v1.60.1 is pure Go. Readers opening a database with `immutable=1` do not see
records still in its WAL file (checked by a SQLite probe in review).

## Decision

1. Evidence is the bytes the sensor delivered (ADR 0004) plus `seq` (ours, gap-free), `provider`,
   `provider_seq` and `recv_time_ns`. The collector is the only writer (ADR 0007).
2. Record leaf, SHA-256 over one byte encoding: `"kordon/raw/v1"`, 0x00, u64be seq, u16be length +
   provider, u64be provider_seq, i64be recv_time_ns, 32-byte SHA-256 of the raw bytes. A new
   encoding gets a new version string. Test vectors live in `testdata`; malformed input is refused.
3. One SQLite database per day, or earlier at a size limit; WAL with `synchronous=FULL`, commits at
   most every 200 ms. Sealing a shard: checkpoint the WAL, switch to `journal_mode=DELETE`, fsync,
   compute the file's SHA-256, then rename it into the closed directory. A shard that fails any step
   stays unpublished and the store state is UNKNOWN. Closed shards are never written again.
4. A batch is the set of records committed in one anchoring interval; its range and leaf go to the
   ledger, which anchors batches and seals (ADR 0006). The ledger keeps its own durable map of
   batch → log index and appends each batch at most once; after a restart it reads the last log
   entry, which names its batch, and resumes from there. The ledger continuously compares the last
   anchored `seq` with the collector's highest committed `seq`; a lag beyond the limit is UNKNOWN.
5. Retention: a shard may be deleted only when it is sealed, its seal is in a cosigned checkpoint,
   and it is older than the minimum age. Before deleting, the ledger appends an expiry entry naming
   the shard and its hash. Deletion without an expiry entry is tampering.
6. Cap: when the size cap is reached and no shard is eligible, the collector drops new records,
   records a loss event and the witness side raises an alarm (ADR 0006). Evidence already stored is
   kept; blindness is visible. The cap never grows by itself.
7. Normalized events (OCSF 1.9.0) are a derived view rebuilt from raw shards. Every row carries
   `schema_version` and `normalizer_version`; readers reject an unknown major version. The class
   mapping is decided in the normalizer ADR.

## Alternatives considered

- One growing database: retention needs `DELETE` and `VACUUM`, which rewrite live evidence.
- Hash chain over normalized OCSF: breaks on every normalizer change.
- Deleting the oldest shard when the cap is hit: lets a flood of events push evidence out.
- immudb: BSL licence and a database server; DuckDB: analytics only, never in the write path.

## Consequences

- Laurel's output is evidence: if Laurel alters a record, we anchor the altered bytes.
- Crash test: with Laurel writing at the rate in `acceptance/0.toml`, `kill -9` the collector and
  restart it at once; records Laurel handed over before the kill and missing after restart count as
  durability loss. Records lost while the collector was down count as sensor loss (ADR 0004).
- Tests: test vectors for the leaf encoding; an unknown major version is refused; a failed seal leaves
  the shard unpublished; retention never deletes an ineligible shard; the cap drops new records with
  a loss event. Rates, sizes, ages and limits are numbers in `acceptance/0.toml`.
- Retro-hunt attaches closed shards read-only; the attach limit is measured, not assumed.
