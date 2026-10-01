# 0005 — Store raw records in SQLite day shards; derive OCSF views

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The store must survive a crash, keep exact evidence, have a cap and retention from day one (R5),
and feed the Merkle log (ADR 0006). Normalized formats change: OCSF 1.9.0 (2026-08-03) added the
`record_integrity` profile, and minor versions ship every few months. A hash over a normalized object
breaks every time the normalizer changes. modernc.org/sqlite v1.60.1 embeds SQLite 3.53.4 in pure Go.
One benchmark inserted 1M rows in about 2.4 s (cvilsmeier/go-sqlite-bench, March 2026); with
group commit the limit is fsync, not the driver (inference, to be measured).

## Decision

1. The source of truth is the raw bytes the sensor delivered (Laurel JSON lines, ADR 0004), with
   `seq` (ours, gap-free), `provider`, `provider_seq`, receive time and `raw_sha256`.
2. Records go to SQLite in WAL mode with `synchronous=FULL`, one writer (the collector, ADR 0007),
   committed in groups at most 200 ms apart. One database file per day, or earlier when it reaches a
   size limit. A closed shard is never written again.
3. Leaf hash with domain separation and a version:
   `H("kordon/raw/v1" ‖ seq ‖ provider ‖ provider_seq ‖ raw_sha256)`, SHA-256. Changing the
   construction means a new version string, never a silent change.
4. SQLite is authoritative; the Merkle log (ADR 0006) is filled from a watermark. After a restart the
   collector compares the log size and the highest `seq` and records any mismatch as an event.
5. Retention deletes whole closed shards. When the size cap is reached, the oldest closed shard is
   deleted and an event names it; ingest never stops silently and the cap never grows by itself.
   Numbers (days, bytes) live in `acceptance/0.toml`.
6. Normalized events (OCSF 1.9.0) are a derived view that can be rebuilt from raw shards. Every row
   carries `schema_version` and `normalizer_version`; readers reject an unknown major version. The
   class mapping is decided in a later ADR for the normalizer.

## Alternatives considered

- One growing database: retention needs `DELETE` and `VACUUM`, which rewrite live evidence.
- Hash chain over normalized OCSF: breaks on every normalizer change; OCSF defines no canonical form.
- cgo SQLite: faster inserts, rejected in ADR 0003. DuckDB: analytics only, never in the write path.
- immudb: BSL licence and a full database server for one host.

## Consequences

- Laurel's output is evidence; if Laurel alters a record, we chain the altered bytes. Kernel-level
  integrity is out of scope for floor 0 and stated in `THREAT_MODEL.md`.
- Tests: `kill -9` of the collector at 2000 records/s loses at most 1 s of records counted from the
  sensor's write; a 10000 records/s burst for 10 s loses none; a reader given an unknown major
  version fails; retention and cap behaviour each have a lifecycle test.
- Retro-hunt across days attaches several shards read-only; the attach limit is measured, not assumed.
- A `prev_hash` column is not added: the Merkle log is the integrity proof (ADR 0006).
