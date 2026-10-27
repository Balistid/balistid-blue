# 0026 — Log typed entries, and allow Tessera's one MPL-2.0 dependency

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-27
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 anchors the record log in Tessera with entries that are "hashes and ranges, never record bodies", but does
not say what one entry is. One per raw record at `sustained_rate` (2000/s) is about 6·10^10 leaves a year, some 2 TB
of level-0 hashes alone, far over `host_log_cap_gib` (10). Tessera v1.0.4's root package imports
`github.com/hashicorp/golang-lru/v2` (`antispam.go`), whose licence is MPL-2.0; ENGINEERING.md §7 allows only
Apache-2.0, MIT, BSD and ISC, so ADR 0006 cannot be built as decided. ADR 0006 leaves the push channel, the yearly
rollover and the checkpoint interval open.

## Decision

1. A log entry is one typed ledger event, never one raw record. Encoding `balistid/entry/v1` (`internal/entry`):
   the label, a zero byte, a type byte, the host's time in ns since 1970 UTC (information only, never a security
   question, T22), then big-endian fixed-width fields; a string is one length byte and printable ASCII. Types:
   `batch` (first and last seq, and the RFC 6962 root over the `rawrecord.Leaf` of every record in that range),
   `seal` (first and last seq and SHA-256 of a sealed shard: the store's index line, its name follows from first),
   `loss` (stage, records, bytes), `health` (OK or UNKNOWN with its reason, truncated and malformed records since
   the previous health entry), `announce` (shutdown or suspend), `final` (the next yearly log's origin). Decoding is
   strict: a known label and type, every field in range, no trailing bytes, at most 256 bytes; vectors pin it, a
   fuzz target covers it (`fuzz_hours`). A change of any field needs a new label. Loss and health records stay raw
   records in the store too; their entries give the Pi, which holds no bodies, what it alarms on.
2. The ledger writes a `batch` at least every second while records arrive (`anchor_interval_s`) and checkpoints
   every 5 s; the Pi polls the relay every 30 s. Both are defaults, not acceptance numbers.
3. Tessera v1.0.4 as decided, with one exception to ENGINEERING.md §7: `github.com/hashicorp/golang-lru/v2`,
   MPL-2.0, linked unmodified. MPL-2.0 is copyleft per file: an unmodified file stays available from its source and
   our code keeps Apache-2.0 (a reading of the licence, not legal advice). Any other licence, or a modified MPL
   file, still needs its own ADR. The dependency lands in its own commit with every module's licence listed (R14).
4. Unit tests use a fake witness in-process; the range's end-to-end test runs a pinned litewitness in the guest
   (ADR 0006, point 5). The Pi pushes through ntfy with a token stored only on the Pi; T16 then includes the Pi's
   outbound internet access. A new yearly origin is added on the Pi by hand (`witnessctl add-log`) after the old
   log's `final` is cosigned: no code on the Pi changes whom it trusts from host data (T17).
5. `internal/entry` is code-owned like `internal/rawrecord`. Who merges the ledger and relay code is decided with
   their first pull request.

## Alternatives considered

- One entry per raw record: over the log cap within days at sustained_rate. One per shard: anchoring would wait
  for a seal (up to a shard's size) instead of a second.
- A lean log on `golang.org/x/mod/sumdb/tlog` (one BSD module, about 500 lines of our own crash-safe tile writing):
  crash-safe files are what the store failed two critic rounds on (ADR 0013); kept as the fallback if this
  exception is refused. Forking Tessera to drop the LRU: a fork to maintain for one import.
- Automatic origin rollover on the Pi: code that changes trust from host data, once a year.

## Consequences

- Amends ADR 0006 points 1 and 3 and ENGINEERING.md §7 (the named exception). ADR 0013's `shard-seal` is `seal`.
- The root of a `batch` lets a later proof show one record inside an anchored range; health and loss entries are
  forgeable by root (T14), as ADR 0006 states. Tests: vectors per type, refusal of every malformed field, an
  unknown type or label and trailing bytes; decode then encode gives the same bytes.
- Next: Tessera in go.mod with `go list -deps` and the licences (R14), then the ledger core (ledger-plan L3).
