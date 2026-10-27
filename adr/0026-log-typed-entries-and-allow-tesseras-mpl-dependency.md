# 0026 — Log typed entries, and allow Tessera's one MPL-2.0 dependency

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-27
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 anchors the record log in Tessera with entries that are "hashes and ranges, never record bodies", but does
not say what one entry is. One per raw record at `sustained_rate` (2000/s) is about 6·10^10 leaves a year, some 2 TB
of level-0 hashes alone, far over `host_log_cap_gib` (10). Tessera v1.0.4's root package imports
`github.com/hashicorp/golang-lru/v2` (`antispam.go`), MPL-2.0; ENGINEERING.md §7 allows only Apache-2.0, MIT, BSD
and ISC, so ADR 0006 cannot be built as decided. It also leaves the push channel, rollover and intervals open.

## Decision

1. A log entry is one typed ledger event, never one raw record. Encoding `balistid/entry/v1` (`internal/entry`):
   the label, a zero byte, a type byte, the host's time in ns since 1970 UTC (information only, T22), then
   big-endian fixed-width fields; a string is a length byte and printable ASCII. Types: `batch` (first and last
   seq of committed records, and the RFC 6962 Merkle tree hash over D[i] = the 32-byte `rawrecord.Leaf` of seq
   first+i), `seal` (first, last seq and SHA-256 of a sealed shard, the store's index line; its name follows from
   first), `loss` (stage, records, bytes), `health` (OK, or UNKNOWN with its reason; records stored truncated and
   malformed the collector counted since its previous health record; a collector restart counts from zero, and
   what it counted but never reported stays only in its stats records), `announce` (shutdown or suspend),
   `final` (the next yearly log's origin, a C2SP origin: no `+`). Seqs are 1 to 2^63-1, as the store issues them.
   Decoding is strict: known label and type, every field in range, no trailing bytes, at most 256 bytes; vectors
   pin it, a fuzz target covers it (`fuzz_hours`). A changed field needs a new label; a new type keeps v1 and
   reaches the Pi before the ledger writes it. Loss and health records stay raw records in the store too.
2. What the Pi checks between entries (batch ranges without gap or overlap, how often health must come, nothing
   after `final`) is decided with the Pi's verifier, against `anchor_interval_s`, `loss_alarm_s`,
   `silence_alarm_s` and `announced_quiet_max_h`; v1 carries what those checks read. A seq range declared lost
   (ADR 0013 point 5) gets its own type with the code that records it. Checkpoints every 5 s and a Pi poll every
   30 s are defaults, not acceptance numbers.
3. Tessera v1.0.4 as decided, with one exception to ENGINEERING.md §7: `github.com/hashicorp/golang-lru/v2`,
   MPL-2.0, linked unmodified only as Tessera's dependency, never imported by our code. MPL-2.0 is copyleft per
   file: binaries and packages name it, its licence and its source (MPL §3.2), and our code keeps Apache-2.0 (a
   reading of the licence, not legal advice). Any other licence, or a modified MPL file, needs its own ADR. Tessera
   lands with the ledger code that uses it, in its own commit with every module's licence (R14), a depguard rule
   against importing golang-lru and a licence check over `go list -deps`.
4. Unit tests use a fake witness in-process; CI and the range run a pinned litewitness end to end (ADR 0006,
   point 5). The Pi pushes through ntfy with a token stored only on the Pi; T16 includes the Pi's outbound
   internet. A new yearly origin is added on the Pi by hand (`witnessctl add-log`) after the old log's `final` is
   cosigned: no code on the Pi changes whom it trusts from host data (T17).
5. `internal/entry` is code-owned like `internal/rawrecord`. Who merges ledger and relay code is decided with
   their first pull request.

## Alternatives considered

- One entry per raw record: over the log cap within days. One per shard: anchoring would wait for a seal.
- A lean log on `golang.org/x/mod/sumdb/tlog` (one BSD module, about 500 lines of our own crash-safe tile
  writing): crash-safe files are what the store failed two critic rounds on (ADR 0013); the fallback if this
  exception is refused. Forking Tessera to drop the LRU: a fork to maintain for one import.
- Automatic origin rollover on the Pi: code that changes trust from host data, once a year.

## Consequences

- Amends ADR 0006 points 1 and 3 and ENGINEERING.md §7 (the named exception); ADR 0013's `shard-seal` is `seal`.
- A batch root lets a later proof show one record inside an anchored range; health and loss entries are
  forgeable by root (T14), as ADR 0006 states. Tests: vectors per type, every malformed field refused, round trip.
