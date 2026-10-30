# 0031 — Watch the log from the Pi

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 points 3 and 4 put a watchdog and a scheduled verifier of ours on the Pi, beside litewitness, and
leave how it learns the log, what it checks and when it alerts to this step (ADR 0026 point 2, ADR 0030 point 3).
litewitness keeps only each log's size and root and raises no alarm. Tessera's client verifies proofs but reads
any body whole; Prometheus with Alertmanager is a service stack for a few checks; the ntfy CLI is a shell call.

## Decision

1. `balistid-pi`, one daemon as its own uid on the Pi, reads the size and root its own litewitness keeps for one
   origin from litewitness's index page on the Pi (not `-obscurity`), every second. The host sends it no
   checkpoint and the Pi holds no key: what it trusts is what its witness cosigned (T17).
2. It fetches the log's entry bundles from the relay, every bundle from its last verified size to the witness's,
   and recomputes the RFC 6962 root from the bundles and its stored compact range. Equal to the witness's root:
   every new entry is included and the log is consistent with what it verified before. Another root, or a
   witness behind the Pi, is a fork alarm and the Pi's state does not move. No hash tile is fetched.
3. The new entries are decoded strictly and checked in log order, as ADR 0027 writes them: batches follow each
   other without gap or overlap, a seal follows the batch ending at its last seq and seals tile the seqs, a loss
   is of a record after the last batch, nothing follows `final`. A broken rule, a loss of any stage but
   truncated, a health entry with unstored records, or UNKNOWN alarms; UNKNOWN for starting or a pending canary
   only when no OK follows within 60 s. Truncated records alarm when more than `truncation_alarm_per_hour` fall
   within an hour of the Pi's clock. A cosigned `final` asks the maintainer to add the next origin by hand.
4. Clocks are the Pi's monotonic clock, polled each second; host times never decide (T22). Silence: no verified
   growth for `silence_alarm_s`. A verified announcement opens a quiet episode that holds off the silence alarm
   while the witness does not grow past the Pi; it closes after an hour of growth without one, a later
   announcement does not restart it, and at `announced_quiet_max_h` from its first announcement the silence
   alarm runs again. Freshness: no step caught up with the witness for `verify_freshness_s`.
5. The Pi keeps one state file per origin: size, root, the compact range over complete bundles and the last
   partial bundle's entries, read back only when they give the root; a file that does not stops the daemon. It
   keeps no copy of the log: a mirror against deletion (T15) is its own step. An old origin's file is removed by
   hand after `log_retention_days`, as nothing on the Pi trusts its clock to delete (R5 exit, T22).
6. Alerts go to ntfy over HTTPS by POST with a token from a systemd credential, never argv, environment or logs,
   texts built from typed values only. An alert goes out when its condition starts, every 6 h while it holds,
   a key at most once a minute with what was held back sent after, retried with backoff; a daily message shows
   the Pi alive, a failed unit alerts from `OnFailure`. Triggers fire a minute before their acceptance limit.
7. `cmd/balistid-pi` and `internal/watch` are code-owned and built for arm64 reproducibly in CI, installed by
   hash. The relay's server and ADR 0030 point 4's served wait follow with a stand-in of this daemon in the range.

## Alternatives considered

- A mirror of verified bundles now: crash-safe staging for evidence nothing reads yet; it comes with its reader.
- The relay's cosigned checkpoint for the Pi: one file, but the host chooses when the Pi sees which; the witness
  then has to grow out of the Pi's sight for withholding to show. It stays the fallback if `-obscurity` is needed.
- Inclusion proofs per entry from hash tiles: slower than one root. litewitness's SQLite file: its WAL needs writes.
- A push-only uid behind a socket: the token can only post to its topic; the residual is in T16.

## Consequences

- Amends ADR 0006 point 3 (bundles only, from the relay) and point 4, ADR 0030 point 3 (the quiet episode).
- A dead Pi or a failed push is still silent until the daily message is missed (T27, floor 3).
- Tests: a fork and a witness behind refused, every log rule broken once, silence, quiet with late entries, cap
  not restarted, freshness, 11 against 10 truncations, a capped fetch, alerts merged and never dropped.
  `verify_s` and `pi_store_cap_gib` (state and witness, no mirror yet) are measured on the Pi (L12).
