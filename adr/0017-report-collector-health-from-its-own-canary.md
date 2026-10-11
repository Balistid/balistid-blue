# 0017 — Report the collector's health from its own canary

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-11
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0004 point 4 requires sensor health that is fresh or UNKNOWN with a canary on a schedule; ADR 0007 gives the
collector the canary. Acceptance: two missed canaries 30 s apart set UNKNOWN (`canary_interval_s`), killing Laurel or
stopping auditd reads UNKNOWN within 10 s (`sensor_down_s`), a health failure reaches the phone within 120 s
(`loss_alarm_s`), health is OK within 30 s of boot (`ready_s`). An audited syscall can sleep up to 60 s per record when
the kernel backlog is full (ADR 0016), so a canary writer can hang. Laurel re-execs itself on SIGHUP with the same pid.

## Decision

1. Health is UNKNOWN from start until the first canary is stored, and READY=1 is sent once the reader runs.
2. A canary goroutine creates `c-<n>` every 30 s in a 0700 directory of the collector's uid outside the store, and
   removes `c-<n-1>`; an audit rule watches the directory with key `balistid-canary`. Probe `n` counts as seen only
   when the writer stores a record with that key, the collector's uid and pid, `success=yes` and the name `c-<n>`.
3. The writer checks deadlines on its own tick: a probe not seen within 30 s is a miss whether or not its goroutine
   returned; two misses set UNKNOWN. A late record for an old probe does not count. No exec, so the unit can deny
   `execve` (T18); shutdown does not wait for the canary goroutine, which holds no store state.
4. Every EOF from Laurel sets UNKNOWN until a probe is seen over the next connection, and a probe is sent at once.
   Every connection is a health record with Laurel's pid and its cause: collector start, a new pid (Laurel restarted),
   or the same pid while the collector stayed up (a re-exec on SIGHUP or a reconnect, not told apart), which
   `reconnects_per_day` counts.
5. Health records (`schema_version` 1, ≤ 4 KiB, merged per tick): started (version, boot id, rule version), connection,
   lost (ADR 0016), refused, canary state on change, stats every 60 s (records, bytes, truncated, malformed, lost,
   queue high-water, max lag from handover to commit), stopping. A lag over 1000 ms is itself a health event.
6. The writer's tick feeds the systemd watchdog (`Type=notify`, `WatchdogSec`), also while the store is down, so a
   stuck writer is restarted and a deliberate drain is not.
7. While the store is down, health and loss still leave the collector: to the journal each minute and, from floor 0's
   ledger on (9.4), on the collector's stream to the ledger, so the watchdog alerts within `loss_alarm_s`.

## Alternatives considered

- An exec canary (`/usr/bin/true <token>`): needs `execve` in a process that parses untrusted input (T18).
- Liveness from traffic alone: a quiet host and a dead pipeline look the same.
- Health only in the store: a store outage would hide itself until the Pi's silence alarm (900 s).

## Consequences

- Exception to ENGINEERING §7: the canary goroutine is not awaited at shutdown.
- The audit rule, the directory and the units (`Restart=always`, sysinit ordering before auditd, stop before
  `shutdown.target`, the file descriptor store) ship with deployment; the range then checks `ready_s` and
  `canary_interval_s` under the final sandbox, not only `systemd_exposure`.
- The ledger ADR must carry health on the stream independently of the store.
- Tests: a forged or stale canary record (other uid, other pid, old `n`) is not seen; a canary syscall that never
  returns is a miss; EOF reads UNKNOWN until a probe; re-exec, restart and collector start are told apart; the
  watchdog stops when the writer is stuck and continues while the store is down.
