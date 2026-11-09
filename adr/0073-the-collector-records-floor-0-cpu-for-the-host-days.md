# 0073 — The collector records floor 0's CPU for the host's days

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-09
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-09)
- Agent: claude/opus-5.5
- Decides who computes for issue #201; amends the methods of `healthy_ok` and `cpu_cores_typical`.

## Context

`healthy_ok`, `loss_per_day`, `reconnects_per_day` and `cpu_cores_typical` are decided over 7 days on the reference
host, and who computes the binding result "is decided in 9.5": a result at the maintainer's uid is advisory
(T33, ADR 0018, 0025). Health, loss and connection records are already in the collector's store, 0700 and its
own uid, sealed and anchored in the ledger, and nothing retires them before a witness cosigns (ADR 0029, 0043);
they can be counted after the days. CPU cannot: nothing on the host reads it, and what a unit spent is gone with
its cgroup. The range's CPU trials read cgroups through `systemctl show`, which the collector, without exec
(T18), cannot run.

## Decision

1. The collector reads `usage_usec` of each floor-0 unit's cgroup once a second (`CPUUnits`: auditd with Laurel and
   every balistid service but the runner's, a test holding the list to `deploy/`), through one directory fd for the
   inode and the counter. An invocation ends when its cgroup is gone, has another inode or counts less; its last
   read adds to `gone_usec`. A failed read keeps the last good one and names why.
2. The started, stats (every minute) and stopping records carry it as `cpu`: `awake_ms` since the start on the
   monotonic clock, which a suspend stops, `boot_ns` (CLOCK_BOOTTIME) or `boot_err`, `ncpu`, and per unit `ino` and
   `usec` or `absent`, `gone`, `gone_usec` and `err`. The counters are cumulative, so a stats record that gives way
   in the queue loses no CPU. stopping reads again first.
3. The binding results are computed after the days by a oneshot of the collector's uid over the sealed shards,
   installed as its own component, so the recorder is not reinstalled within the days (ADR 0068 point 2). Its own
   ADR fixes the method; this one fixes what it reads and these rules:
   - A day is a UTC day. `cpu_cores_typical` divides a day's CPU by its awake time, the monotonic time between
     the day's records, so a suspend neither dilutes nor fills it.
   - A day counts with at least 4 h awake; the 7 days are the first 7 such days from the first started record of
     the installed version, none chosen after the fact.
   - An invocation that ended adds `ncpu` × the 1 s it went unread. After a collector that ended without stopping,
     the next started record closes each unit it finds in the same invocation; any other, the collector's own
     among them, counts at `ncpu` cores since its last stored read. A day only such a bound fails is UNKNOWN with
     that reason, which fails it as a MISS does (R6).
   - `healthy_ok`'s 30 s samples are taken on the awake time; one without a health record behind it is UNKNOWN.

## Alternatives considered

- systemd's `CPUUsageNSec`: the same counter, read over D-Bus or `systemctl`, which the collector cannot exec, and
  gone once the unit stops, except a journal line only adm or wheel read.
- sysstat (`pidstat`, `sadc`) and `atop`/`below`: per process or every cgroup from root, a privileged recorder
  against R13 with history nobody signs.
- node_exporter or a sampling timer: a daemon with an HTTP listener, or an exec every interval, each audited by
  the rules it measures.
- A meter of its own uid: one more daemon and uid; the collector's store already gives cap, retention, seal and
  ledger (R5).
- Wall time as the divisor: an idle night or a suspend halves a day's mean without changing what a user sees.

## Consequences

- A stats record grows by about 0.9 KiB, 2.5 KiB with every counter at its largest, under the store's 4 KiB (a test).
- `cpu_cores_typical` counts the collector's own reads; `cpu_cores` (the 1000 execs a second run) is not decided
  here and can bracket its load with these records.
- Kernel audit work charged to kauditd or to the audited processes is outside every unit's cgroup and not counted.
- Revert: a pull request removing this file, `cpu.go`, the `cpu` fields and the methods' clauses.
