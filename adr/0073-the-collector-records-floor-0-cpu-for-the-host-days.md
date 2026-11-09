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
its cgroup. The range reads cgroups through `systemctl show`, which the collector, without exec (T18), cannot run.

## Decision

1. The collector reads `usage_usec` of each floor-0 unit's cgroup in system.slice at most once a second
   (`CPUUnits`: auditd with Laurel and every balistid service but the runner's; a test holds the list to `deploy/`
   and refuses `Slice=` there), through one directory fd for the inode and the counter. An invocation ends when its
   cgroup is gone, has another inode or counts less; its last read adds to `gone_usec` and the time since it to
   `gone_unread_ms`. A failed read keeps the last good one and names why, in the record and once in the journal.
2. Started, stats (every minute) and stopping carry it as `cpu`: `mono_ns` (CLOCK_MONOTONIC, which a suspend stops)
   and `boot_ns`, or `mono_err`/`boot_err`, `ncpu` (the collector's CPUs), per unit `ino` and `usec` or `absent`,
   `gone`, `gone_usec`, `gone_unread_ms`, `err`, and `err` when the collector's own cgroup is absent. The counters
   are cumulative, so a stats record that gives way loses no CPU; stopping reads again first.
3. A oneshot of the collector's uid computes the binding results over the sealed shards after the days, installed
   as its own component so the recorder is not reinstalled within them (ADR 0068 point 2). Its ADR fixes the method
   within these rules:
   - A day is a UTC day; CPU between two records across midnight splits by their `mono_ns`. `cpu_cores_typical`
     divides a day's CPU by its awake time, the `mono_ns` between its records of each boot.
   - A unit counts from 0 when first seen absent or new in a boot; from the last record of the same inode, also of
     an earlier collector run; otherwise the day is UNKNOWN.
   - What went unread counts at `ncpu` cores: `gone_unread_ms` for ended invocations, and for a collector that
     ended without stopping the time from its last record to the next started, unless that record finds the inode.
   - A day counts with at least 4 h awake; the 7 days are the first 7 such days from the first started record of
     the installed version. `healthy_ok` samples every 30 s of awake time; a gap in the records is UNKNOWN.
   - Any UNKNOWN fails the day as a MISS does (R6).

## Alternatives considered

- systemd's `CPUUsageNSec`: the same counter over D-Bus or `systemctl`, which the collector cannot exec, gone once
  the unit stops but for a journal line only adm or wheel read.
- sysstat, `atop` or `below`: per process or every cgroup from root, a privileged recorder against R13.
- node_exporter or a sampling timer: a daemon with a listener, or an exec every interval the rules audit.
- A meter of its own uid: one more daemon; the collector's store already has cap, retention, seal and ledger (R5).
- Wall time as the divisor: a suspend would halve a day's mean without changing what a user sees.

## Consequences

- A stats record grows by about 1 KiB, 2.5 KiB with every counter at its largest, under the store's 4 KiB (a test).
- Not counted: kernel audit work outside the units' cgroups, and a oneshot that starts and ends between two reads.
  The recorder has no oneshot; before `witness` installs net, announce and pi-failed, floor 0 moves into a
  `balistid.slice`, whose counter keeps its ended children's CPU.
- Awake time counts an idle host kept awake, which a sleep inhibitor at the user's uid can lengthen; the result
  shows each day's awake hours. At a stop with a backlog stopping gives way first; the stats before it bounds it.
- Revert: a pull request removing this file, `cpu.go`, the `cpu` fields and the methods' clauses.
