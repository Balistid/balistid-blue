# 0038 — Report kernel and dispatcher loss from balistid-auditstat

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-31
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0004 point 4 makes kernel `lost` (resets included) and dispatcher overflow events; ADR 0007 names
`balistid-auditstat` without a design; ADR 0036 point 4 leaves both INVALID, so `loss_alarm_s` cannot pass.
`AUDIT_GET` returns the fixed `audit_status` (`lost` a resettable u32, `pid` 0 while auditd is down) and needs
`CAP_AUDIT_CONTROL`, which can also disable audit. auditd 4.2.1 counts no dispatcher drop: every overflow sets a flag
(audisp/queue.c:278) that only a SIGHUP raising `q_depth` (:593) or auditd's exit (:670) clears, shown only in
`/run/audit/auditd.state`, rewritten in place as root:`log_group` 0640 on SIGCONT or every `report_interval`
(src/auditd.c:230-264). `log_group` also sets audit.log's group (auditd.conf(5)).

## Decision

1. `balistid-auditstat`: its own uid, only `CAP_AUDIT_CONTROL`, `AF_NETLINK` only, no exec, no `PrivateUsers` (audit
   netlink refuses user namespaces, I). Every 5 s it sends `AUDIT_GET`, never a set, decodes the reply with a strict
   fixed-length decoder on `x/sys/unix` and reads nothing else. It writes a fixed-size report (version, seq,
   CLOCK_BOOTTIME, the status fields) by rename into its `RuntimeDirectory`, 0750, group of the collector.
2. The collector reads on its tick the report (`O_NOFOLLOW`, auditstat's uid, exact size, known version) and, as
   `log_group`, `auditd.state` (`report_interval = 5` via the installer), only `plugin queue overflow detected =
   yes|no`; an empty, partial or unknown file is read again, never data. No text reaches the privileged process.
3. Loss stages, written by the collector: 7 kernel (the rise of `lost`; a fall is a reset and logs max(new, 1)) and
   8 dispatcher (1 record when the flag goes from no to yes); in both, Records is a lower bound. The started record
   carries `lost`, the flag and the boot id; a restart logs only changes since the last stored report of that boot,
   and a boot's first report logs a non-zero `lost` or a yes once.
4. Health reasons: 8 report or state file missing, refused or its seq unchanged for two polls; 9 dispatcher
   overflowed, sticky until auditd restarts or its `q_depth` is raised, both root; 10 auditd not running (`pid` 0).
5. The Pi alerts per stage, `loss-<stage>` (cap, queue, framing, store, shutdown, kernel, dispatcher) and
   `loss-unstored` (unstored records), not `loss`; `truncated`, `logcap` stay. Pis decode new stages and reasons first.
6. `balistid-collector -queue-bytes` only lowers the 64 MiB queue, to at least one largest record; only the range
   sets it, so Laurel's real stream fills a small queue under a frozen store before the dispatcher overflows.
7. The loaded-rules check (ADR 0004 point 4, `sensor_down_s` "rules differ") is a later checkpoint and open until
   then: `AUDIT_LIST_RULES` returns variable records, a larger parser in the privileged process.
8. `loss_alarm_s`, 10 trials each: kernel loss transient (auditd stopped, then resumed: alert, then OK), sustained,
   and dispatcher overflow, timed from the guest's first seen rise of `lost` (after the 60 s backlog wait) or flip
   of the flag; a pass is its key at the sink within 65 s; a flag already yes is INVALID.

## Alternatives considered

- `auditctl -s` in the unit: exec and a text parser by the capability (ADR 0017 bans exec). go-libaudit's status
  call: the same request as a module unchanged since 2025-05 (ADR 0004), for about 100 lines we fuzz. auditstat
  reading `auditd.state`: a parser by the capability. A push socket: `AF_UNIX` and a listener for what a file does.
- The journal line "queue to plugins is full": 5 per window, its group reads every log. Clearing reason 9 when the
  flag reads no: only root clears it. A loss-queue writer as `_laurel`: 150 lines; stopping Laurel overflows auditd.

## Consequences

- Amends ADR 0004 point 4, ADR 0007's table and point 4, ADR 0027 point 6 (stages 7-8, reasons 8-10), ADR 0031
  points 3 and 6 (keys per stage), ADR 0036 point 4 and the `loss_alarm_s` method.
- Residuals: under `-e 2` the capability still resets `lost` and can claim the audit pid while auditd is down (I;
  negative trials record it, ADR 0017's canary stays independent). The collector's group reads audit.log (T18). An
  overflow keeps the host UNKNOWN until root acts, against `healthy_ok`.
- Tests: decoders refuse bad length, type or version and are fuzzed; reason 8 for a wrong-owner, wrong-size or stale
  report; a reset logs; a same-boot restart counts nothing twice; reason 9 holds; the unit pins its capability,
  `AF_NETLINK`, `NoNewPrivileges`; no deploy unit has `-queue-bytes`; range: exposure ≤ 4.0, only auditstat has CapEff.
