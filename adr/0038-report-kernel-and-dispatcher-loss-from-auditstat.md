# 0038 — Report kernel and dispatcher loss from balistid-auditstat

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-31
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0004 point 4 makes kernel `lost` (resets included) and dispatcher overflow events; ADR 0007 names
`balistid-auditstat` without a design. `AUDIT_GET` returns the fixed `audit_status` (`lost` a resettable u32, `pid` 0
without auditd, `enabled` 2 when locked) and needs `CAP_AUDIT_CONTROL`, which can also disable audit. auditd 4.2.1
counts no dispatcher drop: an overflow sets a flag (audisp/queue.c:278) that only a SIGHUP raising `q_depth` (:593) or
the queue's end (:670: exit, or no plugins left) clears, shown only in `/run/audit/auditd.state`, truncated and
rewritten in place as root:`log_group` 0640 on SIGCONT or every `report_interval`, unlinked at a clean exit
(src/auditd.c:230-264, :1230). auditd.service restarts it on failure, flag cleared. `log_group` owns audit.log too.

## Decision

1. `balistid-auditstat` runs as its own user with the group `balistid-auditreport`, only `CAP_AUDIT_CONTROL`,
   `AF_NETLINK` only, no exec, `InaccessiblePaths=/var/log/audit`, without `PrivateUsers` or `PrivatePIDs` (audit
   netlink needs the initial namespaces, I). Every 5 s it sends one `AUDIT_GET`, never a set, and takes one message
   only: from the kernel (port 0), with the request's seq, type `AUDIT_GET`, flags 0, the exact payload length and
   nothing after it. Anything else is no report, a newer kernel's longer struct too (T26). It writes a fixed-size
   report (version, seq, the status fields) by rename into its `RuntimeDirectory`, 0750.
2. `balistid-collector` joins `balistid-auditreport` and `balistid-auditlog`, auditd's `log_group` (set, with
   `report_interval = 5`, in deploy/auditd/auditd.conf), and hides /var/log/audit too. On its tick it reads the report
   (`O_NOFOLLOW`, auditstat's uid, exact size, known version) and `auditd.state` (`O_NOFOLLOW`, a regular file of root,
   ≤ 4 KiB, one `plugin queue overflow detected = yes|no` line). A failed check refreshes nothing.
3. Loss stages, written by the collector: 7 kernel (a rise of `lost`; a fall is a reset and logs max(new, 1)) and 8
   dispatcher (1 record when the fresh flag turns from no to yes); in both, Records is a lower bound. The started
   record also carries `lost`, the flag, auditd's pid and the boot id; a restart logs only changes since the last
   stored report of that boot, and a boot's first report logs a non-zero `lost` or a yes once.
4. Health reasons, named only where health would otherwise be OK, in the order 9, 10, 8, 6: 9 dispatcher overflowed,
   while the fresh flag reads yes (sticky in auditd until a restart or a larger `q_depth`, by root); 10 auditd not
   running or audit not locked (`enabled` ≠ 2); 8 not fresh: no new report seq, or no new mtime of a valid state file
   (three of auditd's writes), within 15 s of the collector's monotonic clock. 8 and 10 wait for the collector's first
   15 s. A new auditd pid in the boot, not the first the collector sees, logs one UNKNOWN with reason 10 over any
   other reason, held until that auditd's first fresh state, as a restart may take an unseen overflow with it.
5. The loaded-rules check (ADR 0004 point 4, `sensor_down_s` "rules differ") is a later checkpoint and open until
   then: `AUDIT_LIST_RULES` returns variable records, a larger parser in the privileged process.

## Alternatives considered

- `auditctl -s`: exec and a text parser by the capability (ADR 0017 bans exec). go-libaudit's status call: the same
  request in a module unchanged since 2025-05 (ADR 0004), for 100 lines we fuzz. auditstat reading `auditd.state`: a
  parser by the capability. A push socket: `AF_UNIX` and a listener. The journal's "queue to plugins is full": 5 per
  window, its group reads every log. A collector latch for 9: lost at restart. One group: auditstat reads audit.log.

## Consequences

- Amends ADR 0004 point 4, ADR 0007's table and point 4, ADR 0017 point 5 (started record), ADR 0027 point 6
  (stages 7-8, reasons 8-10). ADR 0039 alerts on them and times the trials.
- Residuals: under `-e 2` the capability may still reset `lost` or claim the audit pid while auditd is down (I);
  while the flag reads yes, more overflows are unseen (T4); an overflow keeps the host UNKNOWN until root acts,
  against `healthy_ok`; the collector's groups read audit.log outside its unit (T18).
- Tests: the decoder refuses each field above and is fuzzed; a wrong-owner, wrong-size, unchanged or symlinked report
  or state is reason 8 after 15 s, a suspend is not; a reset logs; a same-boot restart counts nothing twice; 9 follows
  the flag across restarts; a new auditd pid is 10; the units pin groups, capability, `AF_NETLINK`, `NoNewPrivileges`;
  range: exposure ≤ 4.0, only auditstat has a CapEff, a trial records what its uid can change under `-e 2`.
