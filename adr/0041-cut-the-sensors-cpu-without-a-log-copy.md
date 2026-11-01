# 0041 — Cut the sensor's CPU: no audit.log copy, less Laurel enrichment

- Status: proposed (accepted when merged with the maintainer's approval, after the same-runner check below)
- Date: 2026-11-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

cpu_cores allows 0.5 cores at 1000 execs/s (`acceptance/0.toml`, ADR 0025); STATUS.md had 0.70 on 4 vCPU. ADR 0040
(proposed, #181) asks for a time-boxed attempt to fit auditd and Laurel before a data-source ADR. cpu-1000 on GitHub's
KVM (ADR 0037), branch `exp/cpu-path`, Laurel's own utime+stime split out of auditd's cgroup (a6272c2), cores:

| Commit | Change | Run | auditd | Laurel | collector | total |
|---|---|---|---|---|---|---|
| a6272c2 | none | 41278505987 | 0.229 | 0.241 | 0.236 | 0.706 (INVALID, steal 3.2 %) |
| a6272c2 | none | 41278509061 | 0.238 | 0.243 | 0.238 | 0.719 (INVALID, steal 3.3 %) |
| 4c9efbf | the decision below | 41279738980 | 0.095 | 0.129 | 0.152 | 0.376 PASS |
| 4c9efbf | the decision below | 41279741587 | 0.111 | 0.140 | 0.161 | 0.412 (INVALID, steal 1.03 %) |

`log_format = RAW` lost the guest's barrier exec in all 4 runs of 2a38cb8 and 8d35f0a (store read refused; 8d35f0a and
4c9efbf differ only in the format); why is not known. The two pairs ran on different runners (Azure regions differ in
the log), and the collector, which the change reaches only through slightly shorter Laurel lines, fell 34 %: much of
the drop may be the hardware (I). Scaled by the collector, auditd fell about 33 % and Laurel about 16 % (I), which on
the baseline's runners would be about 0.36 for auditd with Laurel and 0.60 in total, over the experiment's stop lines
of 0.35 and 0.45. Unmeasured: rate-sustained on 4c9efbf (its only run was on RAW), and collector GOMAXPROCS=2.

## Decision

1. `deploy/auditd/auditd.conf`: `write_logs = no`; `log_format` stays ENRICHED. auditd still writes
   `/run/audit/auditd.state` (its SIGCONT handler does not check `write_logs`, audit 4.2.1 src/auditd.c:225-256), so
   loss stage 8 and ADR 0038 are unchanged.
2. `deploy/laurel/config.toml` `[enrich]`: `execve-env = []`, `container = false`, `systemd = false`,
   `user-groups = false`; `pid`, `spawned-by` and `script` stay, so the process tree and interpreters remain.
3. Accepted only if, on one machine (the local range runner, ADR 0011), cpu-1000 twice on a6272c2 and twice on 4c9efbf
   back to back gives auditd with Laurel at most 0.35 and a total at most 0.45 in both 4c9efbf runs, and
   rate-sustained, rate-burst and loss-dispatcher pass on 4c9efbf. Otherwise this ADR is withdrawn for the
   data-source ADR (fallback F1: auditd stays, Laurel goes), as ADR 0040 says.

## Alternatives considered

- RAW records: auditd's cheapest format, but the range lost its barrier with it; not usable until the cause is found.
- `GOMAXPROCS=2` for the collector (ADR 0025 point 4): not measured within the time box; the next step if the total is
  between 0.45 and 0.5 on the same runner.
- Excluding PROCTITLE and CWD records: fewer records per exec, but evidence and a rule-version change; not tried.
- A CPU quota on the units: turns CPU into backlog and then loss; rejected.

## Consequences

- Evidence lost: the host keeps no audit.log, so nothing cross-checks the Laurel-to-collector hand-over that ADR 0004
  calls not fully measurable (T25), and `ausearch` has no local log. Laurel lines lose `LD_PRELOAD` and
  `LD_LIBRARY_PATH` values per exec, the systemd unit and container of a process and the user's groups. No acceptance
  metric, threat row or parser reads them; a later detection that wants them brings them back with its own CPU number.
- Gained: the collector's groups no longer read an audit.log (the T18 residual of ADR 0038 shrinks), and
  `disk_full_action` for the log disk no longer applies.
- Amends ADR 0004 point 2 (the config in the repository); on acceptance THREAT_MODEL T25 names the lost cross-check.
- The range numbers stay a trend (ADR 0025); the host measures every floor-0 unit, auditstat and the ledger too.
