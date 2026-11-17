# 0076 — Floor 1 first: the recorder freezes unmet

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-16
- Decided-by: jvc0n (2026-11-16, in session)
- Agent: claude/opus-5.5
- Amends ADR 0064 point 1, ADR 0074 and ADR 0075 (it stops 9.5 and the host days), ADR 0056 points 2-4, ADR 0040
  points 1, 2 and 5 and ADR 0065 (the product line and its gates), and ADR 0067 for floor 0.

## Context

The question this project answers: AI agents with wide rights work on the maintainer's machine; what did they
really do, and is what they claim true? Floor 0 records what ran. Its own parts, a store that root cannot rewrite
unseen and a witness off the host, matter once an agent has root; the maintainer gives none root on the host today.

Where floor 0 stands: version A of the recorder runs on the maintainer's host since 2026-11-14 at 23:43. Floor 0
used 0.085 of a core there from 15 November 13:11 to 16 November 00:41 (auditd 0.049, collector 0.027, ledger
0.009): one awake span, not `cpu_cores_typical`'s method, and above its 0.05. The days' judge is a stub (ADR 0074),
so no day is judged; the witness is not built for the host; the host's runner is at 2c09799, without the
collector. None of the 43 metrics of `acceptance/0.toml` has passed on the host. Since 2026-09-30 the work went to
floor 0, and no detection exists yet.

## Decision

1. The floor-0 recorder freezes unmet; this ADR claims no metric passed. 9.5 and the host days stop. The host
   install stays as it is: nothing changes on the host before the floor-1 pilot is valid, and not before
   2026-11-30, except a security fix the maintainer installs.
2. The code of the collector, store, ledger, relay and Pi watcher stays on `main`, frozen: no new scope, and fixes
   only where the range or the host still runs it. The collector stays in the range image as its instrument.
3. `acceptance/0.toml` stays as written, and none of its metrics is measured while the recorder is frozen. These 23
   need the ledger, the relay, the witness or the Pi, or a collector or store behaviour no sensor needs (caps,
   retention, crash loss, reconnects, refusals, alarms), and bind again only if point 5 brings the recorder back:
   `reconnects_per_day`, `crash_loss_ms`, `truncation_alarm_per_hour`, `raw_retention_days`, `raw_cap_gib`,
   `capacity_margin`, `disk_default_gib`, `headroom_gib`, `shard_max_gib`, `derived_cap_gib`, `host_log_cap_gib`,
   `refusal_summary_s`, `anchor_interval_s`, `cosign_gap_s`, `loss_alarm_s`, `silence_alarm_s`,
   `announced_quiet_max_h`, `verify_freshness_s`, `verify_s`, `log_retention_days`, `pi_store_cap_gib`,
   `dead_site_alarm_s`, `push_refused_alarm_s`.
   For the other 20 a later ADR with its own acceptance file decides, after the pilot, which bind a sensor.
4. Floor 1 starts as measurement. The host computes a detection verdict (ADR 0009 point 7: CAUGHT, MISSED, QUIET,
   NOISY, INVALID) from the records of the runner's agent jobs (ADR 0011), with rules as data and the detection
   judge's code locked. ADR 0077 decides that judge. The range code does not change for it.
5. The store and the witness come back through a new ADR when the maintainer gives an agent on the host root, or
   a detection shows one took it. ADR 0067's red team and ADR 0055's floor-0 checkpoint wait with them.
6. This is ADR 0040 point 5's choice of (b) and (c): the commercial line ended on 2026-11-15, so K1 and K2 do not
   run. The floor-1 pilot's report on 2026-11-20 takes the place of ADR 0056's checkpoint as the next decision on
   direction; if the pilot is not valid, work goes to upstream contributions.

## Alternatives considered

- Finish 9.5 first: weeks of days, the witness and version B, against an adversary the host does not have yet,
  while no detection exists.
- Delete the ledger, relay and witness code: loses reviewed work that point 5 plans to bring back.
- Measure all 43 metrics again as a sensor's bar: most of them measure parts this ADR freezes.

## Consequences

- STATUS names the floor-1 pilot as the next step; the README says the recorder is frozen and why.
- `THREAT_MODEL.md` rows stay as they are: no control or proof changes, and each status stays as tested.
- Floor 1 has no acceptance file yet: ADR 0077 brings `acceptance/1.toml` before the judge's first code (R3).
- Revert: a pull request removing this file and restoring the STATUS, README and THREAT_MODEL lines.
