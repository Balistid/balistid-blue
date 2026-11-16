# 0076 — Floor 1 first: the recorder freezes unmet

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-16
- Decided-by: jvc0n (2026-11-16: the plan "proof first", approved in session)
- Agent: claude/opus-5.5
- Stops ADR 0064 point 1, ADR 0074 and ADR 0075 (9.5 and the host days); amends ADR 0067 for floor 0.

## Context

The question this project answers: AI agents with wide rights work on the maintainer's machine; what did they
really do, and is what they claim true? Floor 0 records what ran. Its own parts, a store that root cannot rewrite
unseen and a witness off the host, matter only once an agent has root, which none has on the host today.

Where floor 0 stands: version A of the recorder runs on the maintainer's host since 2026-11-14 at 23:43. Floor 0
used 0.085 of a core there on 15 November from 13:11 to 00:41 (auditd 0.049, collector 0.027, ledger 0.009). The
judge of the 7 days is a stub (ADR 0074), so no day is judged; the witness is not built for the host; the host's
runner is at 2c09799, without the collector. None of the 43 metrics of `acceptance/0.toml` has passed on the host.
Since 2026-09-30 the work went to floor 0, and no detection exists yet.

## Decision

1. The floor-0 recorder freezes unmet. `acceptance/0.toml` stays as written, and this ADR claims no metric passed.
   9.5 and the host days stop. The host install stays as it is: nothing changes on the host before the floor-1
   pilot is valid, and not before 2026-11-30.
2. The code of the collector, store, ledger, relay and Pi watcher stays on `main`, frozen: no new scope, and fixes
   only where the range or the host still runs it. The collector stays in the range image as its instrument.
3. These 21 metrics leave with the recorder, as they measure the store, the ledger, the relay or the Pi:
   `reconnects_per_day`, `crash_loss_ms`, `truncation_alarm_per_hour`, `raw_retention_days`, `raw_cap_gib`,
   `capacity_margin`, `headroom_gib`, `shard_max_gib`, `derived_cap_gib`, `host_log_cap_gib`, `refusal_summary_s`,
   `anchor_interval_s`, `cosign_gap_s`, `silence_alarm_s`, `announced_quiet_max_h`, `verify_freshness_s`,
   `verify_s`, `log_retention_days`, `pi_store_cap_gib`, `dead_site_alarm_s`, `push_refused_alarm_s`.
   The other 22 are candidates for a sensor's bar, which a later ADR with its own acceptance file decides after the
   pilot. Nothing is measured again now.
4. Floor 1 starts as measurement. The host computes a detection verdict (ADR 0009 point 7: CAUGHT, MISSED, QUIET,
   NOISY, INVALID) from the records of the runner's agent jobs (ADR 0011), with rules as data and the judge's code
   fixed. ADR 0077 decides the judge. The range code does not change for it.
5. The store and the witness come back through a new ADR when an agent on the host gets root. ADR 0067's red team
   and ADR 0055's floor-0 checkpoint wait with them.

## Alternatives considered

- Finish 9.5 first: weeks of days, the witness and version B, against an adversary the host does not have yet,
  while no detection exists.
- Delete the ledger, relay and witness code: loses reviewed work that point 5 plans to bring back.
- Measure all 43 metrics again as a sensor's bar: most of them measure parts this ADR freezes.

## Consequences

- STATUS names the floor-1 pilot as the next step; the README says the recorder is frozen and why.
- `THREAT_MODEL.md` rows stay as they are: no control or proof changes, and each status stays as tested.
- Floor 1 has no acceptance file yet: ADR 0077 brings `acceptance/1.toml` before the judge's first code (R3).
- Revert: a pull request removing this file and restoring the STATUS and README lines.
