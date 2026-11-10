# 0075 — What 9.5 passing means

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-10
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-10)
- Agent: claude/opus-5.5
- States when 9.5 has passed, in what order its parts run, and which recorder version the days bind.

## Context

9.5 is spread over ADR 0056, 0064, 0068, 0072, 0073 and 0074, and no line says when it has passed. Range metrics
count only from the runner on the host (ADR 0028), which installs after the recorder; the witness's five deliveries
come after the days (ADR 0072); moving floor 0 into `balistid.slice` before the witness (ADR 0073) changes the
recorder after the days. Without one definition each session re-derives it, and the next step drifts.

## Decision

1. 9.5 has passed when all of these hold on the maintainer's host:
   a. the judge gives PASS for `healthy_ok`, `loss_per_day`, `reconnects_per_day` and `cpu_cores_typical` over the
      7 days on one recorder version A (ADR 0073, 0074), and states each day's bytes, for `capacity_margin`;
   b. after the days, the `witness` component is installed and its five deliveries shown (ADR 0072 point 2);
   c. after the days, the runner on the host runs the acceptance suite from main on 4 vCPUs (#200) and every range
      metric passes there (ADR 0028: `range-kvm` in CI is no evidence);
   d. `cpu_cores` is measured on the host after the witness, as its method says;
   e. every other metric is decided as acceptance and ADR 0043, 0052 and 0072 say for local mode. A metric whose
      method needs the Pi (L12) and has no local-mode rule there stays open, named in STATUS, and does not block.
2. Order: the recorder (version A) installs from a commit the nightly fuzz workflow passed (`fuzz_hours`); during
   the days only the judge's method lands and installs, and nothing installs that changes the recorder. After the
   days, one install brings `balistid.slice`, the witness and the runner (version B).
3. The days bind version A. Version B may change units, the slice and other components; a change to the code of
   the collector, the ledger, auditstat or the sensor's rules or configuration starts the 7 days again.
4. `/security-audit` of the installer's root layer runs before the bootstrap of version A, by the maintainer; its
   findings are fixed or named before the install, as ENGINEERING §5 asks of root changes.
5. 9.5 passing is not floor 0 closing: the ADR 0056 checkpoint follows 9.5 within two weeks; floor 0 closes later,
   when acceptance is met and ADR 0055's audit and deletion pass and ADR 0067's red team ran on one commit.

## Alternatives considered

- Pass 9.5 on the judge alone: the range metrics would rest on CI's `range-kvm`, which ADR 0028 refuses.
- Install the witness and the slice before the days: version A would carry them, but the witness is not built and
  the days would wait for it.
- Rerun the days after version B: a week more, for unit and slice changes the judge's records already cover.

## Consequences

- STATUS lists these parts as the next steps, each with its owner; the open L12 metrics are named there.
- The judge's summary adds each day's stored bytes; its method pull request carries it.
- Revert: a pull request removing this file and its STATUS lines.
