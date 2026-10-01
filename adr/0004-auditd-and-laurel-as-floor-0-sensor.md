# 0004 — Use auditd with Laurel as the floor-0 sensor

- Status: proposed (accepted after the smoke test on the target kernel passes)
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R9: do not write a sensor someone maintains. Linux audit is a stable kernel ABI; Arch ships
`core/audit` 4.2.1. Laurel v0.8.2 (threathunters-io/laurel, GPL-3.0, 2026-07-17) is an auditd plugin
that merges multi-record events into JSON lines and drops root to `_laurel`; one person wrote nearly
all of it, and it is only in the AUR. eBPF sensors break on rolling kernels: Falco 0.45.0 fails on
7.2.7 (falcosecurity/falco#4017, open on 2026-10-01). Loss can happen at four places: the kernel
queue (`lost`), the auditd dispatcher queue (`q_depth`, `overflow_action` in `auditd.conf(5)`),
Laurel, and the hand-over to our collector. `auditctl --reset-lost` zeroes the kernel counter.

## Decision

1. Floor 0 records through auditd and Laurel, built from our PKGBUILD pinned to a tag and sha256 with
   `cargo build --locked`. Laurel is a separate process, not linked into Kordon.
2. Audit rules (including `-b`, `-f`, `-r`), `auditd.conf` and the Laurel config live in the repository
   and are installed only by `kordon-install` (R1, R8). The rule file ends with `-e 2`, so rules
   cannot change until reboot.
3. Laurel writes to a Unix socket the collector listens on. The collector accepts only a peer whose
   `SO_PEERCRED` uid is `_laurel`, caps each record at a fixed size and refuses anything else.
4. Loss is tracked per layer, each as an event: a rise in kernel `lost`, and any decrease of it, which
   means a reset; dispatcher overflow, reported through syslog; Laurel and collector reconnects. Audit
   serial gaps above a threshold set the sensor state to UNKNOWN. Laurel→collector loss is not fully
   measurable on floor 0; `THREAT_MODEL.md` states this gap.
5. Health is fresh or UNKNOWN (R6): a canary record must arrive within N seconds on a schedule, and
   the loaded rule list must hash to the repository's rule hash. A failed or stale reading of any
   of these is UNKNOWN, never healthy. Counters come from `kordon-auditstat` (ADR 0007).
6. R13 covers Kordon's processes. auditd, and Laurel until it drops privileges, are OS components
   that run as root; this ADR records that exception.

## Alternatives considered

- go-libaudit multicast in our daemon: best effort by kernel design, cannot set rules, open ENOBUFS
  issues, no code change since 2025-05. Kept as the fallback if Laurel stops being maintained.
- Falco, Tetragon (eBPF): kernel-coupled; Tetragon is planned for floor 4/5.
- Tracee, Kunai, Sysmon for Linux: no gain over audit for floor 0.

## Consequences

- Smoke test before `accepted`: auditd 4.2.1 and Laurel on kernel 7.2.x in the range VM; it also fixes
  how dispatcher overflow is reported. Results are bound to the running kernel and the installed
  auditd, Laurel and rule versions; an untested combination after reboot is UNKNOWN.
- Tests (R4, R10): killing Laurel, stopping auditd, a missing canary, `--reset-lost`, a socket peer
  other than `_laurel` and a rule-hash mismatch each produce an event or UNKNOWN within N seconds;
  `auditctl -e 0` fails under `-e 2` and the attempt is recorded.
- N, the serial-gap threshold and the allowed loss per day are numbers in `acceptance/0.toml`.
- Laurel's output is part of the trusted base (ADR 0005).
- Trigger to revisit: no Laurel release for 12 months, or a kernel it cannot follow.
