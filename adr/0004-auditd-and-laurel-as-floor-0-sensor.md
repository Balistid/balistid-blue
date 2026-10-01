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
7.2.7 (falcosecurity/falco#4017, open on 2026-10-01). Records can be lost in the kernel queue
(`lost`), the auditd dispatcher (`q_depth`, `overflow_action`), Laurel, or the hand-over to us.
Audit exit rules do not see io_uring operations unless io_uring rules are loaded (`auditctl(8)`).

## Decision

1. Floor 0 records through auditd and Laurel. Laurel is built from our PKGBUILD pinned to a tag and
   sha256 (`cargo build --locked`) and runs as a separate process, not linked into Kordon.
2. Audit rules (including `-b`, `-f`, `-r`), `auditd.conf` and the Laurel config live in the
   repository and are installed only by `kordon-install` (R1, R8). The rules end with `-e 2`.
   io_uring is either disabled (`kernel.io_uring_disabled=2`) or covered by io_uring rules; the smoke
   test decides which, and the other state is UNKNOWN.
3. Laurel hands records to the collector over a Unix socket that admits only Laurel's uid.
4. Required properties, implemented in code with tests: every loss signal we can read (kernel `lost`
   including resets, dispatcher overflow, Laurel and collector reconnects) becomes an event; sensor
   health is fresh or UNKNOWN (R6), with a canary that must arrive on a schedule. How the loaded rules
   are checked against the repository is designed with `kordon-auditstat` (ADR 0007).
5. R13 covers Kordon's processes; auditd, and Laurel until it drops privileges, are OS components that
   run as root. This ADR records that exception.

## Alternatives considered

- go-libaudit multicast in our daemon: best effort by kernel design, cannot set rules, open ENOBUFS
  issues, no code change since 2025-05. Kept as the fallback if Laurel stops being maintained.
- Falco, Tetragon (eBPF): kernel-coupled; Tetragon is planned for floor 4/5.
- Tracee, Kunai, Sysmon for Linux: no gain over audit for floor 0.

## Consequences

- Smoke test before `accepted`, in the range VM on kernel 7.2.x: Laurel's peer uid on the socket and
  its remaining capabilities, how dispatcher overflow is reported, io_uring coverage, and `-e 2`.
  Results are bound to kernel and package versions; an untested combination is UNKNOWN.
- Tests (R4, R10): killing Laurel, stopping auditd, a missing canary, a counter reset, a foreign
  socket peer and loaded rules that differ from the repository each produce an event or UNKNOWN; disabling audit under `-e 2` fails and is recorded.
- Known gap stated in `THREAT_MODEL.md`: loss between Laurel and the collector is not fully
  measurable, and root on the host can blind the sensor undetected; floor 0 does not prevent that.
- Thresholds and allowed loss are numbers in `acceptance/0.toml`.
- Trigger to revisit: no Laurel release for 12 months, or a kernel it cannot follow.
