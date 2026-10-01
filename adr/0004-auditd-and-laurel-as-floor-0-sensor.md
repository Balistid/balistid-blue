# 0004 — Use auditd with Laurel as the floor-0 sensor

- Status: proposed (accepted after the smoke test on the target kernel passes)
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R9: do not write a sensor someone maintains. Linux audit is a stable kernel ABI; Arch ships
`core/audit` 4.2.1. Laurel v0.8.2 (threathunters-io/laurel, GPL-3.0, 2026-07-17) is an auditd plugin
that merges multi-record events into JSON lines, adds parent process data and drops root to `_laurel`.
It is not in the Arch repositories; AUR `laurel-audit` builds it from a tag. One person wrote nearly
all of its commits. eBPF sensors break on rolling kernels: Falco 0.45.0 fails to load a program on
kernel 7.2.7 (falcosecurity/falco#4017, open on 2026-10-01). Checked by API and docs, not run here.

## Decision

1. Floor 0 records through auditd and Laurel. Laurel runs as its own process and is not linked
   into Kordon, so its licence does not reach our code.
2. Laurel is built from our own PKGBUILD in this repository, pinned to a tag and its sha256, with
   `cargo build --locked`. Audit rules, `auditd.conf` limits (`-b`, `-f`, `-r`) and the Laurel config
   live in the repository and are installed only by `kordon-install` (R1, R8).
3. Laurel hands records to the collector as a stream (pipe or unix socket), not through its rotated
   file, so no other uid can rewrite records between write and ingest. The exact option is fixed by
   the smoke test.
4. Loss is what the kernel reports: the collector reads `lost` and `backlog` (`auditctl -s`) on a
   schedule and records every increase of `lost` as an event. A gap in audit serial numbers alone is
   not counted as loss.
5. A canary (a known file access by the collector) must appear in the stream after start and on a
   schedule. Missing canary, stopped auditd, killed Laurel or `audit_enabled=0` make the sensor
   state UNKNOWN (R6), never healthy.

## Alternatives considered

- go-libaudit multicast in our daemon: no extra process, but best effort by design (kernel copies
  to multicast listeners), cannot set rules or backlog, open ENOBUFS issues, no code change since
  2025-05. Kept as the fallback if Laurel stops being maintained.
- Falco, Tetragon (eBPF): richer data, but kernel-coupled; Tetragon is planned for floor 4/5.
- Tracee, Kunai, Sysmon for Linux: stale releases or not packaged; no gain over audit for floor 0.

## Consequences

- Smoke test before `accepted`: auditd 4.2.1 and Laurel on kernel 7.2.x in the range VM, with
  the canary seen and `lost` read.
- Tests (R4, R10): killing Laurel, `auditctl -e 0` and stopping auditd each produce `SENSOR_DOWN`
  within N seconds; a `lost` increase produces an event; a missing canary raises an alarm.
  N and the allowed `lost` per day are numbers in `acceptance/0.toml`.
- A pacman hook on `linux` and `audit` upgrades reruns the smoke test and records the result.
- Laurel output is part of the trusted base (ADR 0005); a Laurel bug can drop or alter records.
- Trigger to revisit: no Laurel release for 12 months, or a kernel upgrade it cannot follow.
