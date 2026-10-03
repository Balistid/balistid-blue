# 0004 — Use auditd with Laurel as the floor-0 sensor

- Status: proposed (accepted after the smoke test on the target kernel passes)
- Date: 2026-10-01, amended 2026-10-03 (release binary, io_uring disabled, socket check with the collector)
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

1. Floor 0 records through auditd and Laurel. Our PKGBUILD packages the official release binary
   `laurel-0.8.2-x86_64-glibc.tar.gz` pinned by sha256, so no toolchain or crates download is part of a
   build; Laurel runs as a separate process, not linked into Kordon.
2. Audit rules (including `-b`, `-f`, `-r`), `auditd.conf` and the Laurel config live in the
   repository and are installed only by `kordon-install` (R1, R8). The rules end with `-e 2`; `-f 1`
   and `disk_full_action` keep a flood from halting the host. Rules cover ptrace, `process_vm_writev`,
   `execveat` and `memfd_create`, the usual ways around exec records.
   io_uring is disabled (`kernel.io_uring_disabled=2`); io_uring audit rules stay UNKNOWN. Whether the
   host can run without io_uring is decided before floor 0 is installed there. The repository also holds
   the plugin entry and the sysctl. gawk is required (augenrules silently loads no rules without it), and
   the kernel command line needs `audit=1 audit_backlog_limit=` equal to the rules' `-b`.
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
- Building Laurel from source with cargo: needs a toolchain and crates.io at build time for the same
  upstream code we already trust (T23). Revisit if we patch Laurel or the release binary disappears.

## Consequences

- Smoke test before `accepted`, in the range VM on kernel 7.2.x: Laurel's uid and remaining
  capabilities, a canary in Laurel's output, `io_uring_setup` refused, `-e 2` refused and recorded, and
  dispatcher overflow reported (`/run/audit/auditd.state`, journal). Laurel's peer uid on the collector
  socket is tested when the collector exists. Results are bound to kernel and package versions; an
  untested combination is UNKNOWN.
- Tests (R4, R10): killing Laurel, stopping auditd, a missing canary, a counter reset, a foreign
  socket peer and loaded rules that differ from the repository each produce an event or UNKNOWN; disabling audit under `-e 2` fails and is recorded.
- Known gaps (`THREAT_MODEL.md`): loss between Laurel and the collector is not fully measurable; root
  can blind the sensor undetected; x32 ABI syscalls match no syscall rule (T8). Floor 0 prevents none.
- Thresholds and allowed loss are numbers in `acceptance/0.toml`.
- Trigger to revisit: no Laurel release for 12 months, or a kernel it cannot follow.
