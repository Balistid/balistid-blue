# 0061 — Record root covering its tracks

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: alex (2026-11-04: issue #241 and ADR 0060's rule); claude/opus-5.5 the rules and the self-test
- Agent: claude/opus-5.5
- Closes issue #241; amends ADR 0004 point 2 (rules version `adr-0004-v3`) and the T3 part of ADR 0060.

## Context

Rules v2 record execs, ptrace, `process_vm_writev`, `memfd_create` and the canary. Root that loads a module or an
eBPF program, kexecs, mounts over a tree, or empties a journal file, an audit, Laurel or unit config, our programs
or our state leaves no record unless it execs a tool; a payload in memory leaves none (T3, T5, T14). Watches with
`auid!=unset` (the issue) miss anything systemd starts; leaving a tree's owner out by program and parent pid
(review round 1) misses a preloaded journald and an orphan, which the kernel reparents to pid 1.

## Decision

1. Rules v3 start with `-c`: a line that cannot load (a tree missing at boot) is skipped, `-e 2` still loads and the
   rule list reads `rules-differ` (ADR 0059). They add `pidfd_getfd` to the inject rules and, under
   `balistid-kernel`, module, kexec and eBPF syscalls (`bpf` of pid 1 left out: systemd attaches cgroup programs at
   every unit start) and root's mount syscalls (`euid=0`: a sandbox mounts hundreds of times in its own namespace).
   `balistid-uring` records `io_uring_setup`, `io_uring_register` and the ring's path and `fallocate` ops.
2. Trees: `/etc/audit`, `/etc/systemd`, `/etc/laurel`, `/usr/local/lib/balistid` (`balistid-config`),
   `/var/log/journal` (`balistid-logs`), `/var/lib/balistid` (`balistid-state`), and any call on journald's binary.
   Each tree records `perm=wa`, and for b64 and b32 `open` and `openat` with `O_CREAT|O_TRUNC` (perm reads only the
   access mode) and `openat2` (pid 1's left out: systemd opens O_PATH). A test holds every tree to this set.
3. Left out of the trees, by program: the ledger (about 4 records a second in the range), the relay and the runner,
   static binaries, so a preload cannot borrow them, whose units write only their own directory (ProtectSystem=
   strict); a never rule by directory fails to load while the directory does not exist yet. journald and the
   collector are left out nowhere: in the range they made 0 and 3 records in 42 s, as their writes go through file
   descriptors, which the rules do not see. A test holds the left-out programs to confined units writing our state.
4. The range self-test's fact `tracks`: the guest, as root without a loginuid, creates, truncates read-only and
   removes a file in each tree, calls each syscall of point 1 with arguments the kernel refuses, and `modprobe`
   loads and removes `dummy`. A part is `yes` only for x86-64 records under its key with the guest's pid (modprobe:
   its own), the number, the outcome and for the truncate `O_TRUNC`. `quiet` fails on a left-out program's record in
   its own directory, bpf or openat2 of pid 1, a line that is no JSON object or a record without the fields judged.
5. The pin of ADR 0059 is renewed from the self-test's `audit_rules`; the collector names `adr-0004-v3`.

## Alternatives considered

- `auid!=unset`, or `exe` with `ppid=1`: root forges both (`systemd-run`, an orphan).
- No exemption at all: the ledger alone stored about 4 records a second in the range, forever.
- `--loginuid-immutable`: trusts the auid, not the trees; it breaks logins in some containers. Install ADR.

## Consequences

- Residuals: root writing into a left-out program's memory (`/proc/<pid>/mem`, unrecorded) acts as it within its
  unit's confinement, and root running one outside its unit writes where its flags point (its exec is recorded); ring reads and writes (audit skips them), b32 calls and the ring's ops are loaded, not exercised; a
  module's or kexec's record is written at the syscall's exit, after a module's init and possibly too late for the
  store before `kexec -e` (T14); hard links made before v3; `/etc/balistid` until the install creates it first.
- `dir=` trees must exist at boot (install ADR). R10 needs the rate trials on a host without steal (ADR 0057), the
  collector's and the runner children's rates measured at the install.
- Revert: a pull request restoring rules v2 and its pin; the fact goes with it.
