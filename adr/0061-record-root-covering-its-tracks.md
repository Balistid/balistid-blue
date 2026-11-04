# 0061 — Record root covering its tracks

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: alex (2026-11-04: issue #241 and ADR 0060's rule); claude/opus-5.5 the rules and the self-test
- Agent: claude/opus-5.5
- Closes issue #241; amends ADR 0004 point 2 (rules version `adr-0004-v3`) and the T3 part of ADR 0060.

## Context

Rules v2 record execs, ptrace, `process_vm_writev`, `memfd_create` and the canary. Root that loads a module or an
eBPF program, kexecs, mounts over a tree, or empties a journal file, an audit, Laurel or unit config, our programs
or our state leaves no record unless it execs a tool; a payload in memory leaves none (T3, T5, T14). The issue
proposed watches with `auid!=unset`: root escapes them through anything systemd starts (`systemd-run`, a timer).

## Decision

1. Rules v3 start with `-c`: a line that cannot load (a tree missing at boot) is skipped, `-e 2` still loads and the
   rule list reads `rules-differ` (ADR 0059). They add `pidfd_getfd` to the inject rules and, under
   `balistid-kernel`, module, kexec, eBPF and mount syscalls, with `bpf` of pid 1 left out (systemd attaches cgroup
   programs at every unit start). `balistid-uring` records `io_uring_setup`, `io_uring_register` and, in the
   io_uring filter, the file ops (open, unlink, rename, link, symlink, mkdir, truncate) of a ring root re-enabled.
2. Writes and removals (`perm=wa`) under `/etc/audit`, `/etc/systemd`, `/etc/laurel`, `/usr/local/lib/balistid` and
   journald's binary (`balistid-config`), `/var/log/journal` (`balistid-logs`) and `/var/lib/balistid`
   (`balistid-state`) are recorded for every process but a tree's owner as systemd starts it (`exe=` and `ppid=1`
   in a `never` rule just before): journald for the journal; the collector, ledger, relay and runner for our state.
   `perm=wa` reads only an open's access mode, so opens with `O_CREAT` or `O_TRUNC` have their own rules per tree,
   and `openat2`, whose flags no rule can read, is recorded whole there but for pid 1's. 32-bit programs get one
   wider rule per tree. A test holds the left-out programs to the units with state there.
3. The range self-test's fact `tracks`: the guest, as root without a loginuid, creates, truncates read-only and
   removes a file with a random name in each tree, calls each syscall of point 1 with arguments the kernel refuses,
   and `modprobe` loads and removes `dummy`. A part is `yes` only for a record under its key with the guest's pid
   (modprobe's: its own pid), the syscall's number and, for a file, CREATE, a truncating `openat` and DELETE.
   `quiet` fails on a record under these keys from a left-out program, bpf of pid 1, or a line it cannot parse.
4. The pin of ADR 0059 is renewed from the self-test's `audit_rules`; the collector names `adr-0004-v3`.

## Alternatives considered

- `auid!=unset` (the issue): fewer rules, but `systemd-run` writes unrecorded; only its exec shows.
- `--loginuid-immutable`: trusts the auid, not the watches; it breaks logins in some containers. Install ADR.
- Every `bpf` call, every `openat2`: systemd's unit starts and reads would dominate the store.

## Consequences

- Residuals: a left-out program as systemd starts it, or one root steers (a drop-in under `/run` or `/usr/lib`, a
  rotate that makes journald delete), writes unrecorded (T1, T18); a syscall touching two trees obeys the first
  rule; hard links made before v3; a module's or kexec's record is written at the syscall's exit, after a module's
  init ran and possibly too late for the store before `kexec -e` (T14); io_uring file ops are loaded, not exercised.
- `dir=` trees must exist at boot (install ADR); every open checks the trees' rules, so R10 needs the rate trials
  on a host without steal (ADR 0057), not GitHub's runner. The runner's child processes writing objects are not
  left out: their rate is measured at the install.
- Revert: a pull request restoring rules v2 and its pin; the fact goes with it.
