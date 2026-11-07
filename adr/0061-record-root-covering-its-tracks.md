# 0061 — Record root covering its tracks

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: jvc0n (2026-11-04: issue #241 and ADR 0060's rule); claude/opus-5.5 the rules and the self-test
- Agent: claude/opus-5.5
- Closes issue #241; amends ADR 0004 point 2 (rules version `adr-0004-v3`) and the T3 part of ADR 0060.

## Context

Rules v2 record execs, ptrace, `process_vm_writev`, `memfd_create` and the canary. Root that loads a module or an
eBPF program, kexecs, mounts over a tree, or empties a journal file, an audit, Laurel or unit config, our programs
or our state leaves no record unless it execs a tool; a payload in memory leaves none (T3, T5, T14). Review rounds
1-3 of #250 showed which ways around a first design stay open; the decision keeps those that leave no record named.

## Decision

1. Rules v3 start with `-c`: a line that cannot load (a tree missing at boot) is skipped, `-e 2` still loads and the
   rule list reads `rules-differ` (ADR 0059). They add `pidfd_getfd` and `prctl` that borrows an exe or keeps
   capabilities across a uid change (`PR_SET_MM` with EXE_FILE or MAP, `PR_SET_SECUREBITS`, `PR_SET_KEEPCAPS`) to the
   inject rules; under
   `balistid-kernel`, module, kexec and eBPF syscalls (`bpf` of pid 1 left out: systemd attaches cgroup programs at
   every unit start) and mounts while the real, effective or saved uid is 0 (a sandbox mounts hundreds of times in
   its own namespace; leaving all three keeps no capability but by that prctl or an exec of a binary with file
   capabilities, whose exec is recorded); under `balistid-handle`, every
   `open_by_handle_at`, as it carries no path a tree sees and a read-only one reopens for writing through /proc. `balistid-uring`
   records `io_uring_setup`, `io_uring_register` and the ring's path and `fallocate` ops.
2. Trees: `/etc/audit`, `/etc/systemd`, `/etc/laurel`, `/usr/local/lib/balistid` (`balistid-config`),
   `/var/log/journal` (`balistid-logs`), `/var/lib/balistid` (`balistid-state`), and any call on the binaries of
   journald, auditd and Laurel.
   Each tree records `perm=wa`, and for b64 and b32 `open` and `openat` with `O_CREAT|O_TRUNC` (perm reads only the
   access mode) and `openat2` (pid 1's left out: systemd opens O_PATH). A test holds every tree to this set.
3. Left out of the trees, by program: the ledger (about 4 records a second in the range), the relay and the runner,
   static binaries, so a preload cannot borrow them, whose units write only their own directory (ProtectSystem=
   strict); a never rule by directory fails to load while the directory does not exist yet. journald and the
   collector are left out nowhere: in the range they made 0 and 3 records in 42 s, as their writes go through file
   descriptors, which the rules do not see. A test holds the left-out programs to confined units writing our state.
4. The range self-test's fact `tracks`: the guest, as root without a loginuid, creates, truncates read-only and
   removes a file in each tree (the truncate by `openat` and by `openat2`), opens one by its handle read-only and
   truncating, mounts from two children root only by real or saved uid, calls each syscall of point 1 refused, and
   `modprobe` loads and removes `dummy`. A part is `yes` only for x86-64 records under its key with the guest's pid (modprobe:
   its own), the number, the outcome, a prctl's option and an `openat`'s `O_TRUNC`. `quiet` fails on a left-out
   program's record, bpf or openat2 of pid 1, a line or SYSCALL that is no JSON object, and a record of its keys
   whose arch, number, pid, exe, outcome or four hex arguments are missing or odd, or a URINGOP item without its op.
5. The pin of ADR 0059 is renewed from the self-test's `audit_rules`; the collector names `adr-0004-v3`.

## Alternatives considered

- `auid!=unset`, `exe` with `ppid=1`: root forges both (`systemd-run`, an orphan); `--loginuid-immutable` trusts
  the auid, not the trees, and breaks logins in some containers (install ADR).

## Consequences

- Residuals: root writing a process's memory (`/proc/<pid>/mem`) acts as it, through its fds too (`ftruncate`
  names no tree); a left-out program run outside its unit writes where its flags point (its exec is recorded); raw
  block writes, `chattr` by ioctl, ring reads and writes go unrecorded; a module's or kexec's record comes at exit,
  after the init, maybe too late before `kexec -e` (T14); hard links made before v3; `/etc/balistid` until the
  install makes it first; b64 `open`, b32 and the ring's ops are loaded, not exercised.
- `dir=` trees must exist at boot (install ADR); R10's rates need a host without steal (ADR 0057), at the install.
- Revert: a pull request restoring rules v2 and its pin; the fact goes with it.
