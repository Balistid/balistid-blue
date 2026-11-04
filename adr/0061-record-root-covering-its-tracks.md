# 0061 — Record root covering its tracks

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: alex (2026-11-04: issue #241 and ADR 0060's rule); claude/opus-5.5 the rules and the self-test
- Agent: claude/opus-5.5
- Closes issue #241; amends ADR 0004 point 2 (rules version `adr-0004-v3`) and the T3 part of ADR 0060.

## Context

`deploy/audit/balistid.rules` v2 records execs, ptrace, `process_vm_writev`, `memfd_create` and the canary. Root
that loads a kernel module or an eBPF program, swaps the kernel with kexec, or removes a journal file, an audit or
unit config or our own state leaves no record unless it execs a tool; a payload in memory leaves none (T5, T14).
io_uring is disabled, but root can re-enable it (T3). The issue proposed watches with `auid!=unset`: root escapes
them through any process systemd starts (`systemd-run`, a timer), which runs with the loginuid unset.

## Decision

1. Rules v3 add, after the canary's watch: `init_module`, `finit_module`, `delete_module`, `kexec_load`,
   `kexec_file_load` (b64 only, i386 has none) and `bpf` under key `balistid-kernel`, and `io_uring_setup` and
   `io_uring_register` under `balistid-uring`, each for b64 and b32. A `never` rule before them drops `bpf` of pid
   1 alone: systemd attaches cgroup programs at every unit start.
2. Writes and removals (`perm=wa`) under `/var/log/journal` (`balistid-logs`), `/etc/audit` and `/etc/systemd`
   (`balistid-config`) and `/var/lib/balistid` (`balistid-state`) are recorded for every process but the program
   that owns the tree, left out by its executable in a `never` rule just before: systemd-journald for the journal;
   the collector, ledger, relay and runner for our state. The exit filter takes the first rule that matches, so the
   canary's watch stays ahead of them and the collector's canary is still recorded. A daemon that writes there and
   is not left out is a rate the rate trials measure (R10); a test holds the list to the units with state there.
3. The range self-test's fact `tracks`: the guest, as root without a loginuid, writes and removes a file with a
   random name under each tree and calls each syscall of point 1 with arguments the kernel refuses; `modprobe` loads
   and removes the `dummy` module. Each part is `yes` only for a record under its key with the guest's pid (for
   modprobe, its child's syscall with the guest as parent), the syscall's number and, for a file, its name as
   CREATE and DELETE. `quiet` is `yes` when no record under these keys comes from a left-out program or from bpf of
   pid 1.
4. The pin of ADR 0059 is renewed from the self-test's `audit_rules`; the collector names `adr-0004-v3`.

## Alternatives considered

- `auid!=unset` (the issue): fewer rules, but `systemd-run` writes unrecorded; only its exec shows.
- `--loginuid-immutable`: makes the auid trustworthy, not the watches; it breaks logins in some containers on the
  maintainer's host. Left to the install ADR.
- Recording every `bpf` call: systemd's unit starts would dominate the store.

## Consequences

- T3: a re-enabled io_uring is recorded when set up; its ops are not. T14: module, kexec and eBPF loads are
  recorded at the syscall's exit, after a module's init ran, so a module that blinds audit in its init leaves only
  the exec that loaded it (open, T14). A process running as a left-out program writes unrecorded (T1, T18).
- Every file write under the four trees costs a tree lookup per syscall; the rate trials re-measure it.
- Tests: the self-test's `tracks` against fixtures for each way to a false `yes` (another pid, another key, no
  DELETE, a left-out program); the pin test; the rule list's left-out programs against the units.
- Revert: a pull request restoring rules v2 and its pin; the fact goes with it.
