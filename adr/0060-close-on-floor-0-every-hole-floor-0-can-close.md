# 0060 — Close on floor 0 every hole floor 0 can close

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: alex (2026-11-04: a hole floor 0 can close is closed on floor 0, however long it takes); claude/opus-5.5
  the map
- Agent: claude/opus-5.5
- Amends ADR 0051 points 1 and 3.

## Context

ADR 0051 accepted 24 of the 28 `partial` and `gap` rows for floor 0, most as root on the host (A2) or a development
tool's DoS. The maintainer then set a stricter rule: acceptance is only for a hole no code of floor 0 can close. Some
accepted rows fail that test: the fix needs neither the Pi nor detection, only our units, rules, packaging or CI.

## Decision

1. A hole is accepted only when closing it needs the off-host witness (L12), detection or response (floor 1), or a
   change outside our code (kernel, auditd, Laurel, hardware); the row then names that floor or upstream. Everything
   else closes on floor 0: at 9.5 if it touches the install, else before ADR 0055's two passes.
2. The map of ADR 0051 point 1 becomes:

   | Closes at | Rows (issue or ADR) |
   |---|---|
   | 9.5 | as ADR 0051, and T2: the ledger's socket admits only the collector's group (#207 reopened); T3: rules record `io_uring_setup`, `io_uring_register` and, in the `io_uring` filter, the ops the exec rules cover, so an io_uring root re-enabled is recorded (#241); T10: the store on a filesystem of its own, btrfs refused, in the install ADR; T25's double store: Laurel with laurel#313 (dec7cf0) in `packaging/laurel` |
   | floor 0 | T4's and T25's uncounted losses: measure in the range whether gaps in the kernel's event serials count them (a backlog drop takes no serial, `lost` counts it), then decide; T29: CI builds and vets every commit of a pull request; T33: `designed` (ADR 0051's consequence); T36: GOCACHE and inodes capped; T8: `mmap` with `PROT_EXEC` and the middle of truncated argv recorded, or named as a kernel limit |
   | L12 | as ADR 0051, and T13: the window is bounded by the checkpoint interval and the Pi's silence alarm; T22: the Pi's time from an authenticated source of its own |
   | floor 1 | as ADR 0051 |
   | upstream | T4: auditd keeps only a flag for dispatcher drops, no count (ADR 0038); T18: `CAP_AUDIT_CONTROL` also resets `lost` and claims the audit pid |
   | accepted | T11's host CLI (0048); T13, T14 and T15 in local mode and beyond L12 (0040 point 3; T15's mirror is its own step, 0031); T16 (0026, 0031); T18's audit.log group (it reads records the collector holds anyway); T19 (0027, 0029, 0030); T21's flush by A2 (0032); T23 (0004); T27's channel holder (0034); T28 (0017, 0030); T31 (0009, 0011); T34 (0010); T37 (0028) |

3. Each new entry of point 2 gets an issue with its milestone (9.5, `floor-0` or L12) and a test that fails before
   the fix (R4). If the serial measurement shows gaps that are no loss, T4 and T25 stay `upstream` and accepted.
4. An `upstream` entry names the project and the change it needs; it closes when a release with that change is
   packaged here, else it stays `partial` with the upstream link.

## Alternatives considered

- Keep ADR 0051's acceptance: reaches 9.5 sooner, but ships holes our own code could close.
- Close every row before 9.5: A2's rows need the witness off the host (ADR 0040 point 3); floor 0 cannot close them.

## Consequences

- 9.5 gains four fixes (T2, T3, T10, T25's double store); floor 0 five more before its passes. The accepted row keeps
  only what the Pi, floor 1 or an upstream change can close.
- T33's status word changes in this pull request.
- Revert: a pull request removing this file; ADR 0051's map applies again and the new issues close as not planned.
