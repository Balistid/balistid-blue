# 0059 — Check the loaded rules by digest and time sensor_down_s

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-04
- Decided-by: alex (2026-11-04: the plan of issue #198); claude/opus-5.5 the bounds and the trial shapes
- Agent: claude/opus-5.5
- Closes issue #198; amends ADR 0004 point 4, ADR 0007's table, ADR 0038 points 1, 4 and 5, ADR 0027 point 6.

## Context

ADR 0004 point 4 asks for an event when the loaded audit rules differ from the repository; ADR 0038 point 5 left it
open, as `AUDIT_LIST_RULES` returns variable records, a parser in the one privileged process. `sensor_down_s` (10 s)
had no trial. The kernel answers the list with one `AUDIT_LIST_RULES` message per rule, `NLM_F_MULTI`, then an
empty `NLMSG_DONE`, each its own datagram from port 0 (kernel/audit.c, auditfilter.c); it needs `CAP_AUDIT_CONTROL`
and works under `-e 2`. Laurel's end closes its socket (`laurel-disconnected` on the next 250 ms tick); auditd's
ends Laurel and leaves `pid` 0 in auditstat's report (`auditd-down`); auditd's unit refuses a manual stop.

## Decision

1. auditstat sends `AUDIT_GET`, takes its reply, then sends `AUDIT_LIST_RULES` with its own seq; never both in flight.
   It checks each datagram's framing only: from port 0, header port 0, the header's length the datagram's, the seq,
   `AUDIT_LIST_RULES` with exactly `NLM_F_MULTI` or a 16-byte `NLMSG_DONE` with it; at most 64 KiB a message, 1024
   messages, 1 MiB. It reads no field of `audit_rule_data`. The digest is SHA-256 over a label, then each payload's
   big-endian u32 length and bytes, in order. Anything else is no report, as today (stale after 15 s).
2. Report v2: label `balistid/auditstat/v2`, seq, status, the rule count and the digest, fixed size.
3. The collector pins the shipped rules in Go: count, digest, `-f`, `-r`, `-b`, `--backlog_wait_time`, and the
   SHA-256 of `deploy/audit/balistid.rules`, which a test ties to the file. A fresh report that differs in any of them
   is health reason 11 `UNKNOWN rules-differ`, at once, without the 15 s wait: it is evidence, not an absence. Order
   9, 11, 10, 8. Until the collector has read a first report, health is 8 at once: an OK then would say nothing of
   the rules (R6). The Pi alerts on 11 at once. The range's self-test reads the pin against the real kernel.
4. `sensor-down`, 21 runs: from health OK, SIGKILL Laurel through a pidfd; once healthy again, SIGTERM auditd, hold
   20 s, start it; once healthy, `auditctl -e 0`. A stage is timed from a stamp right before its signal to the first
   health record not OK, which must be a state its failure causes: Laurel `laurel-disconnected` or `canary-pending`,
   auditd those or `auditd-down`; another state first, none, or over 10 s is a MISS. Audit enabled other than 2 after
   `-e 0`, or no CONFIG_CHANGE refusing it in the store, is a MISS. A stage not proven (no exit, the floor not healthy
   again, another collector process) or health not OK at its stamp is INVALID. A MISS outranks an INVALID.
5. Rules trials, 8 boots each: an image-only drop-in of `audit-rules.service` writes a last rules file before `-e 2`
   (a rule added, a b32 memfd rule removed, `-b` changed); proven by the guest as root. Health never OK and
   `rules-differ` within 10 s of the first stored canary pass.

## Alternatives considered

- Parse `audit_rule_data` and compare fields: the parser ADR 0038 kept out of the privileged process; a digest
  needs only the framing.
- Compile `balistid.rules` to the kernel's form in Go: auditctl's tables and the kernel's class expansion again (R9).
- Record the digest at install: it trusts the boot it checks, the one a changed rules file would load.
- A unit flag for the pin: a third place, beside the binary and the rules, to drift between commits (R1).

## Consequences

- A kernel or audit upgrade that changes the bytes reads `rules-differ` until the pin is renewed from a range run:
  fail-closed, once per upgrade (T26). The range runs linux 7.2.8 and audit 4.2.1; the host its own kernel.
- Other files in the host's `/etc/audit/rules.d`, which augenrules merges, read `rules-differ`: the install ADR
  decides who owns that directory before 9.5's install.
- Reason 11 holds until reboot and hides 10 and 8 while it does. The dispatcher's overflow still comes first.
- Revert: a pull request removing this file, the trials and report v2, and restoring ADR 0038 point 5.
