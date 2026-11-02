# 0045 — Time the kernel's lost by its own log

- Status: proposed (accepted when merged)
- Date: 2026-11-02
- Decided-by: claude/opus-5.5 (delegated by alex, 2026-11-02)
- Agent: claude/opus-5.5
- Amends ADR 0039 point 4

## Context

ADR 0039 point 4 brackets the kernel's loss by the guest's `AUDIT_GET` every 100 ms. On GitHub's KVM both kernel
shapes came out INVALID with a 19.9 s bracket (range-trial runs 41367364452, 41367364984): `audit_receive`
(kernel/audit.c) sleeps the sender of any audit request for up to `backlog_wait_time` (60 s here) while the backlog
is over its limit, and the backlog is full before lost can rise, so no poll answers sooner. The kernel logs each lost
record itself: with `-r 0` (deploy/audit/balistid.rules) `audit_log_lost` prints `audit_lost=N` through printk,
stamped by the kernel when it counts.

## Decision

1. The kernel's bracket is the printk timestamp of `audit_lost=N` for the first N above the count read before auditd
   was stopped, read from `/dev/kmsg` without blocking. A count above N+1 first, or one before the guest's first
   mark, makes the run INVALID.
2. Two marks the guest writes to `/dev/kmsg`, before the stop and after the rise, tie the kernel's clock to uptime:
   each bounds the offset by the uptime read just before and just after its write, and the bracket takes the widest
   offset both allow.
3. Nothing else of ADR 0039 changes: the 65 s rules, the shapes, the dispatcher's bracket by the state file.

## Alternatives considered

- Many pollers, each on its own socket, staggered: about 200 threads for 100 ms under a 20 s sleep, and each still
  sleeps the kernel's backlog wait.
- A shorter `backlog_wait_time` in the range: it changes the system the trial measures.

## Consequences

- `balistid-auditstat` sleeps the same way while the backlog is full, so its report ages and the collector names
  reason 8 (ADR 0038 point 4) during a kernel loss; the trials measure the alert with that in place.
- printk's rate limit could drop the first `audit_lost` line; that run is INVALID, never a false pass.
- Tests: the first count after the mark is the rise, a skipped count or one before the mark is refused, each mark
  bounds the bracket, the record parser is fuzzed.
