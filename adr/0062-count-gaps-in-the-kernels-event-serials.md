# 0062 — Count gaps in the kernel's event serials

- Status: proposed
- Date: 2026-11-07
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-02)
- Agent: claude/opus-5.5
- Answers issue #245 (ADR 0060's floor-0 row for T4 and T25); adds loss stage 9 to ADR 0027 point 6 and its key to
  ADR 0039 point 1.

## Context

Two losses are counted nowhere: the plugin queue's drops after its first (auditd keeps a flag, ADR 0038; T4) and
what a dead auditd or Laurel never hands on (ADR 0016 point 5; T25). The kernel numbers events with one global
counter per boot (`audit_serial()`, kernel/audit.c), taken in `audit_log_start` after the backlog and allocation
checks, so those drops take no serial; records dropped once stamped (rate limit, kauditd hold and retry queue
overflow) do take one, and `lost` counts them. A syscall's records share the serial its first record takes.

PR #256 (9f08f97) shows the serials in the range. On GitHub's KVM: rate-sustained, rate-burst, rate-control-drop and
loss-control-none stored 1 063 565 events with no serial missing; loss-dispatcher-1 left one gap of 54, loss-auditd-
crash-1 one of 99, loss-queue-1 one of 8, each with `lost` 0; loss-kernel-sustained-1 left 87 546 with `lost` at
262 920 (runs in #256). Serial 1, the kernel's `state=initialized` record from before auditd, never reached the store
in any run; where it stops is not known. The scan ran over the store after the trial, not live: how late a serial
can arrive behind a higher one in the collector's stream is not measured yet.

## Decision

1. The collector reads each Laurel line's `ID` (`<sec>.<ms>:<serial>`) where the line starts, strictly, capped; a
   line without one is counted, never guessed. auditd's own events (`DAEMON_*`, auditd's numbers) are left out.
2. A serial missing between the first one received and the highest is held for `gap_hold_s`; one still missing
   then is a gap. Stage 9 `gap` loss entries carry the first missing serial and how many, bound to the seq of the
   record that closed the hold, in seq order like the other stages. The held set is a bounded list of ranges;
   past its cap the oldest range is reported at once (R5, T20).
3. The baseline survives the collector: at start it takes the serial of the last stored Laurel record of the same
   boot (the started record's `boot_id`), so bytes lost across its own restart show as a gap. A new boot, or a
   serial lower by more than 2^31 (the 32-bit counter wrapping), starts a new baseline.
4. A gap is an upper bound of events lost between the kernel's stamp and the store: it also covers losses another
   stage counts (kernel after the stamp, the collector's queue). The Pi alerts `lossgap` for every gap entry; a gap
   with no other stage's entry in its window is the uncounted loss T4 and T25 named.
5. `gap_hold_s` is set by a range measurement before code: the greatest lateness in the collector's stream over the
   rate trials, doubled. The scan of #256 gains it first.

## Alternatives considered

- Parse only in the normalizer: it reads later and from the store, so a loss would be seen after the evidence of
  it could be gone, and floor 0 would still ship T4 and T25 as accepted.
- Patch auditd to count the plugin queue: proposed upstream (linux-audit/audit-userspace#562, #563); it covers only
  the dispatcher and reaches hosts on the distribution's schedule. A count there and a gap here agree once both run.
- Subtract the kernel's `lost`: it counts records, a gap counts events, and both can rise in one window.

## Consequences

- T4 and T25 move from `upstream` and accepted to counted on floor 0, with their alarm; the THREAT_MODEL rows change
  with the code. Pis that decode stage 9 are installed before hosts that emit it (ADR 0027 point 6).
- New: a fuzz target for the ID parser; tests for hold, release, cap, restart baseline, new boot and wrap; range
  trials: loss-dispatcher and loss-auditd-crash raise `lossgap`, the controls and rate trials raise none.
- `acceptance/0.toml` gains `gap_hold_s` from the measurement of point 5, approved by the maintainer.
