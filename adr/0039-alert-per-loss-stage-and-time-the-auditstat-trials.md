# 0039 — Alert per loss stage and time the auditstat trials

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-31
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The Pi folds every loss stage into one `loss` alert and most UNKNOWN reasons into a one-off `unknown`
(internal/watch/verify.go:195-230, alarm.go:30), so a trial cannot tell which stage or cause fired, and the standing
UNKNOWN of a dispatcher overflow (ADR 0038 reason 9) alerts once. The range sink records only tags of a-z, at most
16 bytes (cmd/balistid-range-guest/ntfy.go:84-89). `loss_alarm_s` runs from the injected loss to the phone within
120 s, 55 s of them for delivery (ADR 0036). The queue trial is INVALID: the dispatcher overflows before the
collector's 64 MiB queue fills. auditd writes its state file every 5 s, so a flip is seen up to 5 s late.

## Decision

1. Keys per stage replace `loss`: `losscap`, `lossqueue`, `lossframing`, `lossstore`, `lossshutdown`, `losskernel`,
   `lossdispatcher`, and `lossunstored` for health with unstored records; `truncated` and `logcap` stay. Health
   reason 9 is a condition under `lossdispatcher`, alerted again every 6 h while it holds (ADR 0031 point 6). Pis
   that decode stages 7-8 and reasons 8-10 are installed before hosts that emit them (ADR 0027 point 6).
2. `balistid-collector -queue-bytes` only lowers the 64 MiB queue, to at least one largest record. Only the range
   sets it, so Laurel's real stream fills a small queue under a frozen store before the dispatcher overflows.
3. A trial counts only the alert of its cause: its stage's key, or `unknown` when the ledger shows UNKNOWN with the
   trial's reason and no other reason within its window.
4. A trial's clock starts at the latest moment the guest can show came before the loss: the end of the injection for
   queue, filesystem and store (ADR 0036); its last read of `lost` before the rise (root, every 100 ms); for the flag,
   the mtime of the last state file that read no, as the guest never signals auditd. A pass is its key at the sink
   within 65 s of that, so detection, push and 55 s of delivery stay within the 120 s from the loss.
5. `loss_alarm_s`, 10 trials each: kernel loss transient (auditd stopped, then resumed: its key, then OK within 65 s
   of the resume) and sustained (auditd kept stopped; `lost` rises only after the 60 s backlog wait), and dispatcher
   overflow, INVALID when the flag reads yes before injection. Four trials kill auditd for systemd to restart it,
   passing on `unknown` with reason 10. The control without injection must not alert.

## Alternatives considered

- Hyphenated keys (`loss-kernel`): the sink refuses them, and widening its allowlist changes a gate for a name. One
  `loss` key with the stage in the text: the sink keeps tags, not bodies. A loss-queue writer as `_laurel`: about
  150 lines, and stopping Laurel overflows the dispatcher the trial must not touch.
- The clock from the guest's first sight of the flag: up to 5 s outside the window (5 + 65 + 55 > 120). The guest
  signalling auditd for a fresh state: it would change the delay it measures.

## Consequences

- Amends ADR 0031 points 3 and 6 (keys, the dispatcher condition), ADR 0036 point 4 and the `loss_alarm_s` method.
  Judges move from `loss` to one key, so a check fires less often: its review weighs that (ENGINEERING.md).
- Residuals: delivery to the phone waits for L12; the clock for the flag can start up to 5 s early, which only
  makes a trial stricter.
- Tests: a stage-2 entry raises `lossqueue` and no other key; unstored records raise `lossunstored`; reason 9
  alerts again after 6 h and clears with the flag; the queue judge refuses a `lossstore` post and the store judge an
  `unknown` with reason 8; each clock's MISS at 65.1 s; no deploy unit carries `-queue-bytes`.
