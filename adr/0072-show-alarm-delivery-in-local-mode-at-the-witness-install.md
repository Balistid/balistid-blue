# 0072 — Show alarm delivery in local mode at the witness install

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-09
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-09)
- Agent: claude/opus-5.5
- Closes issue #204; amends ADR 0036 point 1 and ADR 0043's local-mode metrics, and the methods of
  `loss_alarm_s`, `silence_alarm_s`, `dead_site_alarm_s` and `push_refused_alarm_s` in `acceptance/0.toml`.

## Context

`loss_alarm_s` and `silence_alarm_s` pass only once L12 shows the range's ntfy sink to the phone within 55 s
(ADR 0036 point 1), and `dead_site_alarm_s` and `push_refused_alarm_s` run on the Pi (L12). ADR 0040 moved L12 after
9.5. In local mode, the 9.5 default, `balistid-pi` runs on the host and sends every alert (ADR 0043 points 1, 2);
loss and a stalled ledger alert at the host's ntfy, while power-off silence and both dead-man metrics need the
opt-in dead-man, which no code builds yet (L12). ADR 0068 (#270) installs the recorder first and the `witness`
component, which brings `balistid-pi` and the ntfy token, after it; the recorder's 7 days run before `witness`
(ADR 0068 point 6), when the host sends no alert. Every loss and silence alert posts at priority 5
(`internal/watch/push.go`), the priority ntfy delivers to a phone at once; one key posts at most once a minute.

## Decision

1. No alarm metric gates the recorder's 7 days on the host: with no `balistid-pi` and no token nothing can alert.
2. In local mode the leg from ntfy to the phone is shown at the `witness` install, on the maintainer's host and
   phone: five posts by hand to the install's topic with its token at priority 5, at least a minute apart, each
   timed by the maintainer from the post to the notification on the phone and seen within 55 s. Human timing is
   coarse against 55 s, enough to tell a working leg from one that is not. At most two posts may be repeated, once
   each, for a phone that was off; a third repeat or an alert not seen is a MISS. Each cause's time to the sink
   stays the range's (ADR 0036, 0039).
3. With point 2 and the range's trials, `loss_alarm_s` and a killed ledger's `silence_alarm_s` pass for local mode.
4. A WireGuard cut, power-off silence, `dead_site_alarm_s` and `push_refused_alarm_s` do not apply in local mode
   without the dead-man (ADR 0043), so they do not gate 9.5; the higher level and the dead-man's install keep them.
   Until the dead-man exists, nothing alarms in local mode when the host dies.

## Alternatives considered

- Show delivery from the range now: the range's sink is not ntfy, and a real topic in CI would put a phone's
  token in CI.
- Time the posts from `balistid-pi`'s log: it logs failed posts only, not the time of one that went out.
- Wait for L12 for every alarm: 9.5's default would ship with no alert ever shown to reach a phone.

## Consequences

- The `witness` pull request carries the five-post check in its plan; its result goes to that pull request and
  STATUS.md.
- Until `witness` the host's only signal is `balistid status` and the collector's health records, which
  `healthy_ok` counts.
- Revert: a pull request removing this file and the four methods' local-mode clauses.
