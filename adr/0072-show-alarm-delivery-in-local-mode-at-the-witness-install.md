# 0072 — Show alarm delivery in local mode at the witness install

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-09
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-09)
- Agent: claude/opus-5.5
- Closes issue #204; amends the methods of `loss_alarm_s` and `silence_alarm_s` in `acceptance/0.toml`.

## Context

`loss_alarm_s` and `silence_alarm_s` pass only once L12 shows the range's ntfy sink to the phone within 55 s
(ADR 0036 point 1), and `dead_site_alarm_s` and `push_refused_alarm_s` run on the Pi (L12). ADR 0040 moved L12 after
9.5. In local mode, the 9.5 default, `balistid-pi` runs on the host and sends every alert (ADR 0043 points 1, 2);
loss and a stalled ledger alert at the host's ntfy, while power-off silence and both dead-man metrics need the
opt-in dead-man. ADR 0068 installs the recorder first and the `witness` component, which brings `balistid-pi` and
the ntfy token, after it; the 7 days of #201 run before `witness` (ADR 0068 point 6), when the host sends no alert.

## Decision

1. No alarm metric gates the recorder's 7 days on the host: with no `balistid-pi` and no token nothing can alert.
2. In local mode the leg from ntfy to the phone is shown at the `witness` install, on the maintainer's host and
   phone: five alerts that `balistid-pi` posts to the install's topic, each seen on the phone within 55 s of the post
   time in `balistid-pi`'s log. The leg does not depend on the alert's cause, so one cause shows it; each cause's
   time to the sink stays the range's (ADR 0036, 0039).
3. With point 2 and the range's trials, `loss_alarm_s` and a stalled ledger's `silence_alarm_s` pass for local mode.
4. Power-off silence, `dead_site_alarm_s` and `push_refused_alarm_s` do not gate 9.5. They stay not measured, named
   "local mode: dead-man opt-in (ADR 0043)", until L12 or the dead-man's own install; the higher level keeps them.

## Alternatives considered

- Show delivery from the range now: the range's sink is not ntfy, and a real topic in CI would put a phone's
  token in CI.
- Gate the 7 days on alarms: nothing on the host can alert before `witness`.
- Wait for L12 for every alarm: 9.5's default would ship with no alert ever shown to reach a phone.

## Consequences

- The `witness` pull request carries the five-alert check in its plan; its result goes to that pull request and STATUS.md.
- A phone that is off or silenced during the check is a retry, not a pass: each alert must be seen.
- Until `witness` the host's only signal is `balistid status` and the collector's health records, which
  `healthy_ok` counts.
- Revert: a pull request removing this file and the two methods' local-mode clause.
