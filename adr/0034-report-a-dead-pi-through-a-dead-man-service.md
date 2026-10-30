# 0034 — Report a dead Pi, or one whose alarms stop, through a dead-man service

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

When the Pi dies, nothing alarms: its daily message stops, and nobody is told that it stopped (T27, ADR 0006
Consequences, ADR 0031 Consequences). The same holds when the Pi lives but its pushes fail: ntfy is down, or it
refuses the Pi's token. `Pusher` retries a failed push forever (`internal/watch/push.go`, backoff up to 5 min), so
nothing ever reports the failure. Silencing on purpose is another threat: root on the host reaches the Pi's LAN
(ADR 0032) and could drop exactly the Pi's alarms, and an agent at the maintainer's uid may reach the mail or the
account that a dead-man service alerts through: that is floor 3. ntfy.sh accepts 250 messages a day.

## Decision

1. T27 covers failure (A6): the Pi dies or loses its uplink, `balistid-pi` stops, ntfy is down or refuses the
   Pi's token. Silencing by A1 or A2 stays a residual, and T27's actor stays A6.
2. `balistid-pi` pings an outside dead-man service every 2 minutes, an HTTPS GET with no body to a URL whose
   random UUID is the only secret: a systemd credential on the Pi, never on the host, in argv, environment or
   logs. It pings success only while its watch loop ran in the last minute and no push or probe failed. When no
   push was accepted for 30 minutes it publishes a probe, a POST with the push's token to a topic on the same
   ntfy server that no phone subscribes: at most 48 a day, inside ntfy.sh's 250. A push or probe not accepted
   within 3 minutes latches the Pi unhealthy: every slot sends the service's failure signal instead of a ping,
   until a push or probe is accepted again and a failure signal was acknowledged. A ping or failure signal the
   service refuses (a mistyped URL answers 404) alerts through ntfy.
3. The service alerts through a channel that is not ntfy (mail or SMS), when a failure signal arrives or a ping is
   10 minutes late: at most 12 minutes after the last ping, which leaves 3 minutes for delivery within
   `dead_site_alarm_s` (900). ntfy refusing the token is seen by the next probe, within 30 minutes, so it alarms
   within `push_refused_alarm_s` (2700). The default is healthchecks.io (period 2 min, grace 10 min); anything with
   the same contract works, nothing on the Pi, which dies with it. L12 builds it.
4. How long the install takes and how many hands-on steps it needs is set by the ADR that brings
   `balistid-install` (9.5): the steps cannot be counted before the installer exists. That ADR also says how the
   Pi's secrets are made on the Pi and how a test shows none passed through the host.

## Alternatives considered

- A VPS or a public witness as the site: the provider, or whoever holds the admin path, can roll back the witness
  and keep pinging (T12, T27); the public network has no production list (witness-network.org, 2026-10-30).
- A ping from a separate timer on the Pi: it stays green while `balistid-pi` or its pushes are dead. A probe
  that only reads (`GET /<topic>/auth`): it passes when write access is gone. A probe every 2 minutes: 720 a day
  over ntfy.sh's quota, so a healthy Pi would latch daily. A probe on the alert topic: it would reach the phone.
- A dead-man check on the Pi itself: it dies with the Pi. The daily alive message alone: noticing it is missing
  is up to a person.

## Consequences

- Amends ADR 0006 Consequences, ADR 0031 point 6 and Consequences: a dead or mute Pi alarms within the two
  limits; a push or probe not accepted within 3 minutes latches it unhealthy. T27 moves to partial.
- Residuals: A2 on the Pi's path or A1 in the alert mail or the service account can silence both channels, and
  write access revoked on the alert topic alone is not seen by the probe (a deliberate act, A1 or A2);
  ntfy accepting a push and the service sending mail do not prove the phone shows them, which only the daily
  message and the install's test alarms show; whoever holds the ping URL can keep a dead Pi looking alive; the
  service learns the Pi's address and ping times, and the Pi needs outbound HTTPS to it (T16).
- Tests (L12): the two metrics' trials; one ping dropped alerts nothing; a 404 ping URL alerts through ntfy; a
  marker URL appears in no journal line, argv or environment on the Pi.
