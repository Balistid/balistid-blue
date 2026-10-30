# 0034 — Make the witness site pluggable; a heartbeat reports a dead site

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 point 2 puts the one witness on the maintainer's Raspberry Pi, and ADR 0031 point 1 has `balistid-pi`
trust only the litewitness on its own machine. A user without a Pi has no path, and nothing says what may stand in
for it. When the Pi dies, nothing alarms: its daily message stops, and nobody is told that it stopped (T27). The
public witness network (witness-network.org/participate, read 2026-10-30) keeps testing and staging lists only,
production is "not available yet", each witness rate-limits a log by its add-checkpoint rate, and maintainers
approve a log by email. How long the install takes and how many steps it needs is not an acceptance number.

## Decision

1. A witness site is one machine the maintainer controls that runs litewitness and `balistid-pi` together: the Pi
   (the default) or a VPS. The relay submits to exactly one site. Its endpoint, public key and witness key come
   from the install (`/etc/balistid/net.env`, ADR 0032 point 3), never from code. The table, the tunnel and the
   relay's allowlist of ADR 0032 are the same for every site; for a VPS the endpoint is a public IPv4 literal and
   WireGuard crosses the internet. Alarms come only from a site, since only there does the watcher see what its
   own witness cosigned.
2. Public witnesses are never a site: they raise no alarm and run best effort. A second cosignature from them
   would make a fork visible beyond the site, but floor 0 does not build it: with no production list, a checkpoint
   every few seconds and each checkpoint's size telling them the host's activity rate, the cost is higher than
   the gain. A later ADR adds it, at most hourly and never in the path to the site, once a production list exists.
3. Dead site (T27): every site pings an outside dead-man service every 5 minutes, an HTTPS GET with no body to a
   URL whose random UUID is the only secret (a systemd credential, 0600, never argv, environment or logs). The
   service alerts the maintainer's phone through its own channel once a ping is 10 minutes late, so a dead site is
   reported within 15 minutes. The default is healthchecks.io (`hc-ping.com/<uuid>`); anything with the same
   contract works, but nothing on the site itself, which dies with it. A failed ping is logged and retried, and
   never alarms on its own. L12 builds it.
4. The install's ease is acceptance (R3, decided here): `install_minutes` and `install_manual_steps`, a host and a
   Pi site from released artifacts to the first test alarm on the phone, measured by the maintainer with
   `balistid-install` (9.5). A VPS site is measured too, as advice.

## Alternatives considered

- Public witnesses alone: no watcher anywhere raises an alarm, and there is no production list to rely on.
- `balistid-pi` reading a public witness's cosignature from the relay: the host would choose what the watcher sees
  and when, so silence and withholding would hide (ADR 0031, alternatives).
- A dead-man check on the site itself, such as Uptime Kuma on the Pi: it dies with the Pi. A second Pi that watches
  the first: another device to keep alive, for the same signal a service gives.
- The daily alive message as the signal: noticing a missing message is up to a person.

## Consequences

- Amends ADR 0006 point 2 (the Pi becomes the default site) and ADR 0031 Consequences (a dead Pi is reported by
  the heartbeat, no longer only when someone misses its daily message). T27 moves from gap to designed.
- `acceptance/0.toml` gets `install_minutes` (10) and `install_manual_steps` (5).
- Residuals: the provider of a VPS site is root on the witness and the watcher, so it can roll back the witness's
  state or silence alarms (A2 on the site); the dead-man service learns the site's address and ping times; whoever
  holds the ping URL can keep a dead site looking alive; while the service is down, a dead site is found only by
  its missing daily message.
- 9.5 precondition: the maintainer creates the check and its phone channel, and the install's test alarm proves
  that the channel works.
