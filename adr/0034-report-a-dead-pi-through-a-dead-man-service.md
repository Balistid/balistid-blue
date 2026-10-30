# 0034 — Report a dead Pi, or one whose alarms stop, through a dead-man service

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

When the Pi dies, nothing alarms: its daily message stops, and nobody is told that it stopped (T27, ADR 0031
Consequences). The same holds when the Pi lives but its pushes do not arrive: ntfy is down, the token is revoked, or
root on the host, which reaches the Pi's LAN (ADR 0032), drops the Pi's traffic to ntfy alone. Whether something
other than the maintainer's own Pi may witness was asked too. A VPS is administered remotely, often from the very
host it watches, and its provider is root on the witness and the watcher; the public witness network
(witness-network.org/participate, read 2026-10-30) has testing and staging lists only, production "not available
yet". How long the install takes and how many hands-on steps it needs is no acceptance number yet.

## Decision

1. The site stays the maintainer's own Pi (ADR 0006). Its endpoint and keys come from the install
   (`/etc/balistid/net.env`), so a replaced Pi is configuration, not code. A VPS or a public witness is no site
   in floor 0 (Alternatives).
2. `balistid-pi` pings an outside dead-man service every 5 minutes, an HTTPS GET with no body to a URL whose random
   UUID is its only secret: a systemd credential on the Pi, 0600, never on the host, in argv, environment or logs.
   It pings only while its watch loop ran in the last minute and an authenticated request to the ntfy server it
   pushes to, with the push's token, host and path, succeeded since the last ping. A push or that request failing
   past its retries sends the service a failure instead of a ping. Alarms keep going through ntfy (ADR 0031
   point 6); the service only reports a Pi that is gone or cannot push.
3. The service alerts through a channel that is not ntfy (mail or SMS) once a ping is 10 minutes late or a failure
   arrives: `dead_site_alarm_s` at most 900. A single late ping does not alert. The default is healthchecks.io
   (`hc-ping.com/<uuid>`, period 5 min, grace 10 min); anything with the same contract works, nothing on the Pi,
   which dies with it. L12 builds it.
4. The install's ease is acceptance (R3, decided here): `install_minutes` and `install_manual_steps` for a host and a
   Pi from released artifacts, from before the check, the topic and their phone channels are set up until both test
   alarms are on the phone. No Pi secret passes through the host, whatever that costs in steps.

## Alternatives considered

- A VPS site: its provider, and whoever holds its admin path, can roll back the witness and the watcher together
  (T12) and keep pinging while silent (T27). It needs its own ADR with the weaker claims stated.
- Public witnesses as a second cosignature: no production list, a checkpoint every few seconds, and each size tells
  them the host's activity rate. Reconsidered once a production list exists.
- A ping from a separate timer on the Pi: it stays green while `balistid-pi` or its pushes are dead.
- A dead-man check on the Pi itself (Uptime Kuma): it dies with the Pi. The daily alive message alone: noticing a
  missing message is up to a person.

## Consequences

- Amends ADR 0031 point 6 (pushes are probed and the ping depends on them) and its Consequences (a dead Pi or a
  failed push alarms within `dead_site_alarm_s`). T27 moves from gap to partial.
- `acceptance/0.toml` gets `dead_site_alarm_s` (900), `install_minutes` (10) and `install_manual_steps` (5).
- Residuals: ntfy accepting a push does not prove the phone shows it, so a dead phone channel is found only by the
  missing daily message; whoever holds the ping URL can keep a dead Pi looking alive; while the service is down, a
  dead Pi is found only by its missing daily message; the service learns the Pi's address and ping times.
- Tests (L12): the Pi powered off, its uplink cut, `balistid-pi` stopped and ntfy unreachable each alert within the
  limit; one ping dropped alerts nothing; the ping URL appears in no log, argv or environment.
