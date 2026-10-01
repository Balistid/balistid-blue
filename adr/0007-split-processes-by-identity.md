# 0007 — Split Kordon into small processes with separate identities

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R13: only the collector and the installer may be privileged; UI and CLI are unprivileged and talk
over a Unix socket checked with `SO_PEERCRED`. Floor 0 must read audit counters, take records from
Laurel, write shards, sign checkpoints, talk to the Pi and answer queries. Reading audit status
(`AUDIT_GET`) needs `CAP_AUDIT_CONTROL`, the same capability that can disable audit, so it must not
sit next to a parser. Parsers and network code are the likeliest places for bugs. The AI agents
that work on this host run as the maintainer's user and are inside the threat model.

## Decision

| Process | Identity | Privilege | Reads | Writes / network |
|---|---|---|---|---|
| `kordon-auditstat` | own uid | `CAP_AUDIT_CONTROL` only | audit status (netlink) | fixed-size counters to collector |
| `kordon-collector` | own uid | none | Laurel socket, counters | shards; socket "stream from `seq`" |
| `kordon-ledger` | own uid | none, no network | collector stream | Tessera tiles, signing key (0600) |
| `kordon-relay` | own uid | none | tiles, closed shards | WireGuard to the Pi only; no key |
| normalizer, CLI | user | none | closed shards, stream | derived database |

1. `kordon-auditstat` parses no text: it reads the fixed status structure and sends numbers.
2. Every socket checks the peer with `SO_PEERCRED` against a per-socket uid allowlist and accepts
   only typed, size-capped requests; anything else is refused and logged.
3. Binaries, units, configuration and keys are owned by root or their service user and installed by
   `kordon-install`; the maintainer's user (and so the agents) cannot write them. Closed shards are
   readable through a group; nothing reads the live database except the collector.
4. Each unit uses systemd sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateNetwork`
   except the relay, restricted address families and capabilities). Units live in the repository.
5. Backpressure is explicit: if a reader is slow, the collector keeps writing and the reader catches
   up from `seq`; if the collector is slow, Laurel blocks and the loss shows up per ADR 0004.

## Alternatives considered

- One root daemon: simplest, but a parser or network bug becomes root and can disable audit.
- Readers on the live WAL database: possible with read-only files, but we keep one writer and give
  readers the stream and sealed shards instead.
- gRPC or HTTP between processes: more surface than typed messages on Unix sockets.

## Consequences

- Tests: the maintainer's uid cannot connect to the collector socket as Laurel, write shards, tiles,
  keys or units, or signal the services; an unknown request type is refused; the ledger, relay and
  CLI hold no capabilities (`/proc/self/status`); the relay holds no key file descriptor.
- Each unit scores at most the threshold in `systemd-analyze security` set in `acceptance/0.toml`.
- Five processes mean five health signals; any missing signal makes the state UNKNOWN (R6).
