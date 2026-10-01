# 0007 — Split Kordon into small processes with separate identities

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R13 says only the collector and the installer may be privileged and that UI and CLI talk over a
Unix socket checked with `SO_PEERCRED`. Reading audit status (`AUDIT_GET`) needs `CAP_AUDIT_CONTROL`,
the capability that can also disable audit, so it must not sit next to a parser. Parsers and network
code are the likeliest places for bugs. The AI agents on this host run as the maintainer's user and
are inside the threat model.

## Decision

| Process | Identity | Privilege | Reads | Writes / network |
|---|---|---|---|---|
| `kordon-auditstat` | own uid | `CAP_AUDIT_CONTROL` | audit status, loaded rules | fixed-size reports |
| `kordon-collector` | own uid | none | Laurel socket, reports | shards; "stream from `seq`" |
| `kordon-ledger` | own uid | none, no network | collector stream | log tiles, signing key |
| `kordon-relay` | own uid | none | tiles | HTTP and witness, WireGuard only |
| `kordon-normalize` | own uid | none | sealed shards | derived database |
| CLI, UI | user | none | derived database, status | requests over sockets |

1. This ADR amends R13: the one privileged Kordon process is `kordon-auditstat`; it parses no
   sensor data and only reports fixed structures. The collector needs no privilege.
2. Every socket checks its peer with `SO_PEERCRED` against a per-socket uid allowlist and accepts
   only typed, size-capped requests; anything else is refused and logged.
3. Binaries, units, configuration and keys belong to root or their service user and are installed by
   `kordon-install`; the maintainer's user, and so the agents, can read the derived database but
   cannot write it or any of these. Raw records leave the collector only towards ledger and normalizer.
4. Units use systemd sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateNetwork` except
   the relay, restricted capabilities and address families) and live in the repository.
5. A slow reader catches up from `seq`; a slow collector makes Laurel block, and loss shows up as
   in ADR 0004.

## Alternatives considered

- One root daemon: simplest, but a parser or network bug becomes root and can disable audit.
- Readers on the live WAL database: possible read-only, but we keep one writer and sealed shards.
- gRPC or HTTP between local processes: more surface than typed messages on Unix sockets.

## Consequences

- Tests: the maintainer's uid cannot impersonate Laurel, read the raw stream, or write shards, tiles,
  keys, units or the derived database; unknown requests are refused; only `kordon-auditstat` holds a
  capability (`/proc/self/status`); the relay holds no key.
- `ENGINEERING.md` R13 is updated in the pull request that adds the first unit file.
- Each unit scores at most the `systemd-analyze security` threshold in `acceptance/0.toml`; any
  missing health signal makes the state UNKNOWN (R6).
