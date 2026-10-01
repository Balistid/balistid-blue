# 0007 — Separate the privileged collector from everything else

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R13: only the collector and the installer run with privilege; UI and CLI are unprivileged and talk to
the daemon over a Unix socket checked with `SO_PEERCRED`. Floor 0 has five jobs: read the sensor,
write raw shards (ADR 0005), append to the Merkle log and talk to the witness (ADR 0006), normalize,
and answer queries. Network code and parsers are the likeliest place for a bug; they should not hold
privilege. A reader of a live WAL database needs write access to its `-shm` file (SQLite docs;
to be confirmed in a test), which would let it corrupt the writer's view.

## Decision

1. `kordon-collector` runs as a dedicated system user with only the capabilities it needs to read
   the audit stream and the `auditctl -s` counters; root only if a test shows a capability set is not
   enough. It reads Laurel's stream, writes shards and is the single writer.
2. It exposes one Unix socket with a typed, allowlisted protocol: status, and "stream raw records
   from `seq`". Every connection is checked with `SO_PEERCRED` against a configured uid list; any
   other uid or an unknown request is refused and logged.
3. `kordon-ledger` runs unprivileged: it consumes the stream, appends to Tessera, serves tiles and
   submits checkpoints to the witness. It holds no capabilities and is the only process with network.
4. `kordon-normalize` and the CLI/UI run unprivileged. They read closed shards opened with
   `immutable=1` and the stream; they never open the live database.
5. Processes run under systemd with sandboxing options (`ProtectSystem`, `NoNewPrivileges`,
   `PrivateNetwork` except the ledger, restricted address families). Unit files live in the
   repository and are installed by `kordon-install`.

## Alternatives considered

- One root daemon doing everything: simplest, but a parser or network bug becomes root.
- UI reading the live database directly: needs write access to `-shm`; rejected.
- gRPC or HTTP between processes: more surface than a small typed protocol on a Unix socket.

## Consequences

- Tests: a uid outside the list is refused by the socket; an unknown request type is refused;
  `kordon-ledger` and the CLI hold no capabilities (`/proc/self/status`); the collector unit scores
  at most the threshold in `systemd-analyze security` set in `acceptance/0.toml`.
- Three processes mean three health signals; each missing signal makes the state UNKNOWN (R6).
- The capability set of the collector is measured in the range VM before the first install.
