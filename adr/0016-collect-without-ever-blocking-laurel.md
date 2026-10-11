# 0016 — Collect Laurel's records without ever blocking Laurel

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-11
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Laurel v0.8.2 keeps one `SOCK_STREAM` to `file = "unix:…"`, connects as `_laurel` after dropping root, writes one JSON
object and `\n` per event with `ID` first, and blocks without a timeout when the reader stops; after a failed write a
listener must be back within about 6.3 s or it exits (`src/bin/laurel/main.rs:116-148,170-177`, `types.rs:35-36`).
auditd 4.2.1 feeds plugins one netlink record at a time from a 16384-record ring; a record finding it full waits 4×2 ms
and is dropped uncounted (`audisp/queue.c`). The kernel backlog then fills and every audited syscall sleeps up to 60 s
per record (`kernel/audit.c`). Blocking Laurel (ADR 0007 point 5) moves loss to where nothing counts it.

## Decision

1. Socket activation: `/run/balistid/collector.sock`, `Accept=no`, root:_laurel 0660. Socket and service start in sysinit
   before auditd, after sysusers, tmpfiles and local filesystems, and stop before `shutdown.target`; `Restart=always`,
   `Type=notify`. A restart keeps Laurel connected; a crash loop fails the socket and ends Laurel without freezing the
   host. `deploy/systemd/balistid-collector.socket` is admitted by a line grammar (amends ADR 0003).
2. An acceptor checks every peer with `SO_PEERCRED` against the uid of `_laurel` (unresolvable: refuse all) and counts
   refusals per minute. Up to four `_laurel` connections wait for one reader that reads each to EOF; a fifth is closed and
   counted. No read or idle timeout (a timeout is a reconnect and a loss); the canary proves liveness.
3. Lines are evidence, not our protocol, so no strict decoding: `providerSeq` is the serial between `{"ID":"` and the next
   `"`, and the line must parse as JSON with that same `ID`, or it is stored with `providerSeq` 0 and counted malformed.
   A line over 32 MiB (Laurel's largest is ~18 MiB, inferred) is skipped to its `\n` and counted lost, as is one cut by EOF.
4. The reader builds the record (`rawrecord.New`) and queues it in a queue bounded in bytes; a full queue drops it at once
   and counts it, so the collector never blocks Laurel. Losses are counted outside the queue per stage (framing, queue,
   store, shutdown, connections) with first and last `ID` and receive time, findable in auditd's own log.
5. One writer goroutine owns the store (ADR 0013): `Append` of the record, Flush every 250 ms, health and loss records.
   Records appended since the last commit count as lost (at most) if a store call fails. Shutdown reads what Laurel
   already sent (100 ms deadline), stores it, then closes the store.
6. If the store cannot open or turns UNKNOWN, the reader keeps draining and counting, the counts go to the journal each
   minute, health is UNKNOWN and Open is retried every 30 s; the loss is stored once the store is back.
7. Any EOF from Laurel sets UNKNOWN until a canary arrives over the next connection. The first connection after start is
   not a reconnect; a later one from the same pid is, a new pid is a Laurel restart.
8. A canary goroutine writes a file outside the store every 30 s, watched by an audit rule with key `balistid-canary`; it
   counts as seen once its record is stored, and two misses set UNKNOWN. No exec, so the unit can deny `execve` (T18);
   shutdown does not wait for it, as it may sleep in the kernel backlog.
9. Health records (`schema_version` 1): started (version, boot id, rule version), laurel connection with pid, lost,
   refused, canary, stats each 60 s (records, bytes, truncated, lost, queue high-water, max lag), stopping. A lag over
   1000 ms is a health event. The writer's tick feeds the systemd watchdog.
10. Queue size, shard size (512 MiB, so a seal stays within `crash_loss_ms`) and retry times are constants with their
    formula in code, measured in the range; acceptance numbers do not change.

## Alternatives considered

- Block Laurel (ADR 0007 point 5): trades our counted loss for auditd's uncounted one and can freeze the host.
- Exit when the store fails: restarts end in a failed socket, Laurel exits and only root can bring it back.
- A line deadline or idle timeout loses data on close; a streamed hash changes `rawrecord`, a capped buffer suffices.

## Consequences

- Amends ADR 0007 point 5. `fuzz_hours` runs in a scheduled CI workflow; seeds are read from `testdata/*.jsonl`.
- Still uncountable: records before the reader starts at boot and unread data of a Laurel that died (T25). While the store
  is down only the journal shows UNKNOWN, and a crash then loses the counts; the Pi silence alarm remains.
- Tests: foreign peer refused while Laurel is connected; old connection read to EOF; fragment stored as malformed; full
  queue drops without blocking; kill -9 in a seal loses nothing acknowledged; store failure; canary; shutdown; watchdog.
