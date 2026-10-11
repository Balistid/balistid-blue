# 0016 — Collect Laurel's records without ever blocking Laurel

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-11
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Laurel v0.8.2 keeps one `SOCK_STREAM` to `file = "unix:…"`, connects as `_laurel` after dropping root, writes one JSON
object and `\n` per event with `ID` first, and blocks without a timeout when the reader stops; after a failed write a
listener must be back within about 6.3 s or it exits (`src/bin/laurel/main.rs:116-148,170-177`, `types.rs:35-36`).
auditd 4.2.1 feeds plugins from a ring (16384 records, our `q_depth`; default 2000); a record finding it full waits
4×2 ms and is dropped, only flagged in `auditd.state` (`audisp/queue.c`). The kernel backlog then fills and audited
syscalls sleep up to 60 s per record before the kernel counts `lost` (`kernel/audit.c`). Blocking Laurel (ADR 0007
point 5) moves loss to where it is not counted and can stall the host.

## Decision

1. Socket activation: `/run/balistid/collector.sock` (root-owned 0755 `/run/balistid`), `Accept=no`, root:_laurel 0660;
   other uids are denied by the kernel at connect. The acceptor checks each accepted peer with `SO_PEERCRED` against the
   uid of `_laurel` (unresolvable: refuse all) and counts refusals per minute (amends ADR 0007 point 2 for this
   socket: Laurel's lines are evidence, not typed requests). Up to two `_laurel` connections (Laurel holds at most an
   old and a new one) wait for one reader that reads each to EOF; a third waits in the listen backlog. A collector
   restart drops the connection: Laurel reconnects to the socket systemd keeps and its unread bytes stay uncounted.
2. Lines are evidence, so no strict decoding. `providerSeq` is the decimal after `:` in the `ID` that opens the line;
   a line whose JSON does not parse with that same `ID` is stored with `providerSeq` 0 and counted malformed, and so is
   a head cut by EOF or a tail that opens a connection. A line over 2 MiB is streamed, not validated: its first and
   last MiB, length and SHA-256 become the record through a `rawrecord` constructor for given parts.
3. The reader builds the record and queues it in a queue bounded in bytes; a full queue drops it at once and counts
   it, so the collector never blocks Laurel except while its own process starts. Losses are counted outside the queue
   per stage (framing, queue, store, shutdown, connections) with first and last `ID` and receive time.
4. One writer goroutine owns the store (ADR 0013): `Store.Append` takes the record, Flush every 250 ms, health and
   loss records. If a store call fails, the failing record and those appended since the last commit count as lost
   (at most). The writer closes that store, keeps its counters and opens a new one every 30 s; meanwhile the reader
   keeps draining and counting, and health is UNKNOWN (ADR 0017).
5. Acceptor and reader start before `Store.Open`, which runs in a goroutine the writer owns, so the writer's tick
   keeps running through a long recovery. Shutdown reads what Laurel already sent (100 ms deadline), stores it, then
   closes the store.
6. Queue size, shard size (starting at 512 MiB) and retry times are constants with their formula in code; the range
   measures them against `crash_loss_ms`.

## Alternatives considered

- Block Laurel (ADR 0007 point 5): trades our counted loss for auditd's uncounted one and can stall the host.
- Exit when the store fails: restarts end in a failed socket, Laurel exits and only root can bring it back.
- A line deadline or idle timeout: closing loses data; Laurel writes whole lines, a stall is Laurel's.

## Consequences

- Amends ADR 0007 points 2 and 5. Acceptance: `loss_per_day` and `loss_alarm_s` also count the collector's loss
  records; `record_max_kib` stores malformed lines and counts them; `fuzz_hours` runs on the commit to be installed in
  a scheduled CI workflow, crashers committed as seeds in `testdata/*.jsonl`.
- Exceptions to ENGINEERING §7: no read or idle timeout on Laurel's connection and no strict decoding of its lines.
- Still uncountable: unread bytes of a connection at a collector restart or of a Laurel that died (T25). Before the
  reader starts at boot Laurel blocks on the socket systemd holds.
- Tests: a peer with another uid that reaches the socket is refused and counted; old connection read to EOF; tail and
  head fragments stored as malformed; a line over 2 MiB stored truncated; full queue drops without blocking; a failing
  store call counts its record; kill -9 at any point, including a seal, keeps every line handed over more than 1000 ms
  before it (hard resets in the range).
