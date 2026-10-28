# 0027 — Stream committed leaves to the ledger, and log loss and health

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-28
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0026 left the channel from the collector and the fields of `loss` and `health` open; ADR 0017 point 7 asks for
health on that channel while the store is down. The store does not return a record's seq, and leaves live only in
the shard's `leaf` column. A second connection on the active shard would break its seal (leaving WAL needs it
alone). Tessera v1.0.4 resolves an `Add` only once the entry is integrated, so its log is a prefix of its input.

## Decision

1. After each `Flush` that returns without error, the collector's writer reads seq, leaf, and what point 6 needs,
   of the records in (sent, `Committed`], in seq order and capped per tick, through the store's one connection
   (inside its open transaction if there is one, so it never waits); sealed shards are opened read-only. A bounded channel takes them to a
   link goroutine; when full, `sent` stays, so the writer never waits for the ledger. Live, resend and restart are
   this one path. Seqs that a seal committed but whose index line failed wait for the reopen to recover the shard.
2. The ledger listens on its own socket, not one systemd passes (`SO_PEERCRED` would show systemd's uid), and takes
   only the collector's uid; the collector takes only the ledger's uid. Messages are typed, length-prefixed, at most
   64 KiB, decoded strictly, fuzzed both ways. Refusals are summed per minute in the ledger's journal: it cannot
   write the raw store, so `refusal_summary_s` covers the collector's sockets.
3. On connect the ledger sends L, the last seq of its last batch, with that batch's first seq and root. The
   collector refuses L above `Committed` and recomputes the root from its own leaves; a mismatch (a torn write
   re-issued seqs, ADR 0013 point 5) is health UNKNOWN and the stream stops (R6). It then sends from L+1. There are
   no acknowledgements: the next connect's L is the resume point.
4. Entries bound to a seq keep seq order: a loss entry precedes the batch covering its record; a seal cuts the batch
   at its last seq and follows it. Health is bound to no seq. On start the ledger reads its log back to the last
   batch, at most 64 bundles, else fails closed; a resent entry already in that tail is dropped; a seal with a known
   first seq and another hash, or out of position, is refused and turns the ledger UNKNOWN. This replaces ADR 0013
   point 3's resend after the last seal.
5. A batch covers at most 1 s of leaves. Tessera's POSIX log runs without antispam, checkpoints every 5 s, signed
   with Ed25519; the ledger locks its directory for its lifetime. A tree over `host_log_cap_gib` turns it UNKNOWN
   and it appends nothing more (R5), tested by a lowered cap; rollover comes with the Pi's verifier (ADR 0026, 2).
6. Type 3 `loss`: the seq of the record carrying it, stage, records. Stages: 1 cap (the store's loss record, cap or
   full filesystem, and the collector's cap stage), 2 queue, 3 framing, 4 store, 5 shutdown (the collector's lost
   records, their count), 6 truncated (a committed record whose original length exceeds its data, 1). Type 4
   `health`: state (1 OK, 2 UNKNOWN), reason (0 none, 1 starting, 2 store down, 3 Laurel disconnected, 4 canary
   missed, 5 canary pending) and the records counted lost and not yet stored; the writer sends it on connect and on
   change, beside the store. Nothing fills lost bytes or kernel and dispatcher loss yet; a new stage or reason
   widens decoding, so it reaches the Pi first.

## Alternatives considered

- Leaves pushed from the store's memory: a second path for resend and restart. Acknowledgements: nothing uses
  them. A state file beside the log: after a crash it can disagree with the log and log a range twice.
- Loss and truncation from the stats record: lost after the last one; one entry per truncated record is not.

## Consequences

- Amends ADR 0013 point 3, ADR 0026 point 1 (types 3 and 4) and the method of `refusal_summary_s`. The started
  record's order and counts after the last stats record (ADR 0026) stay collector issues. The Pi counts truncated
  entries per hour of its own clock; any other loss stage or UNKNOWN alarms.
- Tests: leaves equal `rawrecord.Leaf` across a rotation, never past `Committed`; a stalled ledger never stops a
  tick; resume from L; L above `Committed` and a wrong root refused; kill -9 of the ledger after `Add`, after
  integration, between a batch and its seal or a loss and its batch: no gap, no overlap, and a consistency proof
  from the old checkpoint (a fake witness; none ships before the relay); a second ledger, another uid refused.
