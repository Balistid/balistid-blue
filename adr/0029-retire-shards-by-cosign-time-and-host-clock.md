# 0029 — Retire shards by the witness's cosign time and the host's clock together

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-29
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0005 point 4 lets the collector delete a shard once the ledger reports its seal anchored and cosigned and it is
older than `raw_retention_days`, measured between witness cosignature times. Nothing deletes yet: the store's only
exit is its cap (R5). The relay keeps the last checkpoint the witness cosigned (`checkpoint.cosigned`); each
cosignature/v1 line carries the witness's time in seconds under its key. The ledger knows where a seal entry landed
only for entries it appended itself: after a restart it reads back to its last batch (ADR 0027 point 4), and Tessera
collects partial bundles. The Pi has no RTC (T22): its clock can start behind or be moved by its time source.

## Decision

1. The relay's file is readable by its group, which the ledger joins. The ledger reads it about once a second,
   capped and without following links; `internal/cosign` checks the ledger's signature, the witness's cosignature
   and the origin. The collector checks the same note again, so no process trusts another's reading of it.
2. The ledger keeps the last seal it appended and the log size after it; once a cosigned checkpoint covers that
   size, the seal is its covered seal. After a restart it has none until a seal it appends is cosigned. Frame 5
   `cosigned` (the covered seal and the note, at most 16 KiB) follows the hello and every change of either. This
   amends ADR 0027 point 3: the ledger sends after its hello, still no acknowledgement.
3. The collector takes the frame only after this connection's hello passed its check, only for a seal equal to a
   line of its own index that does not end past what it sent, with a note both installed keys verify and a witness
   time not older than the last one taken. Indexed shards through that seal without a cosign time get the larger of
   that time and the newest stored one; a stored time never changes.
4. The index becomes `balistid-seals 2`: a line adds the host's time at the seal and, once known, the cosign time;
   seqs run on from the first line, not from 1. The oldest shard is retired, one per writer tick, never the last
   sealed one, when the latest witness time is `raw_retention_days` past its cosign time and the host's clock as far
   past its seal: the index is rewritten without it, then the file unlinked and the directory synced. Open removes
   an unindexed shard below the first line, what a crash in between leaves; no index with shards not starting at
   seq 1 fails Open. Marking and retiring skip a store that is UNKNOWN or short of space and try on the next tick;
   they never spend the reserve, and the space retiring frees refills it first.
5. A hello below the first kept seq stops the stream with reason 6 instead of retrying a read that cannot succeed.

## Alternatives considered

- Trust the ledger's report as ADR 0005 words it: a compromised ledger (T19) could make the collector retire at once.
- A batch frontier (a shard counts once a later batch is cosigned): rests on the collector never skipping a seal;
  an exact seal is checked against the index.
- An inclusion proof of the seal entry under the cosigned root: unforgeable by the ledger, at the cost of proofs in
  the collector; the ledger can only name a seal the index holds, and nothing retires before both clocks agree.
- Witness time alone: a Pi clock moved forward retires everything at once; one that started behind dates shards
  decades back. A replayed old note would too, without the monotonic time of point 3.
- A `retire` entry for the Pi: nothing reads it before the Pi's verifier, and root deletes without one (T15).

## Consequences

- Amends ADR 0005 point 4 (the host clock is a second condition, never the only one, ENGINEERING §7 Time), ADR
  0013 points 2, 6 and 7, ADR 0027 point 3 and the method of `raw_retention_days`.
- T22 designed; left open: root setting both clocks. T15 stays a gap. T19: a compromised ledger can name a later
  indexed seal as covered, so a shard not yet cosigned retires once both clocks pass its age. T18-T20: the relay's
  file and frame 5 are new input, capped, decoded strictly and fuzzed.
- Range: a range-only `-shard-max` seals mid-run; fact `shard_cosigned` finds a cosign time in the sandboxed index.
- Tests: retirement needs both clocks; an ineligible shard, the last one and a stored time are kept; kill -9
  between the index rewrite and the unlink; a frame with an unknown seal, one past what was sent, before the hello
  check or with an older witness time is refused.
