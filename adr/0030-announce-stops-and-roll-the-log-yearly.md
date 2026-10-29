# 0030 — Announce a clean stop, and roll the log over each year

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-29
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 point 3 promises a cosigned announcement before a clean shutdown or suspend; ADR 0027 point 5 leaves the
log's cap as its only exit until rollover (an R5 exception). Nothing appends `announce` or `final` yet. The relay
stops before the ledger, so the ledger's own SIGTERM is too late for the witness and cannot tell a shutdown from a
restart. Tessera signs a checkpoint every 5 s; the relay asks the witness each second; `cosign_gap_s` is 60.

## Decision

1. The ledger listens on a second socket, `control.sock` 0600 in its runtime directory, for its own uid only
   (`SO_PEERCRED`, refusals summed with the collector socket's, ADR 0007 point 2). One request per connection: one
   frame holding an `announce` or `final` body, decoded strictly; the answer is a status byte and the log's size
   once the entry is in. The waiting batch is logged first, so the entry covers every record held (at the cap: 5).
2. The client is a mode of the same binary: `balistid-ledger -announce shutdown|suspend`, `-final <origin>`. It
   waits, not the ledger: each second it reads the relay's cosigned checkpoint until the entry is proven in its
   root, for at most 20 s at a shutdown and 10 s at a suspend (a lid closing); no guess cuts the wait short. An
   entry not cosigned in time stays in the log; the Pi then alarms after `silence_alarm_s` (R6).
3. Two oneshot units run as the ledger's uid with its sandbox and group: `balistid-announce` sends shutdown from
   `ExecStop` and is ordered after the relay, so it stops before it; `balistid-announce-suspend` sends suspend,
   `Before=` and wanted by `sleep.target`. Restarting the unit announces too; later growth ends the quiet. The quiet
   window and its cap (`announced_quiet_max_h`) are the Pi verifier's (L9), not the host's.
4. Cosigned is not yet read by the Pi, which learns an announcement from the tiles it mirrors: its verifier fetches
   on each new cosigned size and adds "the relay served the entry's bundle" to the client's wait (L9). WireGuard
   must not depend on NetworkManager, which may drop it before the suspend unit ran (an install requirement, 9.5).
5. Rollover is an install step as the ledger's uid, yearly or at the cap, where the log takes only `final`, in a
   slot kept for it (a waiting batch goes to the next log): `-final <next>`; then the ledger refuses the collector,
   whose store keeps its records; cosigned, `final.cosigned` and the verifying key are saved beside the log. Then:
   stop, `log` moved to `log.<n>`, a new Ed25519 key for the new origin, `balistid-ledger -rollover-from log.<n>`,
   start, and on the Pi `witnessctl add-log` and `add-key` (ADR 0026 point 4); until then the relay gets 404.
6. `-rollover-from` opens the new, empty log and checks the old one: `final.cosigned` verifies with the saved key
   and the witness's, its last entry is `final` naming the new origin, and inclusion proofs against the cosigned
   root hold for it and for the tail from the last batch, copied byte for byte as the first entries: the hello and
   root check (ADR 0027 point 3) pass unchanged, and no seal is logged twice. A failed copy leaves a prefix of it.
7. An old log is deleted when the latest witness time and the host's clock are both `log_retention_days` past the
   cosign time of its `final`, proven in it (ADR 0029's two clocks): renamed `.retiring`, synced, removed, resumed.

## Alternatives considered

- A logind inhibitor: a D-Bus module and a 5 s budget. A system-sleep script: no shutdown. The ledger waiting: a
  loop owning the log and polling without a collector, for what a client does with one file read.
- Automatic rollover: trust on the Pi changes by hand anyway. The same key under a new origin: once taken, it
  signs every later year. The old tail read by the collector, or a new entry type: changes on both ends.

## Consequences

- Amends ADR 0006 point 3, ADR 0007 point 2 (a second socket), ADR 0026 point 4 and ADR 0027 point 5: the cap,
  which keeps one slot for `final`, is no longer the only exit. T14 stays open beyond the quiet cap; T17 designed;
  T28: an announcement can miss the witness. A compromised ledger (T19) can announce, or end the log: both alarm.
- Range: the self-test stops `balistid-announce` and starts the suspend unit; facts `announce_cosigned` and
  `suspend_announced` prove each entry in a cosigned root. A real suspend is not run (the VM has no wake).
- Tests: cosigned before stop, appended with the witness away, another uid refused, final at the cap, nothing
  after it live and after a restart, a rollover refusing a wrong origin, key, uncosigned final or forged entry,
  and an old log kept until both clocks pass or dated by another note, with a crash between rename and removal.
