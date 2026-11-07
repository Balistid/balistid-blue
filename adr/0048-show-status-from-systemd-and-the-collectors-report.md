# 0048 — Show status from systemd and the collector's report

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: jvc0n
- Agent: claude/opus-5.5
- Amends: R13 and §7 file modes (ENGINEERING.md), ADR 0007 table (CLI row), ADR 0043 point 4 (when)

## Context

`status_false_ok` (acceptance/0.toml) asks that the unprivileged `balistid status` never show OK while a floor-0
unit is stopped or health is UNKNOWN; `balistid` prints only its version. The collector already computes health
on each 250 ms tick, OK or UNKNOWN with a reason (internal/collector/writer.go `setHealth`), but keeps it in its
0700 store, the journal and the ledger stream. systemd answers `systemctl show` for any user. R13 says the CLI
talks to a daemon over a Unix socket checked with `SO_PEERCRED`; a socket in the collector would give every local
user, A1 included, a new input into the process that parses Laurel's stream (T18). auditstat already hands its
state to the collector as a fixed-size file the reader checks by owner (ADR 0038 point 2). Local mode (ADR 0043)
is not installed yet, so no host has a mode, local history or an alert path for status to read.

## Decision

1. **Channel.** The collector rewrites `/run/balistid-collector/status` on each change of health and every second:
   label, CLOCK_BOOTTIME and its health entry (internal/entry), 0644 in its unit's 0755 runtime directory, which
   goes away while the collector is stopped; §7 allows that one 0644 file. The CLI reads it with `wholefile.ReadOwned` (regular file of
   the collector's uid, exact size, no symlink, no FIFO). R13 now reads: talk over a Unix socket checked with
   `SO_PEERCRED`, or read a fixed-size file the daemon publishes, checked by owner, type and size.
2. **Parts.** Each floor-0 unit of the host (auditd, the collector's socket and service, auditstat, ledger, relay,
   `balistid-net`, `balistid-announce`) from `/usr/bin/systemctl show` with only `LC_ALL=C`, parsed strictly; OK
   only loaded, active and in its expected substate. The health part is OK only from a report at most 5 s old
   (`status.MaxAge`) that says OK. Anything not read is UNKNOWN (R6); the floor is OK only when every part is.
3. **Output.** Text names each part, and under each part not OK a fixed hint where to look; `--json` gives the
   same result (`schema_version` 1). Exit 0 OK, 1 not OK, 2 usage. Mode, history and alerts (ADR 0043 point 4)
   come with the local-mode install; until then the text says so and `status_false_ok` covers units and health.
4. **Trial.** Rows `status-1` and `status-2` (rangejob): the guest, as root, runs the CLI as `balistid-job`
   healthy, then after masking and stopping each unit in turn, after freezing auditd (it refuses a manual stop)
   and Laurel with SIGSTOP, and healthy again. Each run carries the guest's own proof, from before the CLI to after
   it (the unit inactive, the process stopped, every unit active), and for frozen and healthy runs the store's
   health over the CLI's run and, for a freeze, when it began. The judge keeps its own list of units, checks every
   CLI call, waits included, against the store, and lets a MISS outrank any INVALID: OK over a store UNKNOWN
   throughout, a break not shown with its part or a healthy run not OK is a MISS; a run the store leaves open, or a
   freeze that did not start from an OK store, is INVALID.

## Alternatives considered

- A socket in the collector, as R13 read: a listener, a uid allowlist from the install and refusal accounting in
  the process that parses untrusted input, to hand over 74 bytes a file carries without any input.
- The journal: system units' journal is readable only by adm, wheel or systemd-journal, and it is not a state.
- Health from the Pi's watcher: not on the host at the higher level; in local mode a second reader of the same.

## Consequences

- T11 stays partial: A1 at the maintainer's uid can alias or ptrace the CLI; the phone stays the truth.
- The report is world-readable: every local uid learns when the recorder is UNKNOWN, why, and how many losses wait
  to be stored. Any unprivileged status tells the uid running it the same, and A1 runs as the maintainer's uid, so
  a group-readable report would hide nothing from A1.
- Residual: no run freezes the collector (tested in-process); only `--json` runs; local mode adds the Pi's units.
- A collector that stops writing shows UNKNOWN within 5 s. A failed write removes the old report, so the CLI reads
  UNKNOWN at once; only if that fails too does it stand until 5 s. The collector never stops over its report.
- Tests: the report's encoding, owner, age and reasons; each unit state; the parser's fuzz; a negative judge case
  for each way to a false PASS (unproven break, store against the CLI, part not shown, as root, an unbroken unit).
