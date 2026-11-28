# 0082 — The judge first shows the recorder's state and what ran under agents

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-28
- Decided-by: jvc0n (2026-11-28, in session: the plan of step S1)
- Agent: claude/fable-5.2
- Amends ADR 0074 points 2 to 8 (what the judge reads and writes) and ADR 0076 point 1 (the host gains `judge`).

## Context

The question of ADR 0076: what did the agents on the maintainer's machine really run? On 2026-11-28 the host's
collector reports `UNKNOWN canary-missed`; auditd's queue to Laurel overflowed on 2026-11-25 at 18:30:32, and
nothing unprivileged can say since when the store has missed records, what it holds or how much it lost. The store
writes each health change, loss and lag as a record (ADR 0017), so the store itself can answer. ADR 0074's judge is
a stub and its unit and installer component exist. A program's name is chosen by whoever runs it.

## Decision

1. `balistid-judge` under ADR 0074 point 1's unit reads the sealed store and writes `state.json` and `exec.jsonl`
   to `/var/lib/balistid/judge`, 0644. It judges no days: ADR 0074 points 3 to 8 wait with the recorder
   (ADR 0076). No recorder unit or sensor file changes; the host gains the component `judge` only.
2. State comes first, from the seals alone; then shards are read newest first through `shard.Read`'s hashed copy.
   After each shard its runs are appended to `exec.jsonl` and `state.json` is rewritten whole. A limit of 90
   minutes is built in. `state.json` names every shard read and not read, and the last seal's seq and sha256.
3. `state.json` holds the period covered, the seals' count and bytes, every health change with its time, loss by
   stage (`lossOf`), the largest lag, gaps in the kernel's serials counted while reading (ADR 0062 stays proposed),
   records and bytes by rule key, and the intervals with no loss, no gap and health OK: the clean intervals.
4. `exec.jsonl` holds one line per successful execve of a uid of 1000 or more in the 7 newest days read: time,
   serial, pid, ppid, Laurel's keys of the process and of what spawned it (`PID`, `SPAWNED_BY`), the program's base
   name, and whether its path or its spawner's is an agent's own binary (the list is data in the judge). No path,
   argument, environment or directory. A name outside `[A-Za-z0-9._+-]{1,64}` is `x-` and 8 hex of its SHA-256.
5. `balistid-judge view <dir>`, unprivileged, builds the process tree from `exec.jsonl`: a run is under an agent
   when an ancestor is an agent's binary; of every other run it says only where its chain ended, never that no
   agent ran it. The programs seen are always printed, with what they cover; counts, the 20 most frequent,
   programs run once and runs with a broken chain for clean intervals only.
6. The assignment is checked with probes whose truth is known, numbers in `acceptance/2.toml` before the run: of
   30 uniquely named copies of `/usr/bin/true` run by an agent, 29 are in `exec.jsonl` and under an agent; a probe
   the store lacks is a miss. 10 run first in a subshell and 10 detached by a double fork are reported, no bar.
   No probe starts outside an agent (its sandbox denies it the user's service manager): point 8's ADR tests that.
7. The maintainer starts the unit by hand (`systemctl start balistid-judge.service`), as ADR 0074 point 1 has
   it: R8 covers what installs, and the unit runs only what `balistid-install` put there.
8. Fresh events for the first detection on the host will come from one Laurel writing a rotated file (`read-users`),
   the collector and ledger out of the events' path; its own ADR builds it with that detection's rules and reboot.

## Alternatives considered

- Laurel to a file now, without reading the store: changes the frozen recorder before its state is known and
  gives up the only history. Reading `audit.log`: it holds minutes at this rate, and is Laurel again (R9).
- A second reader beside the collector: changes the frozen collector, or adds a plugin to the queue that overflowed.
- Pairing the agents' shell calls with runs and with shifted times: it tests clocks and a shell parser.
- AgentSight (eBPF): kernel-coupled (ADR 0004), assigns by name and parent with fixed weights, no check of them.

## Consequences

- Every local user, so every agent, reads `exec.jsonl`. The assignment is against error, not against an agent
  that hides, and a lower bound: a lost record, a restarted Laurel or a forked shell that never exec'd (Laurel
  names it by its start time only) ends a chain. execveat and 32-bit execs are counted, not listed.
- The last unsealed hours are not read. The judge decodes Laurel's lines itself, tested on `lab/windows` to agree
  with `internal/detect`, which stays locked. `THREAT_MODEL.md` may hold 124 lines: row T41, the export (R10).
- Revert: a pull request restoring the stub, removing this file and `acceptance/2.toml`.
