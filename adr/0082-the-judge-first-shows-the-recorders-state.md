# 0082 — The judge first shows the recorder's state and what ran under agents

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-28
- Decided-by: jvc0n (2026-11-28, in session: the plan of step S1)
- Agent: claude/fable-5.2
- Amends ADR 0074 points 2 to 8 (what the judge reads and writes) and ADR 0076 point 1 (the host gains `judge`).

## Context

The question of ADR 0076: what did the agents on the maintainer's machine really run? On 2026-11-28 the host's
collector reports `UNKNOWN canary-missed`, auditd's queue to Laurel overflowed on 2026-11-25 at 18:30:32, and
nothing unprivileged can say what the store holds or what it lost. The store writes each health change, loss and
lag as a record (ADR 0017), so it can answer itself. ADR 0074's judge is a stub; its unit and component exist.

## Decision

1. `balistid-judge` under ADR 0074 point 1's unit reads the sealed store and writes `state.json` and `exec.jsonl`
   to `/var/lib/balistid/judge`, 0644. It judges no days (ADR 0074 points 3 to 8 wait with the recorder, ADR
   0076) and changes no recorder unit or sensor file: the host gains the component `judge` only.
2. State comes first, from the seals alone. Shards are then read oldest first, in one pass, from the first UTC
   day whose shards up to the newest fit a byte budget (half the rate measured under the unit's CPU policy);
   older ones are named as not read. After each shard its runs are appended to `exec.jsonl` and `state.json` is
   rewritten whole. 90 minutes are a hard stop; then the read is PARTIAL.
3. `state.json` holds the seals, every health change with its time, and a row per UTC day read: records, bytes,
   execs, loss by stage, serial gaps by boot (ADR 0062 stays proposed), seconds its health was not OK, the largest
   lag in the store and in arrival, silences, lines not decoded. It certifies no time as free of loss.
4. `exec.jsonl` holds one line per successful execve of a uid of 1000 or more received on the newest seal's UTC
   day or the 7 before it: the event's time, when it was received, serial, pid, ppid, Laurel's keys of the process
   and of what spawned it, the program's base name, and whether its path or its spawner's is Claude Code's binary.
   No path, argument, environment or directory. A name outside `[A-Za-z0-9._+-]{1,64}` is `x-`, 8 hex of its SHA-256.
5. `balistid-judge view <dir>`, unprivileged, builds the process tree from `exec.jsonl`: a run is under an agent
   when an ancestor is that binary; of every other run it says only where its chain ended. Every count is of what
   the store holds, so "at least", by day, beside that day's loss, gaps and health; a day not read is not read,
   never zero. Nothing is concluded from a run's absence.
6. Probes whose truth is known check the assignment (`acceptance/2.toml`, set before the run): of 30 uniquely
   named copies of `/usr/bin/true` an agent ran, 29 are in a COMPLETE read exactly once, under an agent, within
   5 s of their manifest's time. 10 run first in a subshell and 10 detached are reported; none starts outside it.
7. The maintainer starts the unit by hand (`systemctl start balistid-judge.service`), as ADR 0074 point 1 has
   it: R8 covers what installs, and the unit runs only what `balistid-install` put there.
8. Fresh events for the first detection on the host will come from one Laurel writing a rotated file (`read-users`),
   the collector and ledger out of the events' path; its own ADR builds it with that detection's rules and reboot.

## Alternatives considered

- Laurel to a file now, without reading the store: changes the frozen recorder before its state is known and
  gives up the only history. Reading `audit.log`: it holds minutes at this rate, and is Laurel again (R9).
- A second reader beside the collector: changes the frozen collector, or adds a plugin to the queue that overflowed.
- Pairing shell calls with runs against shifted times: it tests clocks and a shell parser. Intervals certified
  free of loss: three reviews found a way around each rule that dated a loss.
- AgentSight (eBPF): kernel-coupled (ADR 0004), assigns by name and parent with fixed weights, no check of them.

## Consequences

- Every local user, so every agent, reads `exec.jsonl`. The assignment is against error, not an agent that
  hides or lies: Claude Code is known by a path in a home it can write, the probes by its own manifest, and a
  lost record, a restarted Laurel or a forked shell that never exec'd ends a chain (T41). execveat and 32-bit
  execs are counted, not listed; the last unsealed hours are not read. `internal/detect` stays locked: the judge's
  decoder agrees with it on `lab/windows`. `THREAT_MODEL.md` may hold 124 lines, for T41 (R10).
- Revert: a pull request restoring the stub, removing this file and `acceptance/2.toml`.
