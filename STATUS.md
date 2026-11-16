# Status

Updated: 2026-11-16 by claude/opus-5.5 (ADR 0076: the recorder freezes unmet, floor 1 starts as measurement)

## Where we are

Floor 0 (recorder) is frozen unmet (ADR 0076): version A runs on the maintainer's host since 2026-11-14 and
stays as it is, but for a security fix, until the floor-1 pilot is valid and 2026-11-30; no metric of `acceptance/0.toml` has passed
there. Floor 1 starts as measurement: a detection judge on the host will give verdicts over the records of the
runner's agent jobs. `python3 tools/ci/status.py` shows this file next to the ADRs, the runner's results and open
pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured; on the host in version A |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents run jobs; the runner exports each job's records | installed at 2c09799 (no collector in its image); `range-kvm` self-tests every pull request on GitHub's KVM; agent job `p0-smoke-1` ran 2026-11-16 |
| Detection judge (0009 point 7, 0076) | verdicts from a job's records, rules as data | not started; ADR 0077 decides it |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- ADR 0076 (this pull request): the recorder freezes unmet; 9.5 and the host days (ADR 0064, 0074, 0075) stop;
  23 metrics wait with the recorder; floor 1 starts as measurement. #291 (release-number guard) closed unmerged.
- #285 (`main` at dfc833a): every writable mount of a unit is no-exec, proven as root on systemd 259. #289: Go 1.27.4.
- #283, #284 (ADR 0073, 0074), #281 (ADR 0070), #277, #280, #270 (ADR 0068): as before (git log).

## Next step
1. ADR 0077 (the host computes a detection verdict from a job's records; rules are data; the judge locks) with
   `acceptance/1.toml` and `lab/` in the layout and README map, before the judge's code (R3).
2. The detection judge without privilege: `internal/detect`, `cmd/balistid-lab` (`job`, `import`, `table`), tested on a real
   job's records; then a neutral development pair through it and the judge into CODEOWNERS and the mutation gate.
3. One test pair from Codex (technique and legitimate twin, two variants each), rules from several models written
   blind and merged first, four runner jobs, then the pilot report on 2026-11-20 with what it measures and not.

## Open decisions (maintainer)
- Approve ADR 0076 and its README lines (owned paths).
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
