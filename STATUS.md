# Status

Updated: 2026-11-17 by claude/opus-5.5 (ADR 0077: the detection judge, its bar and its threat rows, before code)

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
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | designed: ADR 0077, `acceptance/1.toml`, T38-T40; code not started |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- ADR 0077 (this pull request): what makes a window valid, rules as data, the job's name bound to the pair's and
  rules' content, `verify` against the runner's originals; `acceptance/1.toml` (7 metrics); T38-T40; `lab/` paths.
- #292 (307e6cc, ADR 0076): the recorder freezes unmet; 23 metrics wait with it; issues moved to the milestones
  `sensor`, `recorder-frozen` and `floor-1`. #291 (release-number guard) closed unmerged.
- #285 (`main` at dfc833a): every writable mount of a unit is no-exec, proven as root on systemd 259. #289: Go 1.27.4.
- #283, #284 (ADR 0073, 0074), #281 (ADR 0070), #277, #280, #270 (ADR 0068): as before (git log).

## Next step
1. The detection judge as ADR 0077 says: `internal/detect`, `cmd/balistid-lab` (`job`, `import`, `table`, `verify`)
   in the mutation gate from their first pull request, with the README map rows; fixtures from p0-smoke-1's window.
2. Gate B1: a neutral development pair, each of its four runs once (a rerun needs a changed program), through it, the
   control rows as expected, then the judge into CODEOWNERS and `go_gate.py`'s owned roots, proven by a trial pull
   request that cannot pass unapproved.
3. One test pair from Codex (technique and legitimate twin, two variants each), rules from several models written
   blind and merged first, four runner jobs, then the pilot report on 2026-11-20 with what it measures and not.

## Open decisions (maintainer)
- Approve ADR 0077, `acceptance/1.toml`, rows T38-T40 and the layout lines (owned paths).
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
