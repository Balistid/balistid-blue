# Status

Updated: 2026-11-22 by claude/opus-5.5 (judge locked; the pilot's test pair from Codex)

## Where we are

Floor 0 (recorder) is frozen unmet (ADR 0076): version A runs on the maintainer's host since 2026-11-14 and
stays as it is, but for a security fix, until the floor-1 pilot is valid and 2026-11-30; no metric of `acceptance/0.toml` has passed
there. Floor 1 starts as measurement: a detection judge on the host will give verdicts over the records of the
runner's agent jobs. `python3 tools/ci/status.py` shows this file next to the ADRs, the runner's results and open
pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured; on the host in version A |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents run jobs; the runner exports each job's records | installed at 2c09799 (no collector in its image); `range-kvm` self-tests every pull request on GitHub's KVM; after a reboot on 2026-11-17 it re-ran 24 October jobs left in the inbox, which dropped `p0-smoke-1` (ADR 0078) |
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | on `main` (`internal/detect`, `cmd/balistid-lab`, ADR 0079); gate B1 met 2026-11-22 on four windows in `lab/`; code-owned since #298 |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- #298: the judge locked; trial #300 with green checks stayed blocked without approval.
- #299, gate B1: the four dev-read runs ran once each on 2026-11-22 (4 of the pilot's 23 results
  after the anchor), imported byte for byte; `verify` passes and the table holds every value fixed in #297 before the
  runs: 4 windows valid, the pair counted, both controls 4 windows and 0 wrong, `opus-1` CAUGHT, CAUGHT, QUIET, QUIET,
  no cross rows. Scripts: 3 Codex rounds; residual: a result planted mid-hand-over (only the runner writes).
- #296: the judge (25 closed INVALID reasons, rules on one event, table, verify, import, job),
  ADR 0079, `lab/`'s gates; 3 rounds each of Opus critic and Codex security, a reply round, no escaped mutant but
  3 equivalents. Residual: another content's window vetoes its pair on its claimed hash (narrowing fails open, T39);
  a name made between publish's check and rename is replaced (os.Root has no RENAME_NOREPLACE); parallel imports.
- #294 (ADR 0078, the anchor), #293 (ADR 0077, window validity); older: git log.

## Next step
1. Pilot (B2): the test pair `tmp-hidden` (T1083, written by Codex, this pull request), rules from several models
   written blind and merged first, its four runner jobs, then the report with what it measures and not.

## Open decisions (maintainer)
- Approve this pull request (`STATUS.md`, the pair) and #301 (CI download retries).
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
