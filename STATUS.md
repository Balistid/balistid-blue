# Status

Updated: 2026-11-18 by claude/opus-5.5 (J2: the detection judge's code and ADR 0079, how it reads a window)

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
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | built in this pull request (`internal/detect`, `cmd/balistid-lab`, ADR 0079); no window in `lab/` yet |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- This pull request: the judge (25 closed INVALID reasons, rules on one event, table, verify, import, job) and
  ADR 0079; both packages in the mutation gate; Opus critic and Codex security on its first version.
- #294 (ADR 0078): the anchor is the newest result once the inbox is emptied, fixtures come from
  hard-exec-1's window, a rule is judged on one event; the runner's re-run is issue #295.
- #293 (ADR 0077): what makes a window valid, rules as data, the job's name bound to the pair's and rules' content,
  `verify` against the runner's originals; `acceptance/1.toml` (7 metrics); T38-T40; `lab/` paths. Older: git log.

## Next step
1. The `ci:` pull request of the gates (lane balistid-gates): every runner file of a window in the layout, its
   decoded secret scan, the 16 MiB cap of `lab/`; then CI's `table` twice and in a fresh clone (table_reproducible).
2. Gate B1: a neutral development pair, each of its four runs once (a rerun needs a changed program), the control
   rows as expected, then the judge and `internal/wholefile` into CODEOWNERS and `go_gate.py`'s owned roots, proven
   by a trial pull request that cannot pass unapproved.
3. One test pair from Codex, rules from several models written blind and merged first, four runner jobs, then the
   pilot report with what it measures and not.

## Open decisions (maintainer)
- Approve this pull request: ADR 0079, the judge's code, its rows in the README map and the mutation gate.
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
