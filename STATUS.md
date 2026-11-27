# Status

Updated: 2026-11-27 by claude/fable-5.2 (gate B2: the pilot's report)

## Where we are

Floor 0 (recorder) is frozen unmet (ADR 0076): version A runs on the maintainer's host since 2026-11-14 and
stays as it is, but for a security fix, until 2026-11-30; no metric of `acceptance/0.toml` has passed there.
Floor 1's pilot is measured and valid as a test of the instrument (gate B2): its verdicts can be recomputed and
two more implementations agree on each. It does not compare models, by rank or by family. `python3
tools/ci/status.py` shows this file next to the ADRs, the runner's results and open pull requests. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured; on the host in version A |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents run jobs; the runner exports each job's records | installed at 2c09799 (no collector in its image); `range-kvm` self-tests every pull request on GitHub's KVM; after a reboot on 2026-11-17 it re-ran 24 October jobs left in the inbox, which dropped `p0-smoke-1` (ADR 0078) |
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | on `main` (`internal/detect`, `cmd/balistid-lab`, ADR 0079, 0080), code-owned; gates B1 (2026-11-22) and B2 (2026-11-27) met; nothing is added to it before the roadmap |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- This pull request, gate B2: the pilot's report, `lab/results/2026-11-27-pilot.json`. tmp-hidden: 14 of 21 rules
  catch both variants and stay quiet on both twins, all 14 by the one flag that differs (7 list flag spellings
  and name no program, 7 match it by a substring). time-now: 0 of 22; its twins print the time and zone as the
  technique does and its brief names no twin (of the 17 rules that catch, 10 match `%Z` and 7 the program).
  env-locale not measured (no grep in the image). Cross rows 0 NOISY of 305, each window one unrelated command.
- #313-#319, ADR 0081: the README, its banners and diagram; `range-kvm` skips a change that is prose only.
- #310: T2's 12 windows, byte for byte. #309 (ADR 0080): the judge compares strings as Laurel decodes to, merged
  after the windows were made and before their import; no clean verdict depends on it. #305-#308: T1.

## Next step
1. A roadmap (2026-11-29) orders what follows and names the first rule to run on the maintainer's machine; the
   lab is then its acceptance test. No new model round before it. A new pair merges only if its commands are in
   the image, its brief describes the twin and hints at no answer, the twin is a legitimate activity and not the
   technique with one word changed, no model that wrote it is measured on it, and rules also run on ordinary work.

## Open decisions (maintainer)
- Approve this pull request (the README's sentences on what passing means).
- Run `verify` from a clean checkout and sign the results tag (ADR 0077 point 6); at most 7 runner jobs before.
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
