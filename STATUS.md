# Status

Updated: 2026-11-28 by claude/opus-5.5 (step S1: the host judge's first output, ADR 0082)

## Where we are

Floor 0 (recorder) is frozen unmet (ADR 0076): version A runs on the host since 2026-11-14, as it is until
2026-11-30 but for a security fix; no metric of `acceptance/0.toml` passed there. On 2026-11-28 its collector
reports `UNKNOWN canary-missed`; what the store holds is not known until the host judge runs (ADR 0082).
Floor 1's pilot is valid as a test of the instrument (gate B2): its verdicts can be recomputed and two more
implementations agree on each; it compares no models. `python3 tools/ci/status.py` shows this file. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured; on the host in version A |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents run jobs; the runner exports each job's records | installed at 2c09799 (no collector in its image); `range-kvm` self-tests every pull request on GitHub's KVM; after a reboot on 2026-11-17 it re-ran 24 October jobs left in the inbox, which dropped `p0-smoke-1` (ADR 0078) |
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | on `main` (`internal/detect`, `cmd/balistid-lab`, ADR 0079, 0080), code-owned; gates B1 (2026-11-22) and B2 (2026-11-27) met; nothing is added to it before the roadmap |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |
| Host judge (0074, 0082) | the recorder's state and the users' execs from the sealed store; `view` assigns runs to agents | on this branch, not installed; its probes ran on 2026-11-28, before the install (`acceptance/2.toml`) |

## Done in the last sessions
- This pull request, step S1 (ADR 0082): `balistid-judge` reads forward once and writes `state.json` (seals, health
  changes, a row per UTC day: loss, lag, serial gaps, seconds not OK) and `exec.jsonl` (no argument or path); `view`
  builds the tree and prints every count by day as a lower bound beside that day's evidence, and checks probes.
- e141cb8, gate B2: the pilot's report, `lab/results/2026-11-27-pilot.json`. tmp-hidden: 14 of 21 rules catch
  both variants and stay quiet on both twins; time-now 0 of 22; env-locale not measured; cross rows 0 NOISY of 305.
- #313-#319, ADR 0081: the README, its banners and diagram; `range-kvm` skips a change that is prose only.
- #310: T2's 12 windows, byte for byte. #309 (ADR 0080): the judge compares strings as Laurel decodes to.

## Next step
1. The maintainer installs `judge` from a signed bundle and starts the unit; `view` with the manifests of the
   probes run on 2026-11-28 gives `probes_assigned`, a miss if the store lacks them.
2. The roadmap (2026-11-29) orders what follows and names the first rule to run on the maintainer's machine.

## Open decisions (maintainer)
- Approve this pull request (ADR 0082, `acceptance/2.toml`), then install `judge` and start it by hand.
- Run `verify` from a clean checkout and sign the results tag (ADR 0077 point 6); at most 7 runner jobs before.
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
