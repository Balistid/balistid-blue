# Status

Updated: 2026-11-23 by claude/opus-5.5 (T1 rules, T2's 12 windows judged, ADR 0080)

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
| Detection judge (0009 point 7, 0076, 0077) | verdicts from a job's records, rules as data | on `main` (`internal/detect`, `cmd/balistid-lab`, ADR 0079, 0080); gate B1 met 2026-11-22; T2's 12 windows in `lab/`; code-owned |
| Collector, store, shard (0005, 0007, 0013, 0016, 0017, 0029) | Laurel's records into sealed SQLite shards under a cap | on `main`, code-owned; frozen (ADR 0076), the collector kept in the range image |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030-0032) | signed log, cosigned off the host | on `main`; frozen until an agent on the host gets root (ADR 0076 point 5) |
| Installer, CLI (0048, 0053, 0058, 0068) | signed install of a component; `balistid status` | on `main`; recorder installed on the host 2026-11-14 |

## Done in the last sessions
- This pull request, T2: 12 runner jobs (3 pairs x 4 runs, 16 of the pilot's 23 results after the anchor), imported
  byte for byte, `verify` passes. tmp-hidden counted: Fable, Opus, Sonnet and GPT-6.2 Sol 3/3 rules catch both
  variants and stay quiet on both twins, Haiku and GPT-6 Astra 1/3, GPT-6.1 Terra 0/3. time-now counted: 0 of 22
  rules tell the technique from its twin (every rule that catches is as noisy, it names the program). env-locale not
  measured: its scripts need grep, the image has none (exit 127). Cross rows: 0 NOISY of 305. Raw k/3, no ranking.
- #309 (ADR 0080): the judge compares strings as Laurel decodes to (`%25` is `%`), merged before these windows;
  the time-now reference failed on tech-b before it. Port equal to Laurel's Rust on 27M inputs; 0 of 44 mutants live.
- #305, #306, #308: T1, blind rules from 7 models (Gemini via its API, n=1, then excluded after HTTP 503), the hard
  pair time-now (T1124) from Codex; #307 the authors' harness in `tools/lab/`.
- Older (#293-#299, gate B1 on dev-read): git log.

## Next step
1. Pilot report B2 by 2026-11-27: what tmp-hidden and time-now measure and do not (n=3 per model, briefs that name
   the flag, the GPT family shares the pairs' author, Gemini excluded, time-now's twins also print time and zone);
   cite SIGMERGE, CTI-REALM, CAMLIS. Before the next T1, a pair merges only if its commands are in the image.

## Open decisions (maintainer)
- Approve this pull request (`STATUS.md`, the T2 windows).
- #202 (default caps) and #240 (other rules files) wait with the frozen recorder (ADR 0076).
