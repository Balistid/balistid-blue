# Status

Updated: 2026-10-19 by claude/opus-5.5

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799 (evidence PASS; #107 waits for the next install); trial table, failure trials, agent `trial` jobs, acceptance slot (#99-#104); trials are baseline until the collector joins the image |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main` (#56, #63) |
| Store (0005, 0013) | cap, reserve, loss records, seal index | on `main` (#71, #72), hard cap |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | store side #94, core #97; no units (CP3), not in an image (B4) |
| Ledger, relay, Pi witness (0006) | signed log, cosigned off the host | not started |
| Normalizer, CLI (0005, 0007) | OCSF view, `balistid status` | not started |
## Done in the last sessions
- Collector hardening: `ReadSeals` refuses what `Open` refuses; loss records never give way in the health
  queue; stats carry `lost` (ADR 0017); flaky canary tests wait for the probe goroutine.
- Collector CP2 core merged (#97) after Opus critic and Codex review.
- Runner (ADR 0018-0021): trial limits (#99), rate trials (#100), failure trials with host-stamped marks (#101),
  measures beside each verdict (#102), inbox `trial` jobs (#103), the acceptance suite in its own slot (#104).
  ADR 0021: repeated INVALID runs make a metric INVALID, never a MISS. KVM check on 9daa33a: every trial gave its
  expected verdict (sustained 1 200 000 of 1 200 000, burst 100 000 of 100 000). Installed at 2c09799 (#106 shows
  outside records); baselines and an agent job ran by themselves. #107: tripwire probes every denied clause.
## Next step
1. Runner: done until the collector joins the image; install #107 with the next runner change. One baseline run
   counted a record outside the generated set (13 Oct); #106 shows the record when it happens again.
2. Collector CP3, owned: `*.socket` gate, go_gate for the SQLite modules, units, sysusers, tmpfiles; then the Laurel
   spike and B4 (collector and store reader in the image, its trials in the table).
## Open decisions (maintainer)
- The build unit has no syscall filter, yet runs a commit's PKGBUILD and mkosi: its own change.
- Runner: a VM setup error fails the tick (exit 1) on purpose (maintainer, 13 Oct): a broken host shows in systemd.
- Acceptance: a start that fails inside the sandbox wrappers counts as INVALID (ADR 0021, accepted under T36).
- `test_release.py` bootstrap cleanup removes every `/tmp/balistid-install.*`, also other runs'.
- Does `systemd_exposure` (2.5) cover the runner? Install skips .wants/.requires (root-only).
- R2 signing keys; before floor 0's host install: x32 mitigation, io_uring.
- Store: a full filesystem under the cap needs a range test (`headroom_gib`); index format for deleted shards.
- shellcheck in CI is unpinned (`.github/workflows/ci.yml:336`), against R14; a workflow change is the maintainer's.
