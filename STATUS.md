# Status

Updated: 2026-11-15 by claude/opus-5.5 (version A measured on the host; release-number guard, ADR 0076)

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; CI job `range-kvm` self-tests every pull request on GitHub's KVM (#146, required in the ruleset); on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013, 0029) | cap, reserve, loss records, seal index, retirement | on `main`, code-owned; `Committed` (#128); index v2 and retirement by cosign time and the host clock on `main` (#147, L7) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030, 0031) | signed log, cosigned off the host | ledger core on `main` (#142, ff8398c): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at bf95659); relay (`internal/relay`, `balistid-relay`, deploy) with a pinned litewitness in the range on `main` (#144, 2e2f7de): `ledger_cosigned`, `fork_refused` (KVM PASS at 4fd6db0); announce, final, rollover, old-log retention on `main` (#148, b4d9ca3); the Pi's watcher `balistid-pi` and the relay's bundle server (ADR 0031) on `main` (#150, 3a6d88b), range fact `pi_verified`; L10 on `main` (#153, 6854cdf; ADR 0032): `balistid-net`, the relay-only nftables table and the WireGuard tunnel, facts `pi_reach`, `ledger_net` |
| Normalizer, CLI (0005, 0007, 0048) | OCSF view, `balistid status` | normalizer not started; `balistid status` and its report on `main` (#194) |
## Done in the last sessions
- Version A (dfc833a) installed on the maintainer's host on 2026-11-14, as a measurement only: the store grows
  about 0.34 MB/s (about 28 GiB/day, 1932 B per record on disk: 1465 B data, 359 B unused SQLite page space, 64 B
  hashes), so `capacity_margin` (at most 1.67 GiB/day under the 150 GiB cap) fails and the cap fills on day 5;
  floor-0 CPU about 13 % of a core against `cpu_cores_typical` 0.05. The 7 days (ADR 0075) have not started.
- ADR 0076 (this pull request): `balistid-install` keeps the installed release number and refuses an older signed
  release; MANIFEST v2 carries the number, CI writes it from the store-format pull request on.
- #286, #289, #290: as before (git log of this file).
## Next step
1. A 24 h sample of version A's steady state (records/s, bytes, CPU per unit), then the measurement recorder stops.
   If auditd and Laurel alone exceed 0.05 of a core, the rules are decided before the store format, in one version.
2. Store format v2: one deflate block per commit, the dictionary from the shard's first blocks, the leaf recomputed
   on read, a per-block sum; v1 shards stay readable (simulated on a real shard: about 100 B per record). CI then
   computes the release number from the history and writes MANIFEST v2.
3. Install this release, then the v2 one, one reboot; day 1 must project under 1.67 GiB/day; then the 7 days.
4. 9.5 after the days as ADR 0075 says: #274, #275, #203, #204, #199, #200, #202, #244, #252; after install #243,
   #245-#248; then ADR 0055's two passes and ADR 0067's red team.
## Open decisions (maintainer)
- #202 now, before the store format: `disk_default_gib` 10 cannot hold 30 days of retention at the measured rate;
  a shorter retention after cosigning, fewer events, or a stronger compressor.
- #275, #244, #240, #194, #142, #148, #123, #170, #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on
  4 vCPU, a killed collector's INVALID trial: as before (git log of this file).
