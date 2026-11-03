# Status

Updated: 2026-11-03 by claude/opus-5.5 (#233 trials at the shipped queue, ADR 0056)

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
- #233: trials run the shipped 64 MiB queue, only `loss-queue` lowers it at runtime (ADR 0039 pt 2); `rss_mib` needs
  it. KVM: rss-burst ~113 MiB, rss-1000 ~123 MiB, loss-queue-1/-2 PASS; rate trials INVALID only on GitHub's steal.
- #229 (#199, ADR 0054): range trials decide `canary_interval_s` (CanaryEvery 29 s; Laurel and auditd frozen in turn)
  and `rss_mib` (rss-1000, rss-burst, rss-large at 1 exec/s of 2 MB, VmHWM, OOM as MISS, control rss-oom-control
  MISS). Store reads wait for an idle audit (rate-burst no longer misses its barrier); host lines in CI logs.
- #230: archive.archlinux.org downloads (pacman download, mkosi build) get three tries; #225 a flaky freeze test.
- ADR 0051 (holes to milestones), 0052 (metric deciders), 0053 (FIDO2 manifests), 0055 (a floor closes with
  /security-audit and a deletion pass), 0056 (9.5 on the maintainer's host first). Laurel upstream #313, #314.
## Next step
1. Range: per-second steal windows for the rate and CPU trials, judged only against a MISS (an ADR first); today a
   steal-heavy part of a run can hide in the sum of the rest.
2. 9.5 (ADR 0051): #196 installer (ADR 0053), #197, #198, #201-#204, #213's trial and fact; C3 2026-11-10 (#200).
   Floor 0 closes with ADR 0055's two passes.
## Open decisions (maintainer)
- #194: an OK report the collector can neither rewrite nor remove stands up to 5 s (accepted, acceptance/0.toml);
  the report's tmpfs pages count in the collector's MemoryMax.
- #142: seal continuity left to the Pi (appends wait ~45 ms on btrfs). #148: `-final` ends anchoring until rollover.
  #207: the ledger socket's local flood accepted in T2 (maintainer, 2026-11-02).
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #170: another writer filling the store's fs past its statfs check: SQLITE_FULL, UNKNOWN (ADR 0016 pt 4); T10 residual.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial:
  as before (git log of this file).
