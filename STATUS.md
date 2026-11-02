# Status

Updated: 2026-11-02 by claude/opus-5.5 (#216, #217, #218 merged; #219 found; ADR 0041's checks hold)

## Where we are

Floor 0 (recorder) is done when `acceptance/0.toml` is met. `python3 tools/ci/status.py` shows this file
next to the ADRs, the runner's results and open pull requests, and warns where they disagree. Its parts:
| Part | Does | State |
|---|---|---|
| Sensor (ADR 0004) | auditd + Laurel record kernel events | configured |
| Range, runner (0009-0011, 0018-0021, 0028) | VM where agents test the recorder; the runner runs the acceptance suite itself | installed at 2c09799; CI job `range-kvm` self-tests every pull request on GitHub's KVM (#146, advisory); on `main` (#131, #132): the collector in the image, the guest reads its sealed shards, trials decide metrics (ADR 0022) |
| Raw record, shard (0005) | record encoding and leaf; sealed SQLite file | on `main`, code-owned (#127) |
| Store (0005, 0013, 0029) | cap, reserve, loss records, seal index, retirement | on `main`, code-owned; `Committed` (#128); index v2 and retirement by cosign time and the host clock on `main` (#147, L7) |
| Collector (0007, 0016, 0017) | takes Laurel's records over a socket, never blocks Laurel | on `main` with units, code-owned; A7 closed (#125); range-only `-log-commits` and `-headroom` (#128) |
| Ledger, relay, Pi witness (0006, 0026, 0027, 0030, 0031) | signed log, cosigned off the host | ledger core on `main` (#142, ff8398c): ADR 0027, `internal/anchor`, `internal/link`, collector stream, `balistid-ledger`, deploy, range fact `ledger_anchored` (KVM PASS at bf95659); relay (`internal/relay`, `balistid-relay`, deploy) with a pinned litewitness in the range on `main` (#144, 2e2f7de): `ledger_cosigned`, `fork_refused` (KVM PASS at 4fd6db0); announce, final, rollover, old-log retention on `main` (#148, b4d9ca3); the Pi's watcher `balistid-pi` and the relay's bundle server (ADR 0031) on `main` (#150, 3a6d88b), range fact `pi_verified`; L10 on `main` (#153, 6854cdf; ADR 0032): `balistid-net`, the relay-only nftables table and the WireGuard tunnel, facts `pi_reach`, `ledger_net` |
| Normalizer, CLI (0005, 0007, 0048) | OCSF view, `balistid status` | normalizer not started; `balistid status` and its report on `main` (#194) |
## Done in the last sessions
- #216 (ADR 0050, #206): `shard.Read` reads only an unnamed copy it hashed while making (modernc vfs), so the
  collector's uid can no longer swap or rewrite what a reader takes as sealed; the guest copies to its /tmp. All 63
  trials on 2a64d1b: none worse than `main` (full-fs and the 909147-record sustained store read through the copies);
  Opus critic CLOSED after one reply round; Codex left out by the maintainer (usage against the change's size).
- #217: the ledger socket's local flood accepted in T2 (#207). #218: shellcheck pinned by sha256 (#208).
- ADR 0041's checks hold: the bot's direct `PUT .../merge` refused (405, "must be made through the merge queue"),
  `main` ends at each group's `head_sha` (#195, #214, #215 alone, #216-#218 queued together), history linear.
- #219: `record-max` misses on `main` too (the 2 MB exec stored twice), found by the full suite.
- #194 `balistid status` (ADR 0048), #195, #214 (ADR 0049), residual issues #196-#213: as before (git log).
## Next step
1. /security-audit of floor 0 (maintainer); #219 before 9.5 (a floor-0 metric that misses).
2. 9.5 (#196-#205, #213) when every range metric and the product bar pass: #199 and #213 first (agent), #197, #201,
   #204 are the maintainer's decisions; 2026-11-10 C3 = B4.9 (reinstall, suite, verdicts; #200).
## Open decisions (maintainer)
- #194: an OK report the collector can neither rewrite nor remove stands up to 5 s (accepted, acceptance/0.toml);
  the report's tmpfs pages count in the collector's MemoryMax.
- #142: seal continuity left to the Pi (appends wait ~45 ms on btrfs). #148: `-final` ends anchoring until rollover.
  #207: the ledger socket's local flood accepted in T2 (maintainer, 2026-11-02).
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #170: another writer filling the store's fs past its statfs check: SQLITE_FULL, UNKNOWN (ADR 0016 pt 4); T10 residual.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial:
  as before (git log of this file).
