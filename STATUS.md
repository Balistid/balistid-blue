# Status

Updated: 2026-11-02 by claude/opus-5.5 (#206: shard.Read reads the copy it hashed, this PR, ADR 0050)

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
- This PR (ADR 0050, #206): `shard.Read` reads only an unnamed copy it hashed while making (modernc vfs), so the
  collector's uid can no longer swap or rewrite what a reader takes as sealed; the guest copies to its /tmp.
- #194 (ADR 0048): `balistid status [--json]` shows each floor-0 unit from `systemctl show` and the collector's health from a
  74-byte report in /run/balistid-collector (0644, read by owner, size, age at most 5 s); OK only when every part is.
  Trials status-1/2 break each unit, freeze auditd and Laurel; the judge checks every CLI call against the store's
  health and lets a MISS outrank INVALID. KVM PASS at 88d1310 (both); Opus critic CLOSED; Codex F1 accepted (acceptance).
- #195: the Pi's state refuses bytes after its object. #214 (ADR 0049): accepted limits folded into T11, T21, T27,
  T28 and the scope (local mode); cap 13200 B. Residual triage: issues #196-#213, label `residual`, by milestone.
- Merge queue on (ADR 0041 point 2, maintainer 2026-11-02): rebase, one PR at a time, strict off.
## Next step
1. Before /security-audit, milestone `security-audit`: #207 ledger socket, #208.
2. /security-audit of floor 0 (maintainer), then 9.5 (#196-#205, #213) when every range metric and the product bar pass;
   `range-kvm` required after a week of runs (0028); 2026-11-10 C3 = B4.9 (reinstall, suite).
## Open decisions (maintainer)
- #194: an OK report the collector can neither rewrite nor remove stands up to 5 s (accepted, acceptance/0.toml);
  the report's tmpfs pages count in the collector's MemoryMax.
- #142: seal continuity left to the Pi (appends wait ~45 ms on btrfs). #148: `-final` ends anchoring until rollover.
  #207: the ledger socket's local flood accepted in T2 (maintainer, 2026-11-02).
- #123: the module cap measures after the download; a real bound needs a quota filesystem or a watcher (T36).
- #170: another writer filling the store's fs past its statfs check: SQLITE_FULL, UNKNOWN (ADR 0016 pt 4); T10 residual.
- #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed collector's INVALID trial,
  unpinned shellcheck: as before (git log of this file).
