# Status

Updated: 2026-11-08 by claude/opus-5.5 (#272 OSV, #273 ADR 0069, mutation required; #270 waits for the key)

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
- #273 (e0b044e, ADR 0069, #213): `anchor-sustained` (largest gap between the ledger's batch entries under the
  sustained load, at most 1000 ms) with the control `anchor-control-stall`, and `truncation-11`/`truncation-10`
  (one `truncated` alert within 65 s of the 11th oversized record, none for 10). KVM: truncation PASS; anchor INVALID
  on GitHub's runner (steal), so the host runner decides it; a voided run measured 2100 ms over 658 batches.
- #272 (2e9edba): the 12 OSV advisories Scorecard counted cleared (x/crypto, otel, the range witness's x/net and Go
  1.27.3); govulncheck also scans the witness programs. `mutation` (ADR 0066) is a required check since 2026-11-08.
- #270 (draft on its branch, ADR 0068, replaces #238): `balistid-install recorder`; critic and Codex CLOSED;
  CI red only for `deploy/install/allowed_signers` until the maintainer's key.
- #207, #245, #250, #242, #236: as before (git log of this file).
## Next step
1. #270: the maintainer's FIDO2 key, `deploy/install/allowed_signers`, README row and fingerprint (2026-11-09), CI,
   approve, merge; then the host: Laurel, the boot entry's audit options, other rules out of `rules.d`, the
   bootstrap, a reboot (ADR 0068). The 7 days start there (ADR 0064, #201).
2. 9.5 before the 7 days end: #274 (the guest counts ledger entries not proven against the signed checkpoint),
   #275 (a replayed result stream), #203, #204, #199, #200, #202, #244, #252; after install #243, #245-#248.
   Then ADR 0055's two passes and ADR 0067's red team.
## Open decisions (maintainer)
- #275: bind range evidence to the run, or state in THREAT_MODEL.md that the range trusts the image it builds.
- #202 (yearly log alone fills `disk_default_gib`) and #244 (Laurel 0.8.2 without #313).
- #240: other files in the host's `/etc/audit/rules.d` read `rules-differ` once installed (ADR 0068 refuses them).
- #194, #142, #148, #123, #170, #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed
  collector's INVALID trial: as before (git log of this file).
