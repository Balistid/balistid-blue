# Status

Updated: 2026-11-10 by claude/opus-5.5 (ADR 0074: kernel in started and the judge component before install)

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
- ADR 0071 (#275): the range trusts the guest image it builds; a replay is one case of a guest that lies, which only
  host-observed facts would stop (an assumption for T30). ADR 0072 (#204): no alarm gates the recorder's 7 days;
  in local mode the host-to-phone leg is shown with five alerts at the `witness` install; dead-man metrics wait.
- #281 (3f72c75, ADR 0070, #279): starting, not 8, in the collector's first 15 s before auditstat's first report;
  `loss-control-none` PASS on KVM (ADR 0070). #277 (61bd5db, #274) and #280 (bdc0cb5, #278): the range proves the
  ledger's bundles against its signed root and refuses a cap check bundle of another count.
- #270 (59c8bd7, ADR 0068): `balistid-install recorder`; the maintainer's FIDO2 key in `deploy/install/allowed_signers`,
  its fingerprint in the README map, README.md owned. #273, #272, #207, #245, #250, #242: as before (git log).
- #283 (c4350ff, ADR 0073, #201): the collector records its units' CPU in the store, so the days can be judged.
## Next step
1. The host, once ADR 0074's pull request (the started record's `kernel`, the `judge` component) is merged and from
   its bundle: Laurel, the boot entry's audit options, other rules out of `rules.d`, the bootstrap, a reboot.
2. The 7 days (ADR 0064) count from that install; during them `balistid-judge`'s method (ADR 0074 points 2-8),
   installed with `balistid-install judge` without touching the recorder.
3. 9.5 besides: #203, #199, #200, #252; #244 when Laurel releases
   laurel#313 (v0.8.2 is the latest on 2026-11-09). After install #243, #245-#248; then ADR 0055 and 0067.
## Open decisions (maintainer)
- #202: the default caps under 10 GiB, proposed from the 7 days' growth (ADR 0068 point 6 keeps it the maintainer's).
- #240: other files in the host's `/etc/audit/rules.d` read `rules-differ` once installed (ADR 0068 refuses them).
- #194, #142, #148, #123, #170, #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed
  collector's INVALID trial: as before (git log of this file).
