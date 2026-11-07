# Status

Updated: 2026-11-07 by claude/opus-5.5 (ADR 0068: the recorder installs first; #238 replaced by feat/install-recorder)

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
- #207 (#255, 2492695): the ledger's socket 0660 in `balistid-ledgerlink`, only its and the collector's units.
- #245 (#256, 9f08f97): range trials show serial gaps: none without loss, one per loss stage; ADR 0062 (proposed).
- #250 (ADR 0061, #241, 986b354): rules v3 (80) record module, kexec, eBPF, mounts by any root uid, handle opens,
  borrowed exes and kept capabilities, io_uring, and every tree's writes and creating or truncating opens; only the
  ledger, relay, runner left out by exe. Fact `tracks` proves each part (pin ab00179, range-kvm 41880683498); 5 review rounds.
- #242 (ADR 0060): holes floor 0 can close are closed on floor 0, issues #243-#249; #240 merged (093418c).
- feat/install-recorder (replaces #238; ADR 0058, 0068, #196): `balistid-install recorder` installs the sensor,
  collector, ledger, auditstat and CLI from a signed bundle, the bootstrap runs it; `runner` as in #238. It refuses a
  host without `audit=1 audit_backlog_limit=65536`, Laurel or the audit tools, or with other `*.rules`. CI red until
  the key commit (no placeholder).
## Next step
1. The recorder's install: review (critic, Codex security), the maintainer's FIDO2 key, `deploy/install/allowed_signers`,
   README row and fingerprint (2026-11-09), CI, approve, merge; #202's caps; then the host: Laurel from
   `packaging/laurel`, the boot entry's audit options, other rules out of `rules.d`, the bootstrap, a reboot (ADR 0068).
   Then the `witness` component (#203, #204) and the runner from the installer.
2. Until the recorder has run 7 days on the host, floor 0 takes no new scope (ADR 0064): 9.5's #244, #201, #203,
   #204, #213, C3 (#200); after install #243 (ADR 0068), ADR 0062's stage 9, #246-#248. Then ADR 0055's two passes.
## Open decisions (maintainer)
- #194: an OK report the collector can neither rewrite nor remove stands up to 5 s (accepted, acceptance/0.toml);
  the report's tmpfs pages count in the collector's MemoryMax.
- #142, #148, #123, #170, #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed
  collector's INVALID trial: as before (git log of this file).
