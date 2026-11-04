# Status

Updated: 2026-11-04 by claude/opus-5.5 (#250 rules v3 and fact tracks, #242 ADR 0060)

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
- #250 (draft, ADR 0061, #241): rules v3 (80) record module, kexec, eBPF, mounts by any root uid, handle opens,
  borrowed exes and kept capabilities, io_uring, and every tree's writes and creating or truncating opens; only the
  ledger, relay, runner left out by exe. Fact `tracks` proves each part (KVM 716f7f2, pin ab00179); 4 review rounds.
- #242 (ADR 0060): holes floor 0 can close are closed on floor 0; issues #243-#249. #240 merged (093418c).
- #236 (ADR 0057): rate and CPU trials judge guest steal per span of 1-2 s and void PASS and MISS alike (voiding only
  a MISS let reruns pick the PASSes); measure `steal_worst_ppm`. GitHub's runner steals in most seconds: INVALID there.
- #238 (draft, ADR 0058, #196): `balistid-install` installs the runner from MANIFEST v1 signed by the maintainer's sk
  key, flags 0x05 checked in Go; critic CLOSED, Codex findings fixed. CI red until the key commit (no placeholder).
- #233, #229 (ADR 0054), #237 and ADR 0051-0056 as before (git log of this file); Laurel #313 merged upstream.
## Next step
1. #238: the maintainer's FIDO2 key, `deploy/install/allowed_signers`, README row and fingerprint (from 2026-11-07),
   CI, approve, merge, first install; then 9.5's components on the installer with the install ADR (#197 x32 as a
   named, visible gap; #202 caps).
2. 9.5 (ADR 0051, 0060): #242 and #250 approve and merge, #207, #243, #244, #201 (a timer under its own uid), #203, #204 (L12 residuals),
   #213; C3 2026-11-10 (#200). Floor 0 closes with ADR 0055's two passes.
## Open decisions (maintainer)
- #240: other files in the host's `/etc/audit/rules.d` read `rules-differ` once installed; the install ADR decides
  who owns that directory. A kernel or audit change of the rule bytes needs a renewed pin (ADR 0059).
- #194: an OK report the collector can neither rewrite nor remove stands up to 5 s (accepted, acceptance/0.toml);
  the report's tmpfs pages count in the collector's MemoryMax.
- #142, #148, #207, #123, #170, #125, #128, store on btrfs (T10), refusal_summary_s and ready_s on 4 vCPU, a killed
  collector's INVALID trial: as before (git log of this file).
