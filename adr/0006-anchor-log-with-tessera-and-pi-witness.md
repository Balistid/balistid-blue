# 0006 — Anchor the record log with Tessera, cosigned and watched from the Pi

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Root on the host can rewrite local files, fake local health and use any key stored there, so proof
and alarms must come from off the host. C2SP tlog-witness asks a witness to check an RFC 6962
consistency proof before cosigning; a plain hash chain cannot produce one. Tessera v1.0.4
(Apache-2.0, 2026-07-16) is an embedded Merkle log whose POSIX backend writes C2SP tiles and
signed-note checkpoints. litewitness (torchwood v0.10.0, BSD-3, pre-1.0) is a passive witness: it
answers checkpoint submissions and keeps the latest checkpoint per log. The C2SP specs still change.

## Decision

1. `kordon-ledger` (ADR 0007) appends to an embedded Tessera POSIX log. Entries are hashes and
   ranges, never record bodies, each type with its own versioned encoding defined in code with test
   vectors. Loss events and health state are logged as entries too. Checkpoints are signed notes with Ed25519; origin and keys come from `kordon-install`.
2. A witness, litewitness, runs on the maintainer's Raspberry Pi. The host firewall drops traffic to
   every Pi address for uids other than `kordon-relay`; the Pi accepts only its WireGuard peer. The
   host stores no credential that can cosign or silence alerts.
   Submission is outside the append path; recording never waits for the Pi.
3. The Pi fetches tiles over HTTP from the relay (tiles are static files designed for that) and
   runs a small watchdog of ours: if no new cosigned checkpoint arrives, or the log stops growing,
   within the limit, or the latest health entry reports loss or UNKNOWN, it alerts the maintainer by
   push to the phone. litewitness has no alarm of its own.
4. Verification of the log runs on the Pi on a schedule, against the witness's latest checkpoint.
   Host-side output is advisory only.
5. Tessera, torchwood and the spec versions are pinned; CI runs an end-to-end test host → witness.

## Alternatives considered

- Plain SHA-256 chain: no consistency proofs, so no standard witness. Trillian: maintenance mode.
- immudb (BSL, a server), Sigstore Rekor v2 (a public log service), Tessera's inline witness policy
  (a Pi outage would block anchoring), journald sealing (key on the host; kept only as a second trace).

## Consequences

- Claim for floor 0: the witness refuses a rewritten or rolled-back log, and the Pi alarms when
  checkpoints stop. We do not claim completeness, or that root cannot delete, expire or alter
  evidence before it is anchored; the Pi holds hashes only and cannot recover deleted content.
  A dead Pi raises no alarm, and root can forge health entries. `THREAT_MODEL.md` lists these as
  floor-0 gaps, with the assumption that the maintainer does not read alerts on the host.
- Tests: a forked or rolled-back log is refused; with the Pi cut off from the host, or a flood up to
  the store cap, the watchdog alerts within the limit; the relay holds no key; a uid other than the relay cannot reach the Pi.
- The anchoring and cosign intervals, the alarm limit and the caps of tiles, mirror and witness
  state (R5) are numbers in `acceptance/0.toml`; yearly log rollover is part of the lifecycle test.
- A C2SP spec change is an explicit upgrade with the end-to-end test, never a floating dependency.
