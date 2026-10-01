# Threat model — floor 0 (recorder)

Scope: one Arch Linux host recording through auditd and Laurel (ADR 0004), raw SQLite shards (0005),
a Tessera log cosigned and watched from a Raspberry Pi (0006), five processes (0007). Detection and
response start on floor 1. Each row names its control and its proof in `acceptance/0.toml` or a test.
Status: **designed** (control decided, test not yet passing), **partial** (control leaves a stated
hole), **gap** (no control; the floor meant to close it, or "open"), **assumption**. No row is
"covered" until its test passes in CI or the range.

## Assets and actors

Assets: raw records and sealed shards, the Merkle log and cosigned checkpoints, the signing key, the
truth of health and loss signals, the alert path to the maintainer's phone.
- **A1 agent**: an AI agent or malware at the maintainer's uid. The main adversary.
- **A2 root**: root on the host, including A1 after escalation. Root controls every host process,
  key and network peer, so anything it sends to the Pi is hostile input.
- **A3 input**: crafted records or responses aimed at a parser. **A4 network**: LAN or hotspot.
- **A5 supply chain**: dependency, toolchain, Laurel or package. **A6 failure**: crash, power, disk,
  kernel upgrade, clock, Pi failure.

## Threats

| ID | Actor | Threat | Control | Proof | Status |
|---|---|---|---|---|---|
| T1 | A1 | Alter or delete shards, keys, units, config | Service uids own them (0007) | test perm_matrix | designed |
| T2 | A1 | Impersonate Laurel, squat its socket, read the raw stream | Socket in collector-owned dir, `SO_PEERCRED` | test peer_refused | designed |
| T3 | A1 | Act through io_uring, unseen by exit rules | io_uring disabled or audited (0004) | smoke test | designed |
| T4 | A1 | Flood audit to cause loss or fill the store | Loss entries alarm; cap drops new; maintainer expiry | loss_alarm_s, raw_cap_gib | partial: blind until handled |
| T5 | A1 | Change or disable audit rules | Needs root; `-e 2` (0004) | test rules_locked | designed |
| T6 | A1 | Read secrets in recorded command lines | Raw stream closed to A1; derived DB readable | — | gap: redaction, floor 3 |
| T7 | A1 | Read or delete alerts | Push to phone; no alert client on the host | — | assumption |
| T8 | A1 | Evade recording: ptrace or `process_vm_writev` into own processes, memfd/execveat, interpreters | Rules for ptrace, execveat, memfd_create | drill | partial: interpreters, mmap exec, envp and the middle of truncated argv, floor 1 |
| T9 | A1 | Tamper with the Laurel or Kordon build before install | Builds in CI or range; installer takes rules and binaries from a root-owned checkout, checks sha256 | test install_hash | partial: no R2 hardware key yet |
| T10 | A1 | Fill the shared filesystem so loss records cannot be written | Physically reserved headroom; auditd `disk_full_action` set, `-f 1` | test reserve | designed |
| T11 | A1 | Ptrace, alias or fake the CLI | Host CLI is advisory; truth is the Pi and phone | — | partial: host CLI output can lie |
| T12 | A2 | Rewrite or roll back cosigned history | Witness refuses; Pi verifies (0006) | test fork_refused | designed |
| T13 | A2 | Alter or replace records not yet cosigned | — | — | gap: undetected, window unbounded |
| T14 | A2 | Blind the sensor, forge health, loss or shutdown entries | Announced quiet capped | announced_quiet_max_h | gap: open beyond the cap |
| T15 | A2 | Delete evidence and pass it off as retention | — | — | gap: open |
| T16 | A2 | Attack the Pi through WireGuard, litewitness or tile fetching | Minimal Pi services, pinned and updated | — | partial: Pi parsers are exposed to root |
| T17 | A2 | Start a new log origin to reset history | Pi accepts a new origin only after the old log's final checkpoint | test rollover | designed |
| T18 | A3 | Parser bug in collector or normalizer gains privilege | No capabilities, sandboxed units (0007) | test caps_matrix, fuzz_hours | designed |
| T19 | A3 | Parser bug in the ledger misuses its signing key | Ledger has no network; key only signs checkpoints | fuzz_hours | partial: a compromised ledger can sign |
| T20 | A3 | Crafted records exhaust memory, disk or the refused-request log | Truncated oversize records, store caps, refusal summaries | record_max_kib, rss_mib | designed |
| T21 | A4 | Reach the witness, relay or Pi | WireGuard, relay-uid firewall (0006) | test pi_reach | designed |
| T22 | A4 | Shift the host clock so retention deletes early | Shard age from the cosigned seal time on the Pi | test clock_skew | partial: Pi has no RTC |
| T23 | A5 | Malicious dependency or toolchain | Pins, sha256, reproducible build, govulncheck | CI | partial: Laurel trusted |
| T24 | A6 | Crash or power loss loses committed records | WAL `FULL`, sealing barrier (0005) | crash_loss_ms | designed |
| T25 | A6 | Loss between Laurel and collector | Reconnects are events (0004) | reconnects_per_day | gap: not fully measurable |
| T26 | A6 | Kernel upgrade breaks the sensor, or alarms every week | Results bound to versions; one alarm per kernel | smoke test | designed |
| T27 | A6 | Pi dies, or push delivery fails | — | — | gap: dead-man switch, floor 3 |
| T29 | A1 | Land a secret or untested code via an intermediate commit, a file gitleaks skips, or a swapped toolchain | Layout gate on every commit, rescan of skipped files, pinned toolchain and module hashes (ADR 0003) | tests RangeTest, RescanTest, RescanDetectionTest, ChangeRangeTest, GoCommitsTest, GoGateTest | designed |
| T28 | A6 | Host offline: outage looks like attack | Announced shutdown and suspend; silence alarm | silence_alarm_s | partial: outages alarm too |

## Assumptions

The kernel, firmware and boot chain are not compromised. The maintainer reads alerts on the phone,
runs no alert client on the host and keeps the Pi's admin credentials off the host. auditd and
Laurel are trusted OS components (ADR 0004). A gap stays listed until a floor closes it with a test.
