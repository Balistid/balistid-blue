# Threat model — floor 0 (recorder)

Scope: one Arch Linux host recording through auditd and Laurel (ADR 0004), raw SQLite shards (0005),
a Tessera log cosigned and watched from a Raspberry Pi (0006), five processes (0007). Detection and
response start on floor 1 and get their own rows then. Each row names its ADR and its proof in
`acceptance/0.toml` (`[metric]` ids) or a test. Status: covered, partial, gap (floor that closes it).

## Assets

Raw records and sealed shards; the Merkle log and the witness's cosigned checkpoints; the log signing
key; the truth of health and loss signals; the alert channel to the maintainer's phone.

## Actors

- **A1 agent**: an AI agent or malware running as the maintainer's uid. The main adversary.
- **A2 root**: anyone with root on the host, including A1 after a privilege escalation.
- **A3 input**: crafted records or responses that target a parser or protocol bug.
- **A4 network**: anyone on the local network or the phone hotspot uplink.
- **A5 supply chain**: a malicious or broken dependency, toolchain, Laurel release or package.
- **A6 failure**: crash, power loss, full disk, kernel upgrade, Pi failure.

## Trust boundaries

Kernel ↔ auditd/Laurel (OS, root) ↔ collector socket (Laurel uid only) ↔ Kordon service uids ↔
maintainer uid (A1) ↔ WireGuard (relay uid only) ↔ Pi. Root on the host is trusted by every process
there; only the Pi and the phone are outside its reach.

## Threats

| ID | Actor | Threat | Floor-0 control | Proof | Status |
|---|---|---|---|---|---|
| T1 | A1 | Alter or delete shards, keys, units or config | Service uids own them (0007) | test `perm_matrix` | covered |
| T2 | A1 | Impersonate Laurel or read the raw stream | `SO_PEERCRED` allowlists (0004, 0007) | test `peer_refused` | covered |
| T3 | A1 | Act through io_uring, unseen by exit rules | io_uring disabled or audited (0004) | smoke test | covered |
| T4 | A1 | Flood audit to cause loss or fill the store | Loss events, cap drops new, Pi alarm | `pi_alarm_s` | partial: blind during flood, not silent |
| T5 | A1 | Change audit rules or disable audit | Needs root; `-e 2`; rule check (0004) | test `rules_locked` | covered vs A1 |
| T6 | A1 | Read secrets in recorded command lines | Raw stream closed to A1; derived DB readable | — | gap: redaction (normalizer ADR) |
| T7 | A1 | Read or delete alerts | Push to phone, not read on host | assumption | assumption |
| T8 | A2 | Rewrite or roll back cosigned history | Witness refuses; Pi verifies (0006) | test `fork_refused` | covered |
| T9 | A2 | Alter, drop or replace records not yet cosigned | — | `cosign_interval_s` bounds it | gap: window per interval |
| T10 | A2 | Blind the sensor, forge health or loss entries | — | — | gap: no floor assigned yet |
| T11 | A2 | Delete evidence and pass it off as retention | — | — | gap: no floor assigned yet |
| T12 | A3 | Parser or protocol bug gains privilege or key | Unprivileged parsers, key without network | test `caps_matrix` | covered by design |
| T13 | A3 | Crafted records exhaust memory or disk | Size-capped records, caps (0005) | `rss_mib`, caps | covered |
| T14 | A4 | Reach the witness, relay or Pi | WireGuard, relay-uid firewall (0006) | test `pi_reach` | covered |
| T15 | A5 | Malicious dependency or toolchain | Pins, sha256, reproducible build, govulncheck | CI | partial: Laurel is trusted |
| T16 | A6 | Crash or power loss loses committed records | WAL `FULL`, sealing barrier (0005) | `crash_loss_ms` | covered |
| T17 | A6 | Loss between Laurel and collector | Reconnect events (0004) | — | gap: not fully measurable |
| T18 | A6 | Kernel upgrade breaks the sensor | Results bound to versions, UNKNOWN (0004) | smoke test | covered |
| T19 | A6 | Pi dies or loses power | — | — | gap: external dead-man switch |
| T20 | A6 | Host offline, so the Pi cannot tell outage from attack | Alarm after a limit | `pi_alarm_s` | partial |

## Assumptions

The kernel, firmware and boot chain are not compromised. The maintainer reads alerts on the phone,
not on the host, and holds the Pi's admin credentials off the host. auditd and Laurel are trusted
OS components (R13 exception in ADR 0004). A gap stays listed until a floor closes it with a test.
