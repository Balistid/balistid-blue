<div align="center">

<h1><picture><source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg"><img src=".github/banner-light.svg" width="420" alt="Balistid Blue"></picture></h1>

**Security for one Linux machine and the AI agents on it, built from open-source tools.**

[![CI](https://github.com/Balistid/balistid-blue/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Balistid/balistid-blue/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Balistid/balistid-blue/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Balistid/balistid-blue)
[![Fuzz](https://github.com/Balistid/balistid-blue/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/Balistid/balistid-blue/actions/workflows/fuzz.yml) [![Licence](https://img.shields.io/github/license/Balistid/balistid-blue)](LICENSE) [![Go version](https://img.shields.io/github/go-mod/go-version/Balistid/balistid-blue)](go.mod) ![Platform: Linux](https://img.shields.io/badge/platform-Linux-555) [![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-b08800)](STATUS.md)

</div>

> [!WARNING]
> This is pre-alpha and does not protect your machine yet. [STATUS.md](STATUS.md) says what works today.

## What Balistid is

Balistid is meant to guard one Linux machine, including from the AI agents that work on it. The plan is to join open-source security tools into one small platform that records what happens, spots an attack, stops it, and checks whether an agent told the truth about what it did. A lab measures which of these parts work, and in the end one light should tell you whether you have to look.

It is for a single person with a single machine, not a company with a security team. It has no sensor of its own and today builds on auditd and Laurel (x86-64). Most of it does not exist yet:

| Part | Question it answers | Today |
|---|---|---|
| Limits | What may an agent do? | planned |
| Record | What happened on the machine? | runs on one machine, none of its targets met yet, frozen (ADR 0076) |
| Detection | Was that an attack? | rules are being measured in the lab |
| Response | Can it be stopped, and undone if that was a mistake? | planned |
| State | What does the machine look like now? | planned |
| Claims | Is what the agent said true? | planned |
| Packages | What did a pacman or AUR package do during install? | planned |
| Lab | Does any of this work? | running, see below |
| Red | How would an attacker get around it? | planned |
| Light | Do I have to look? | planned |

## Testing detections

A rule that fires on an attack is easy to write. The trouble starts when it also fires on normal work. So each attack in the lab has a harmless twin that looks almost the same, and a rule passes only if it catches the attack in both of its variants and ignores both twins. AI models write the rules from a short description, without seeing the commands.

| What an attacker does | Harmless twin | Rules that passed |
|---|---|---|
| List the files in `/tmp`, hidden ones too | List only the visible ones | 14 of 21 |
| Read the current time | Work out when the machine booted | 0 of 22 |

In the second test 17 rules caught the attack at least once, and every one of them flagged a twin too. The numbers are small: three rules from each of seven models, and one from Gemini in the second test. They say nothing about which model is better. A third test could not be measured because its scripts need `grep` and the VM image has none. You can recompute them with Go 1.27:

```sh
git clone https://github.com/Balistid/balistid-blue && cd balistid-blue
go run ./cmd/balistid-lab verify lab   # is the recorded data unchanged?
go run ./cmd/balistid-lab table lab    # what did each rule do on each run?
```

## How it works

On the machine, auditd passes kernel events to Laurel, the collector stores them in SQLite files, and a signed log makes later changes visible. Without a second device that holds only against an attacker who is not root. The code for a witness on a Raspberry Pi is here too. The recorder stays as it is for now, and the log and the witness wait until an agent gets root on the machine (ADR 0076).

In the lab, `balistid-range` boots an Arch Linux VM, the test runs inside, and the host decides the result.

## Plan

The code and the decision records speak of floors: 0 recorder, 1 detection, 2 response, 3 AI agents, 4 packages, 5 daily use and hardening for an AI server. Each should be useful even if the next one never ships.

It will not manage fleets, offer SOC features for many tenants or become a hosted service. It will not add a kernel sensor where auditd, Tetragon, AIDE or YARA do the job, or claim protection that no test has shown.

## Repository map

CI fails when a directory with tracked files has no row here, or a row names something that is not tracked.

<details><summary><b>Open the map</b></summary>

| Path | Purpose |
|---|---|
| `ENGINEERING.md` | Binding engineering rules (R1–R14) for humans and agents |
| `CLAUDE.md`, `AGENTS.md`, `STATUS.md` | Working instructions for Claude Code and Codex; Current floor, next step, open decisions (overwritten, never appended) |
| `THREAT_MODEL.md` | Threats per floor with their control, proof and honest status |
| `adr/` | Architecture decision records, one page each |
| `acceptance/` | Acceptance numbers per floor, committed before the floor's code |
| `cmd/balistid/` | The unprivileged command-line client (`version` and `status`) |
| `cmd/balistid-range/`, `cmd/balistid-range-guest/` | Range launcher: `build` an image, `run` it once (ADR 0009); Program inside the range VM that checks isolation and the sensor |
| `cmd/balistid-runner/` | Range runner: `build` its image at install, `tick` one evidence run or agent job (ADR 0011) |
| `cmd/balistid-collector/` | Collector daemon: the socket systemd passes, Laurel's lines into the raw store (ADR 0016, 0017) |
| `cmd/balistid-ledger/` | Ledger daemon: the collector's stream into the signed log, over its own socket (ADR 0027) |
| `cmd/balistid-auditstat/` | auditstat daemon: the kernel's audit status every 5 s, the one process with CAP_AUDIT_CONTROL (ADR 0038) |
| `cmd/balistid-relay/` | Relay daemon: the ledger's checkpoints to the witness, the cosigned one kept (ADR 0006, 0026) |
| `cmd/balistid-pi/` | The Pi's watcher daemon: verifies the log against the Pi's witness, alerts the phone through ntfy (ADR 0031) |
| `internal/buildinfo/` | Version string stamped at release build |
| `internal/rangevm/` | Range sandbox, QEMU argv, results parser, verdict, build and retention |
| `internal/rangeguest/` | Parsers for what the guest reads: auditctl, /proc, Laurel JSON, auditd state |
| `internal/rangejob/`, `internal/rangerun/` | Contract between agents and the range runner, starting with the inbox request; The range runner: its record of the inbox (one run per job name and content in 30 days) and quota; it never changes the inbox |
| `cmd/balistid-lab/`, `internal/detect/`, `lab/` | The detection judge and the pilot's data it reads: pairs, rules, imported windows; `job`, `import`, `table`, `verify` (ADR 0077-0080) |
| `internal/anchor/`, `internal/entry/` | The ledger's log: the collector's stream as typed entries in Tessera, signed checkpoints, resume from the log's tail (ADR 0027); The ledger's log entries: typed events of hashes and ranges, their byte encoding and strict decoding (ADR 0026) |
| `internal/relay/`, `internal/cosign/` | The ledger's checkpoints to the witness (c2sp.org/tlog-witness) and back its verified cosignature, the entry bundles to the Pi; holds no signing key (ADR 0006, 0026, 0031); The checkpoint the witness cosigned, verified with both keys; the witness's time from its signed line (ADR 0029) |
| `internal/watch/` | The Pi's side of the log: root recomputed from the relay's bundles, the log's rules, alarms, push (ADR 0031) |
| `internal/link/`, `internal/rawrecord/` | The wire between collector and ledger: typed, length-prefixed frames, decoded strictly (ADR 0027); The stored evidence record: its byte encoding, leaf hash and truncation (ADR 0005) |
| `internal/shard/`, `internal/store/` | Raw records in one SQLite file per shard: append with gap-free seq, seal, verified read (ADR 0005); Shards under a cap: rotation, loss records, reserve, the seal index and recovery after a crash (ADR 0005, 0013) |
| `internal/collector/` | Collector: Laurel's lines to records as evidence, a byte-bounded queue that never blocks Laurel, loss counted per stage (ADR 0016) |
| `internal/status/` | What `balistid status` shows: floor-0 units from systemd, the collector's health report (ADR 0048) |
| `internal/unixsock/`, `internal/wholefile/` | What every service needs from its local sockets: the peer's uid from the kernel, messages to systemd (ADR 0007); Files written whole: temp file, fsync, rename, directory fsync (ENGINEERING.md 7) |
| `internal/auditstat/` | The kernel's audit status over netlink, strictly decoded, and the fixed report auditstat writes for the collector (ADR 0038) |
| `cmd/balistid-install/`, `internal/install/`, `deploy/install/` | `balistid-install`: installs a component only from a MANIFEST the maintainer's FIDO2 key signed, each file checked; compare the key's `SHA256:tbzX99QWbavyFXa2EQ3Ka5kchy7MJh+MPpjEirTZjlI` before the first install (ADR 0053, 0058) |
| `deploy/audit/` | Audit rules; the range image and `balistid-install`'s recorder install them (ADR 0004, 0068) |
| `deploy/auditd/`, `deploy/laurel/`, `deploy/sysctl/` | auditd configuration, the Laurel plugin entry, Laurel's configuration and the kernel settings (io_uring disabled) |
| `cmd/balistid-judge/`, `deploy/judge/` | The judge: a oneshot as the collector's uid that will judge the recording days from the sealed store, not built yet (ADR 0074) |
| `deploy/collector/`, `deploy/ledger/`, `deploy/auditstat/` | Collector's socket and service units, its user and directories (ADR 0016, 0017); Ledger's service unit, its user and log directory (ADR 0027); auditstat's service unit, its user and its report's group (ADR 0038) |
| `deploy/relay/`, `deploy/net/` | Relay's service unit and its user; it reaches only the Pi's end of the tunnel (ADR 0026, 0031, 0032); The firewall that lets only the relay's uid reach the Pi, the WireGuard tunnel to it, and its user (ADR 0032) |
| `deploy/announce/`, `deploy/pi/` | Units that announce a clean shutdown or suspend through the ledger's control socket (ADR 0030); The Pi's watcher unit, its failure alert and its user, installed on the Pi by hand (ADR 0031) |
| `deploy/runner/` | Range runner's build and tick units, timer, users and directories; `balistid-install` installs them (ADR 0011, 0058) |
| `packaging/laurel/` | PKGBUILD for the pinned Laurel release binary |
| `range/` | mkosi configuration and guest unit of the range image |
| `tools/ci/`, `tools/lab/` | Repository gates (layout and this map, commit lint, pins, secrets, Go), the runner's release manifest, root probes on CI's systemd (`probe_*.py`), their tests; the pilot's blind rule authors (T1) |
| `githooks/`, `.github/` | Local hooks (CI is the authority, they give earlier feedback); CI workflow, code owners, issue and pull request templates |

</details>

## License

Apache License 2.0, see `LICENSE`.
