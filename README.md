<div align="center">

<img src="https://avatars.githubusercontent.com/u/336239940?v=4&s=192" width="96" alt="Balistid logo"><h1>Balistid Blue</h1>

**Open-source security tools under one light layer. No detection counts until the lab has measured it.**
For one Linux host. Local first. No sensor of its own.

[![CI](https://github.com/Balistid/balistid-blue/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Balistid/balistid-blue/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Balistid/balistid-blue/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Balistid/balistid-blue)

</div>

> [!WARNING]
> **Pre-alpha: it does not protect a host yet.** It records on one machine, below its own acceptance numbers, and
> measures detections in a VM. Where we are: `STATUS.md`. Why: ADR 0076.

## The idea

Six questions Balistid is meant to answer about what runs on the host, AI agents first:

```mermaid
flowchart LR
  A["Allowed?<br/>may it"]:::plan --> B["Done?<br/>did it"]:::now --> C["State?<br/>is it so"]:::plan --> D["Honest?<br/>is it true"]:::plan
  D --> E["Proven?<br/>does it work"]:::now --> F["Act?<br/>do I need to"]:::plan ~~~ G[" "]:::none
  classDef none fill:transparent,stroke:transparent,color:transparent
  classDef now fill:#1f6feb,stroke:#1f6feb,color:#ffffff
  classDef plan fill:transparent,stroke:#8b949e,stroke-dasharray:5 4
```

Solid: code on `main` today, recording and the lab. Dashed: planned, not built.

## Measured, not claimed

A detection counts only if it catches an attack **and** stays quiet on its twin: a harmless run that looks alike.
Models write the rules blind, VM runs give the records, a judge on the host gives the verdict. Recompute it:

```sh
git clone https://github.com/Balistid/balistid-blue && cd balistid-blue
go run ./cmd/balistid-lab verify lab   # every imported window, byte for byte
go run ./cmd/balistid-lab table lab    # every rule, every verdict
```

Pilot, raw counts, three rules per model (one from Gemini): on `tmp-hidden` 14 of 21 rules do both, on `time-now` 0 of 22. Small samples, no ranking, one pair not measured; more in `STATUS.md`.

## Floors

Each floor must be useful on its own, even if the next one never ships.

| Floor | What it gives you | Today |
|---|---|---|
| 0 Recorder | A tamper-evident timeline of what happened on the host | On one host, unmet, frozen (ADR 0076) |
| 1 Detection | An alert on the phone, proven by an attack it must catch and normal work it must not | Measured in the lab |
| 2 Response | Contain what a proven detection found, explained and reversible | Planned |
| 3 AI agent actor | AI coding agents as first-class actors: normal work told apart from abuse | Planned |
| 4 Package actor | What a pacman or AUR package did when it was installed | Planned |
| 5 UX and AI server | Explained verdicts, an interruption budget, a nightly report; a hardened AI server | Planned |

**Built for** one person: a workstation, a homelab, a self-hosted AI server. One install, few interruptions.
**Not for** fleets or SOC teams. **Never** a new kernel sensor where auditd, Tetragon, AIDE or YARA already do the
job, and never a claim of protection without a test that fails when the protection is removed.

## How it fits together

Range: `balistid-range` boots an Arch image once in QEMU inside bwrap and turns the guest's facts into a verdict
(ADR 0004, 0009). Floor 0: auditd → Laurel → collector → SQLite shards → signed ledger → relay → Raspberry Pi witness
(ADR 0005-0007, 0027, 0031), run on KVM for pull requests (`range-kvm`, ADR 0028). Why lives in `adr/`, risks in `THREAT_MODEL.md`.

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
