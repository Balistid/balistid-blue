# Balistid Blue

Balistid Blue is a light, local-first security control plane for Linux hosts on x86-64. It ships no sensor of its
own: it runs maintained open-source security tools under one command layer, keeps a history whose tampering a
witness off the host can prove (an optional higher level), and explains each verdict to the person who acts on it.

Status: pre-alpha. Nothing here is ready to protect a machine yet. See `STATUS.md`.

## Why

Single-host Linux users (developer workstations, homelabs, a self-hosted AI server) get either
nothing or tooling built for a SOC team: a manager, an indexer, a dashboard and a full-time analyst.
Balistid Blue aims at the opposite end: one install, sane defaults, few interruptions, and every verdict
explained.

## What makes it different

1. **Provable history.** The core is an event record whose tampering is detectable, with checkpoints
   anchored off the host (for example on a Raspberry Pi witness).
2. **Detections are proven, not assumed.** Every detection ships with an attack scenario that must
   trigger it and a legitimate scenario that must not, replayed in CI and run in an isolated VM range.
3. **Actors, not just events.** Package transactions (pacman/AUR), AI coding agents, AI server
   services and the administrator are modelled as actors on top of the same record.
4. **Built for one person.** Explained verdicts, an interruption budget and a nightly report instead
   of a real-time wall of alerts.

## Floors

Each floor must be useful on its own, even if the next one never ships.

| Floor | Name | Value on its own |
|---|---|---|
| 0 | Recorder | Trustworthy, tamper-evident timeline of what happened on the host |
| 1 | Drill | Automated proof that detections fire on real techniques in a VM |
| 2 | Package actor | What a pacman/AUR package actually did when it was installed |
| 3 | UX | Explained verdicts, interruption budget, nightly report |
| 4 | AI server profile | Hardening and monitoring for a self-hosted AI server |
| 5 | AI agent actor | AI coding agents observed as first-class actors |

## Non-goals

- Writing a new kernel sensor where auditd, Tetragon, AIDE, YARA or similar already do the job.
- Fleet management, multi-tenant SOC features or a hosted service.
- Claiming protection that has not been demonstrated by a test that fails without it.

## How it fits together

Today: `balistid-range build` packs the sensor configuration from `deploy/` and the
Laurel package into an Arch image; `balistid-range run` boots it once in QEMU inside bwrap, the guest checks
the sensor and writes facts to a raw results disk, and the host turns them into a verdict (ADR 0004, 0009).
Planned for floor 0: auditd → Laurel → collector → raw SQLite shards → ledger → Raspberry Pi witness
(ADR 0005–0007). Each decision lives in one place: why in `adr/`, where we are in `STATUS.md`, what can go
wrong in `THREAT_MODEL.md`, the numbers in `acceptance/`, and what lives where in this map.

## Repository map

CI fails when a directory with tracked files has no row here, or a row names something that is not tracked.

| Path | Purpose |
|---|---|
| `ENGINEERING.md` | Binding engineering rules (R1–R14) for humans and agents |
| `CLAUDE.md`, `AGENTS.md` | Working instructions for Claude Code and Codex |
| `STATUS.md` | Current floor, next step, open decisions (overwritten, never appended) |
| `THREAT_MODEL.md` | Threats per floor with their control, proof and honest status |
| `adr/` | Architecture decision records, one page each |
| `acceptance/` | Acceptance numbers per floor, committed before the floor's code |
| `cmd/balistid/` | The unprivileged command-line client (today only `version`) |
| `cmd/balistid-range/` | Range launcher: `build` an image, `run` it once (ADR 0009) |
| `cmd/balistid-range-guest/` | Program inside the range VM that checks isolation and the sensor |
| `cmd/balistid-runner/` | Range runner: `build` its image at install, `tick` one evidence run or agent job (ADR 0011) |
| `cmd/balistid-collector/` | Collector daemon: the socket systemd passes, Laurel's lines into the raw store (ADR 0016, 0017) |
| `cmd/balistid-ledger/` | Ledger daemon: the collector's stream into the signed log, over its own socket (ADR 0027) |
| `cmd/balistid-auditstat/` | auditstat daemon: the kernel's audit status every 5 s, the one process with CAP_AUDIT_CONTROL (ADR 0038) |
| `cmd/balistid-relay/` | Relay daemon: the ledger's checkpoints to the witness, the cosigned one kept (ADR 0006, 0026) |
| `cmd/balistid-pi/` | The Pi's watcher daemon: verifies the log against the Pi's witness, alerts the phone through ntfy (ADR 0031) |
| `internal/buildinfo/` | Version string stamped at release build |
| `internal/rangevm/` | Range sandbox, QEMU argv, results parser, verdict, build and retention |
| `internal/rangeguest/` | Parsers for what the guest reads: auditctl, /proc, Laurel JSON, auditd state |
| `internal/rangejob/` | Contract between agents and the range runner, starting with the inbox request |
| `internal/rangerun/` | The range runner: its record of the inbox (one run per job name and content in 30 days) and quota; it never changes the inbox |
| `internal/anchor/` | The ledger's log: the collector's stream as typed entries in Tessera, signed checkpoints, resume from the log's tail (ADR 0027) |
| `internal/entry/` | The ledger's log entries: typed events of hashes and ranges, their byte encoding and strict decoding (ADR 0026) |
| `internal/relay/` | The ledger's checkpoints to the witness (c2sp.org/tlog-witness) and back its verified cosignature, the entry bundles to the Pi; holds no signing key (ADR 0006, 0026, 0031) |
| `internal/cosign/` | The checkpoint the witness cosigned, verified with both keys; the witness's time from its signed line (ADR 0029) |
| `internal/watch/` | The Pi's side of the log: root recomputed from the relay's bundles, the log's rules, alarms, push (ADR 0031) |
| `internal/link/` | The wire between collector and ledger: typed, length-prefixed frames, decoded strictly (ADR 0027) |
| `internal/rawrecord/` | The stored evidence record: its byte encoding, leaf hash and truncation (ADR 0005) |
| `internal/shard/` | Raw records in one SQLite file per shard: append with gap-free seq, seal, verified read (ADR 0005) |
| `internal/store/` | Shards under a cap: rotation, loss records, reserve, the seal index and recovery after a crash (ADR 0005, 0013) |
| `internal/collector/` | Collector: Laurel's lines to records as evidence, a byte-bounded queue that never blocks Laurel, loss counted per stage (ADR 0016) |
| `internal/unixsock/` | What every service needs from its local sockets: the peer's uid from the kernel, messages to systemd (ADR 0007) |
| `internal/wholefile/` | Files written whole: temp file, fsync, rename, directory fsync (ENGINEERING.md 7) |
| `internal/auditstat/` | The kernel's audit status over netlink, strictly decoded, and the fixed report auditstat writes for the collector (ADR 0038) |
| `deploy/audit/` | Audit rules; the range image uses them, `balistid-install` will (ADR 0004) |
| `deploy/auditd/` | auditd configuration and the Laurel plugin entry |
| `deploy/laurel/` | Laurel configuration |
| `deploy/sysctl/` | Kernel settings (io_uring disabled) |
| `deploy/collector/` | Collector's socket and service units, its user and directories (ADR 0016, 0017) |
| `deploy/ledger/` | Ledger's service unit, its user and log directory (ADR 0027) |
| `deploy/auditstat/` | auditstat's service unit, its user and its report's group (ADR 0038) |
| `deploy/relay/` | Relay's service unit and its user; it reaches only the Pi's end of the tunnel (ADR 0026, 0031, 0032) |
| `deploy/net/` | The firewall that lets only the relay's uid reach the Pi, the WireGuard tunnel to it, and its user (ADR 0032) |
| `deploy/announce/` | Units that announce a clean shutdown or suspend through the ledger's control socket (ADR 0030) |
| `deploy/pi/` | The Pi's watcher unit, its failure alert and its user, installed on the Pi by hand (ADR 0031) |
| `deploy/runner/` | Range runner's build and tick units, timer, users, directories and the script root installs them with (ADR 0011) |
| `packaging/laurel/` | PKGBUILD for the pinned Laurel release binary |
| `range/` | mkosi configuration and guest unit of the range image |
| `tools/ci/` | Repository gates (layout and this map, commit lint, pins, secrets, Go), the runner's release manifest, and their tests |
| `githooks/` | Local hooks; CI is the authority, hooks give earlier feedback |
| `.github/` | CI workflow, code owners, issue and pull request templates |

A code graph (graphify) is deliberately not kept: at this size it would only add something to go stale.
Revisit when floor 0 runs several processes.

## License

Apache License 2.0, see `LICENSE`.
