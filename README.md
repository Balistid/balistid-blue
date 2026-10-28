# Balistid Blue

Balistid Blue is a local-first security control plane for a single Linux host on x86-64. It does not ship its own
sensors. It runs maintained open-source security tools under one command layer and turns their
output into a small number of cases a single person can understand and act on.

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
| `internal/buildinfo/` | Version string stamped at release build |
| `internal/rangevm/` | Range sandbox, QEMU argv, results parser, verdict, build and retention |
| `internal/rangeguest/` | Parsers for what the guest reads: auditctl, /proc, Laurel JSON, auditd state |
| `internal/rangejob/` | Contract between agents and the range runner, starting with the inbox request |
| `internal/rangerun/` | The range runner: its record of the inbox (one run per job name and content in 30 days) and quota; it never changes the inbox |
| `internal/anchor/` | The ledger's log: the collector's stream as typed entries in Tessera, signed checkpoints, resume from the log's tail (ADR 0027) |
| `internal/entry/` | The ledger's log entries: typed events of hashes and ranges, their byte encoding and strict decoding (ADR 0026) |
| `internal/link/` | The wire between collector and ledger: typed, length-prefixed frames, decoded strictly (ADR 0027) |
| `internal/rawrecord/` | The stored evidence record: its byte encoding, leaf hash and truncation (ADR 0005) |
| `internal/shard/` | Raw records in one SQLite file per shard: append with gap-free seq, seal, verified read (ADR 0005) |
| `internal/store/` | Shards under a cap: rotation, loss records, reserve, the seal index and recovery after a crash (ADR 0005, 0013) |
| `internal/collector/` | Collector: Laurel's lines to records as evidence, a byte-bounded queue that never blocks Laurel, loss counted per stage (ADR 0016) |
| `internal/unixsock/` | What every service needs from its local sockets: the peer's uid from the kernel, messages to systemd (ADR 0007) |
| `deploy/audit/` | Audit rules; the range image uses them, `balistid-install` will (ADR 0004) |
| `deploy/auditd/` | auditd configuration and the Laurel plugin entry |
| `deploy/laurel/` | Laurel configuration |
| `deploy/sysctl/` | Kernel settings (io_uring disabled) |
| `deploy/collector/` | Collector's socket and service units, its user and directories (ADR 0016, 0017) |
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
