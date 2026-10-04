# Kordon

Kordon is a local-first security control plane for a single Linux host. It does not ship its own
sensors. It runs maintained open-source security tools under one command layer and turns their
output into a small number of cases a single person can understand and act on.

Status: pre-alpha. Nothing here is ready to protect a machine yet. See `STATUS.md`.

## Why

Single-host Linux users (developer workstations, homelabs, a self-hosted AI server) get either
nothing or tooling built for a SOC team: a manager, an indexer, a dashboard and a full-time analyst.
Kordon aims at the opposite end: one install, sane defaults, few interruptions, and every verdict
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

Today (floor 0, sensor proven): `kordon-range build` packs the sensor configuration from `deploy/` and the
Laurel package into an Arch image; `kordon-range run` boots it once in QEMU inside bwrap, the guest checks
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
| `cmd/kordon/` | The unprivileged command-line client (today only `version`) |
| `cmd/kordon-range/` | Range launcher: `build` an image, `run` it once (ADR 0009) |
| `cmd/kordon-range-guest/` | Program inside the range VM that checks isolation and the sensor |
| `internal/buildinfo/` | Version string stamped at release build |
| `internal/rangevm/` | Range sandbox, QEMU argv, results parser, verdict, build and retention |
| `internal/rangeguest/` | Parsers for what the guest reads: auditctl, /proc, Laurel JSON, auditd state |
| `deploy/audit/` | Audit rules installed by `kordon-install` (ADR 0004) |
| `deploy/auditd/` | auditd configuration and the Laurel plugin entry |
| `deploy/laurel/` | Laurel configuration |
| `deploy/sysctl/` | Kernel settings (io_uring disabled) |
| `packaging/laurel/` | PKGBUILD for the pinned Laurel release binary |
| `range/` | mkosi configuration and guest unit of the range image |
| `tools/ci/` | Repository gates (layout and this map, commit lint, pins, secrets, Go) and their tests |
| `githooks/` | Local hooks; CI is the authority, hooks give earlier feedback |
| `.github/` | CI workflow, code owners, issue and pull request templates |

A code graph (graphify) is deliberately not kept: at this size it would only add something to go stale.
Revisit when floor 0 runs several processes.

## License

Apache License 2.0, see `LICENSE`.
