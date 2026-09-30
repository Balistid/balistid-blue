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

## Repository map

| Path | Purpose |
|---|---|
| `ENGINEERING.md` | Binding engineering rules (R1–R14) for humans and agents |
| `CLAUDE.md`, `AGENTS.md` | Working instructions for Claude Code and Codex |
| `STATUS.md` | Current floor, next step, open decisions (overwritten, never appended) |
| `adr/` | Architecture decision records, one page each |
| `acceptance/` | Acceptance numbers per floor, committed before the floor's code |
| `tools/ci/` | Repository gates (docs budget, commit lint, action pinning) and their tests |
| `githooks/` | Local hooks; CI is the authority, hooks give earlier feedback |

## License

Apache License 2.0, see `LICENSE`.
