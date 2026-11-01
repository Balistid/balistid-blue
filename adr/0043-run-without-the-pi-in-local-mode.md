# 0043 — Run without the Pi in local mode

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-02
- Decided-by: alex
- Agent: claude/opus-5.5
- Amends: ADR 0006 point 2 and Consequences, 0031 point 1, 0032 point 3, 0034 point 3, 0040 point 3

## Context

ADR 0040 runs the base on one machine, the off-host witness a higher level, and leaves local history to this ADR.
Every alert comes from `balistid-pi` on the Pi (cmd/balistid-pi/main.go:1-3); `balistid` prints its version only.
Shards retire by the witness's cosign time (ADR 0029), announcements and rollover wait for a cosigned checkpoint
(ADR 0030): with no witness the store's only exit is its cap. The range already runs the pinned litewitness and
`balistid-pi` beside the recorder, in a namespace of the guest (ADR 0032 point 4). The witness network approves
each log on a human request, suggests at most 24 checkpoints a day and lists production as "Not available yet"
(witness-network.org/participate, 2026-11-02). CPU is 0.70 of 0.5 cores before anything is added (ADR 0040).

## Decision

1. Local mode is the default install for 9.5: sensor, collector, store, ledger and relay as decided, plus the Pi's
   two services on the host, each its own uid without privilege: the pinned litewitness on 127.0.0.1:7380, its key
   a systemd credential served by OpenSSH's `ssh-agent` in its own unit, and `balistid-pi` reading it and the relay
   on 127.0.0.1:7381. No `balistid-net`, WireGuard or table; the relay's addresses come from the mode's drop-in.
2. Alerts go to ntfy as on the Pi (ADR 0031 point 6, ADR 0039 keys), the token a root-only credential. A dead-man
   ping under ADR 0034, the host as the site, is opt-in for machines that stay on (a laptop's suspend would page).
3. The claim: loss, health, log cap and a stalled ledger alert against A1 and A6, and a forking ledger (T19) is
   refused by a witness of another uid. Against A2 nothing: root holds the witness key, the token and the ping URL,
   so it rewrites or rolls back any history, starts a new origin and mutes every alert. A dead host: the dead-man only.
4. `balistid status` names the mode first and never shows history OK in local mode: "history: local only, root
   can rewrite it"; at the higher level "history: cosigned by <witness> <age> ago, as this host sees it" (T11).
   Alerts: on, off (no topic: the install still finishes) or failing. `status_false_ok` covers both lines.
5. The higher level is any second Linux machine the user owns (the Pi, an old laptop, a team's server) running
   litewitness and `balistid-pi` per ADR 0031-0034, reached per ADR 0032. A move either way is a rollover (ADR 0030
   point 5): no witness vouches for history it did not see grow; what came before is only as good as local mode.
6. No off-host anchor ships free in 9.5. A checkpoint upload in compliance mode (Backblaze B2: 10 GB free, a lock
   that "cannot be removed by any user") is the candidate after K1 if users ask: it proves a rollback afterwards,
   but refuses nothing, alarms nobody and costs a cloud account, an uploader and a verifier.

## Alternatives considered

- No witness: nothing retires, no announcement is cosigned; watching the relay's checkpoint changes `internal/watch`.
- The witness network: per-log approval, no production list; one Balistid log of users' checkpoints is a hosted
  service (README non-goal) that learns every host's activity. Armored Witness: a small run for volunteers.
- A git remote with a ruleset: a write deploy key acts "as an organization member with admin access" (GitHub
  docs); a public repository publishes each checkpoint. OpenTimestamps, RFC 3161: root deletes the proof. A VPS
  witness: a second machine whose admin path can roll it back (ADR 0034). R9: every service named here exists.

## Consequences

- Local-mode rows: T12, T17 and T22 become gaps (no off-host witness; one clock), T13-T15 stay gaps, T27 is the
  host's watcher (partial with the dead-man only), T11 has no off-host view, T16 and T21 do not apply.
- Local-mode metrics: `pi_store_cap_gib` and the range fact `pi_reach` do not apply; `cosign_gap_s`, `verify_s`,
  `verify_freshness_s`, `announced_quiet_max_h` are measured on the host; `loss_alarm_s` and stalled-ledger
  `silence_alarm_s` at the host's ntfy as the range runs them; power-off silence, `dead_site_alarm_s` and
  `push_refused_alarm_s` need the dead-man. The higher level keeps every metric as written.
- litewitness, its agent and `balistid-pi` count in `cpu_cores`, `rss_mib`, `disk_default_gib` and
  `uninstall_leftovers`, measured before 9.5. litewitness (torchwood v0.10.0, pre-1.0, with Prometheus and modernc
  SQLite) moves from range-only to the host, licences checked (R14). Residual: a uid binding 7380 or 7381 while its
  service is down alarms falsely, never OKs. Tests: units without `balistid-net`, status per mode, a rollover.
