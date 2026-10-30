# 0036 — Measure the Pi's alarms end to end in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

L11 decides the Pi's alarm metrics in the range: `silence_alarm_s`, `announced_quiet_max_h`, `loss_alarm_s`,
`cosign_gap_s`, `host_log_cap_gib`. A trial runs at most 29 min, and ADR 0018 refused a range run that holds the
runner a day. The Pi's stand-in lives in a namespace of the guest, so it dies with the VM. Its pushes go to
127.0.0.1:7382, where nothing listens. Kernel loss and dispatcher overflow have no detector (ADR 0027 point 6).
At its cap the ledger appends nothing more, so the Pi sees silence after 840 s, not the UNKNOWN 0027 point 5 promised.

## Decision

1. The range measures `silence_alarm_s` at its real limit, with one trial per cause: WireGuard cut on the host side;
   the ledger killed and kept stopped; a hard stop for power-off (SIGKILL and stop of ledger, relay and collector,
   socket included, without `balistid-announce`, then the host side of tunnel and veth down). A trial passes when
   the first `silence` alert reaches the sink 825 to 900 s after the cut; a Pi restart in the run misses.
2. `announced_quiet_max_h` and `cosign_gap_s` are decided over 24 h on the Pi and the reference host (L12). In the
   range `balistid-pi -quiet <d>` takes only Silence < d ≤ its default (24 h − 1 min), else it exits 2; only the
   range drop-in sets it, to 20 min. Three trend trials: announce and stay off; announce, ledger masked; announce,
   back for a minute, announce again. Each passes when silence alerts 20 to 21 min after the first announcement.
   Every alarm trial reports the largest gap between cosigned checkpoints while connected, as a trend.
3. `balistid-range-ntfy`, a range-only unit in the Pi's namespace, listens on 127.0.0.1:7382 and starts before
   `balistid-pi` (a failed first push backs off up to 5 min). It runs as a dynamic user, loopback only, takes POST
   bodies up to 4 KiB and 4096 lines with read, write and idle timeouts, answers 200 and records CLOCK_BOOTTIME,
   tag and whether the token matched. Latency ends at the sink; delivery to the phone is L12's.
4. `loss_alarm_s`: under load the guest freezes the store's filesystem (a full queue), fills it, or makes the store's
   files refuse writes. A trial passes when `loss` (for the store also `unknown`) reaches the sink within 120 s and
   the ledger holds the matching entry, else it is INVALID; four per case, twelve in all. Kernel loss (auditd
   stopped) and dispatcher overflow (Laurel stopped) are injected with the rules locked (`-e 2`) and their evidence
   kept, but they are INVALID "no detector" until `balistid-auditstat` (ADR 0007), its own milestone after L11 and
   before L12; until then `loss_alarm_s` cannot pass. A control with no injection must not alert.
5. The log keeps its last two slots: a health UNKNOWN with the new reason 7, "log at its cap", logged once, also
   after a restart at that size; then `final`. The Pi alarms on it as on any UNKNOWN. `balistid-ledger -cap-bytes`
   only lowers the 10 GiB cap, to at least three entries; the range lowers it to fill in minutes. A trial passes
   when `unknown` reaches the sink within 114 s of a checkpoint at the cap, with one such entry, the final slot free,
   the collector refused for `cap` and full bundles at most the bytes per entry the cap counts.

## Alternatives considered

- A 24 h trial class on the runner holds it a day per run (refused for `healthy_ok`, ADR 0018). A shorter Silence in
  the range would not measure its number. Rules without `-e 2` in the image: it would differ from the host.
- The sink inside the guest program: root parses HTTP and starts after the Pi. The Pi in a second VM: real
  power-off, at two VMs and a network per run. A VM reboot for the second quiet case reboots the Pi's stand-in too.
- `balistid-auditstat` inside L11: the one privileged long-running process gets its own checkpoint and review.

## Consequences

- Amends ADR 0027 points 5 and 6 (reason 7, the UNKNOWN before `final`), ADR 0030 point 5 (two slots at the cap),
  ADR 0031 point 4 (the range shortens the quiet cap) and the methods of the five metrics; numbers are unchanged.
- Residuals: power-off, the quiet cap and the cosign gap are measured only in L12; `loss_alarm_s` waits for
  auditstat; a host that keeps crashing the Pi delays silence, as each start restarts it (`OnFailure` alerts).
- T4 and T25 stay partial until auditstat; T13 and T28 get silence measured, power-off in L12; T14 the quiet
  mechanism; T20 the cap alarms.
- Tests: the flags refuse a longer quiet or a higher cap; deploy units carry neither; each judge's window and its
  INVALID cases; the cap entry logged once before `final` and across a reopen; reason 7 decoded and alarmed.
