# 0036 — Measure the Pi's alarms end to end in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

L11 decides the Pi's alarm metrics in the range. A trial runs at most 29 min; ADR 0018 refused a run that holds the
runner a day. The Pi's stand-in lives in a namespace of the guest and dies with the VM; its pushes go to 127.0.0.1:7382,
where nothing listens. Kernel loss and dispatcher overflow have no detector (ADR 0027 point 6). At its cap the ledger
appends nothing more: the Pi sees silence after 840 s, not the UNKNOWN 0027 point 5 promised.

## Decision

1. `balistid-range-ntfy`, a range-only unit in the Pi's namespace, listens on 127.0.0.1:7382 and starts before
   `balistid-pi` (a failed first push backs off up to 5 min). A dynamic user, loopback only; POST bodies up to
   4 KiB, 4096 lines, read, write and idle timeouts. It records CLOCK_BOOTTIME, tag and token match, answers 200
   only with the range token and 401 without it; only matched posts count. The Pi alerts a minute before each
   limit (ADR 0031 point 6): judges time to the sink within the limit less 55 s, and silence and loss pass only
   once L12 shows sink to phone within 55 s.
2. Silence at its real limit, one trial per cause: WireGuard cut on the host side; the ledger killed and kept
   stopped; a hard stop for power-off (SIGKILL and stop of ledger, relay and collector, socket included, without
   `balistid-announce`, then the host side of tunnel and veth down). Pass: the first `silence` post 825 to 845 s
   after the last cosigned checkpoint; a Pi restart in the run misses. Power-off itself is L12's.
3. `announced_quiet_max_h` and `cosign_gap_s` are decided over 24 h on the Pi and the reference host (L12). In the
   range `balistid-pi -quiet <d>` takes only Silence < d ≤ its default (24 h − 1 min), else it exits 2; only the
   range drop-in sets it, to 20 min. Three trend trials: announce and stay off; announce, ledger masked; announce,
   back for a minute, announce again. Each passes when silence alerts 20 to 21 min after the first announcement.
   Every alarm trial reports the largest gap between cosigned checkpoints while connected, as a trend.
4. `loss_alarm_s`: under load the guest freezes the store's filesystem (a full queue), fills it, or makes the store's
   files refuse writes, four trials each. Each injection has its own proof (freeze held, no free blocks, a refused write
   in the collector's journal); without it, or with the sink, clock or facts broken, a run is INVALID. A proven
   injection without its loss (store: health) entry and its alert within 65 s is a MISS; a fill whose store went down on
   a disk-full write, not to its cap, is INVALID with that alert (Alex 2026-10-31). The control must not alert. Kernel
   and dispatcher loss (auditd, Laurel stopped), rules locked (`-e 2`), are INVALID "no detector" until
   `balistid-auditstat` (ADR 0007), its own milestone between L11 and L12; until then `loss_alarm_s` cannot pass.
5. The log keeps its last two slots: a health UNKNOWN with the new reason 7, "log at its cap", logged once, also
   after a restart at that size; then `final`. Rollover does not copy it into the next log. The Pi alarms on it at
   once under its own key, `logcap`. `balistid-ledger -cap-bytes` only lowers the 10 GiB cap, to at least three
   entries; the range lowers it to fill in minutes. Pass: `logcap` at the sink within 65 s of the cap, one entry, the
   final slot free, the collector refused for `cap` and full bundles at most the bytes per entry the cap counts.

## Alternatives considered

- A 24 h trial class on the runner holds it a day per run (refused for `healthy_ok`, ADR 0018). A shorter Silence in
  the range would not measure its number. Rules without `-e 2` in the image: it would differ from the host.
- The sink inside the guest program: root parses HTTP and starts after the Pi. The Pi in a second VM: real
  power-off, at two VMs and a network per run. A VM reboot for the second quiet case reboots the Pi's stand-in too.
  `balistid-auditstat` inside L11: the one privileged long-running process gets its own checkpoint and review.

## Consequences

- Amends ADR 0027 points 5 and 6 (reason 7 before `final`), ADR 0030 points 5 and 6 (two slots at the cap; the cap
  entry stays in the old log), ADR 0031 point 4 (the range shortens the quiet cap) and the five metrics' methods.
- Residuals: power-off, delivery, the quiet cap and the cosign gap wait for L12, `loss_alarm_s` (T4, T25) for
  auditstat; a host crashing the Pi delays silence (`OnFailure` alerts). T13, T28, T14 and T20 gain the trials above.
- Tests: the flags refuse a longer quiet or a higher cap; deploy units carry neither; the sink refuses a wrong token;
  each judge's MISS and INVALID cases; the cap entry once before `final`, across a reopen and not after rollover.
