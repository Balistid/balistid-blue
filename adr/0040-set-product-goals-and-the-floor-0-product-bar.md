# 0040 — Set product goals and the floor-0 product bar

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The repository records floors and numbers but no product goal, segment or point at which to stop: `acceptance/0.toml`
holds no install, disk or typical-load number, and `rss_mib` allows 512 MiB. The sensor alone takes 0.46 of the
0.5-core budget, 0.70 with the collector (ADR 0025, cpu-1000 trend). Market facts (fetched 2026-11-01): Wazuh's
quickstart wants 4 vCPU and 8 GiB for 1-25 agents (documentation.wazuh.com/current/quickstart.html), Wazuh Cloud
starts at 571 $/month for up to 100 agents (wazuh.com/cloud); LimaCharlie charges 3 $ per endpoint with 2 free
(limacharlie.com/pricing), Fleet 7 $ per host (fleetdm.com/pricing). No evidence that individuals pay was found.

## Decision

1. **Goals.** A real product with commercial premises, not a portfolio piece: light, easy to install and run, and
   protecting a host against attackers in general (an AI agent is one of them). The base runs on one machine; the
   witness off the host (ADR 0006) is an optional higher level.
2. **Segment.** Individuals, homelabs and developers use a free tier and are the first users. The paying segment is
   small teams and admins with 2-50 Linux servers. Hypothesis, checked at K2 and not a commitment: the core stays
   Apache-2.0 for everyone; paid are a read-only view across hosts, signed detection packs with updates, support.
   The non-goal in `README.md` ("fleet management ... or a hosted service") stays until an ADR before the paid layer.
3. **Difference, stated honestly.** Detections proven by an attack (little noise), explained verdicts, a fraction
   of the footprint (our agent against their agent and server, not against a price list). Verifiable history: "an
   attacker cannot erase it" holds only with the witness off the host; in local mode only against an attacker
   without root. The local-mode ADR (9.5) weighs a cheap off-host anchor in the free tier.
4. **Floor-0 product bar.** On a clean Arch or Ubuntu LTS machine: install within 10 min and 3 manual steps,
   including the reboot that `-e 2` needs, after showing that io_uring goes off for the whole host; uninstall
   leaves nothing; typical and stress CPU each at most 0.5 cores; RSS at most 256 MiB; at most 10 GiB of disk by
   default; `balistid status` never shows OK for a broken floor. The store lives on the existing filesystem with
   its reserve (`headroom_gib`, ADR 0005); an own filesystem is optional. Metrics `install_min`, `install_steps`,
   `uninstall_leftovers`, `cpu_cores_typical`, `disk_default_gib`, `status_false_ok`, and `rss_mib` lowered.
5. **Continue or stop, decided now.** K1, when 9.5 passes: on at least 2 machines of people other than the
   maintainer the base installs from the documentation within the bar and runs 2 weeks without intervention and
   without `missed`. If not, or no K1 within 40 merged product pull requests from 2026-11-01, a decision between
   (a) one narrow function, (b) upstream contributions, (c) a lab without a commercial line. K2, 8 weeks after
   0.1: at least 3 users for 2 weeks and at least 1 written commitment to pay the stated price; if not, the
   commercial line ends and open source continues by (a)-(c). Each K re-checks rivals: Prempti with eBPF or outside
   hooks, Wazuh Lumen generally available on Linux, a cheap hosted HIDS for small teams. Support stays within 3 h a week;
   above it the product is simplified, not extended.

## Alternatives considered

Keeping "single person, single host" as the only audience: the data show individuals do not pay, so the product
would have no commercial premise. A hosted witness as the paid offer: no commercial market for it was found.

## Consequences

- CPU decides before more Pi work: a time-boxed attempt to fit auditd and Laurel; if they cannot, an ADR on the
  data source, which reopens ADR 0004. L12 on a real Pi and the witness end to end move after 9.5.
- The default caps (raw, reserve, derived, log tiles) must sum to at most 10 GiB; today's values stay the ceilings
  a user can raise to. How the install ADR splits them, and how `capacity_margin` holds on a host with a large
  baseline, is decided there.
- The collector's heap limit (192 MiB) leaves little for the other services; it is re-cut when `rss_mib` is first
  measured (B6).
- Every floor from 9.5 carries a product bar in its acceptance file next to the technical numbers.
