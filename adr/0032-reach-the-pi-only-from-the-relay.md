# 0032 — Reach the Pi only from the relay, through WireGuard

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 point 2 drops traffic to every Pi address for uids other than `balistid-relay` and has the Pi accept
only its WireGuard peer; nothing does either yet (T21), and the relay's addresses came from an install that does
not exist. A firewall and a tunnel need `CAP_NET_ADMIN`, which R13 gives no Balistid process. The host runs
NetworkManager; a distribution's `nftables.service` loads a ruleset that may flush every table. A kernel socket,
like WireGuard's, has no file, so `meta skuid` never matches it; a SYN-ACK is matched by its listener's uid.
`wg` prints a key file it cannot parse, whole.

## Decision

1. `balistid-net`, a oneshot of its own uid with `CAP_NET_ADMIN` as its only capability, ambient and bounding,
   loads `deploy/net/nftables.conf` and then makes `balistid0`, keys it from a credential and brings it up. A
   line runs only after the one before it succeeded, so the tunnel never exists without the table. Stopping
   deletes the link and keeps the table. It starts after `nftables.service` and `firewalld.service`, and
   nothing its programs print reaches the journal: the unit's failed state is the signal.
2. The table `inet balistid` replaces itself whole. Output: to the Pi's tunnel address only TCP of the relay's uid,
   and the last packets of its connections by their conntrack mark; to its LAN endpoint only WireGuard's port to
   its port with WireGuard's fwmark, which no unprivileged socket can set. Input: from the tunnel only replies and
   the Pi to the relay's port; the Pi's or the host's tunnel address arriving elsewhere is dropped. Forward:
   nothing to or from the tunnel, nothing to either Pi address (routed containers and VMs bypass the output hook).
   Each refusal is logged with the table's version and its reason, and on output the sender's uid, at most 10 a
   minute per reason; its counter keeps every one.
3. The tunnel is fixed in the repository: host 10.207.57.1, Pi 10.207.57.2, UDP 51820. The relay requires
   `balistid-net`, submits to the Pi's witness on 7380, serves bundles at the host's end on 7381 and allows only
   the Pi's /32. The install writes `/etc/balistid/net.env` (the Pi's public key and LAN address, refused unless
   an IPv4 literal, since nft resolves names) and the host's key `/etc/balistid/wg-key`, root's 0600.
4. The range runs this unit and table unchanged, with real WireGuard over a veth to a network namespace that
   stands in for the Pi (endpoint 192.0.2.2), keys made at boot. litewitness and `balistid-pi` run in that
   namespace. The guest's interfaces are then exactly `balistid-lan`, `balistid0` and `lo`; `pci_net` still
   proves the VM has no NIC (amends ADR 0009). Self-test facts: `pi_reach`, other uids refused and the relay
   through, the input rules seen in their counters, the refusals in the kernel's log, an unmarked datagram
   from WireGuard's port refused once the tunnel is stopped; `ledger_net`, the ledger's process seeing only
   loopback. The guest posts to the witness as the relay's uid. The forward chain is pinned only by its text.

## Alternatives considered

- wg-quick: a root shell script with hook lines. systemd-networkd beside NetworkManager: two managers of one
  host's routes. NetworkManager's WireGuard profile: host state outside the repository (R1).
- nftables.service with our include: the host's ruleset decides whether the table survives its load.
- Plain veth in the range: tests the relay's allowlist but not this unit, the table or the tunnel before L12.
- The relay's cgroup instead of its uid: its path changes on restart; `NFTSet=` binds the table to start order.

## Consequences

- Amends ENGINEERING.md R13 and ADR 0007 points 4 and Consequences: besides `balistid-auditstat`, only
  `balistid-net` holds a capability, `CAP_NET_ADMIN`, for its start at boot; `systemd_exposure` scores it (1.5).
- Residuals: root can flush the table (A2 is root; T21 is A4); IPv6, broadcast and multicast reach the Pi's
  LAN from the host until the Pi's own firewall (L12); while the relay is down another uid can take port 7381
  (the Pi then alarms); the subnet can collide with a network the host joins, and changing it is a commit.
- 9.5 host preconditions: NetworkManager leaves `balistid0` unmanaged; nothing flushes the ruleset after boot;
  no guest bridged, macvlan or ipvlan onto the LAN; the Pi has a fixed LAN address and serves the host no DNS
  or NTP, which the endpoint rule would cut for every uid.
