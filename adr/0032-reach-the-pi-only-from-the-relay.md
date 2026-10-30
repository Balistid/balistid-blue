# 0032 — Reach the Pi only from the relay, through WireGuard

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0006 point 2 drops traffic to every Pi address for uids other than `balistid-relay` and has the Pi accept
only its WireGuard peer; nothing does either yet (T21). The relay's unit took its addresses from an install that
does not exist, and allowed the Pi's address only by a comment. Loading a firewall and making a tunnel needs
`CAP_NET_ADMIN`, which R13 gives no Balistid process. The host runs NetworkManager; Arch's `nftables.conf`
begins with `flush ruleset`. A kernel socket, such as WireGuard's own, has no file, so `meta skuid` never
matches it; a SYN-ACK is matched by its listener's uid.

## Decision

1. `balistid-net`, a oneshot of its own uid with `CAP_NET_ADMIN` as its only capability, ambient and bounding,
   loads `deploy/net/nftables.conf` and then makes `balistid0`, keys it from a credential and brings it up. A
   line runs only after the one before it succeeded, so the tunnel never exists without the table. Stopping
   deletes the link and keeps the table.
2. The table `inet balistid` replaces itself whole. Output: to the Pi's tunnel address only TCP of the relay's
   uid; to its LAN endpoint only WireGuard's port to WireGuard's port. Input: from the tunnel only replies and
   the Pi to the relay's port; the Pi's or the host's tunnel address arriving elsewhere is dropped. Forward:
   nothing to or from the tunnel, nothing to the endpoint (containers and VMs bypass the output hook).
3. The tunnel is fixed in the repository: host 10.207.57.1, Pi 10.207.57.2, UDP 51820. The relay submits to
   the Pi's witness on 7380, serves bundles on the host's end at 7381 and allows only the Pi's /32. The install
   writes `/etc/balistid/net.env` (the Pi's LAN IPv4 literal, never a name, and its public key) and the
   host's key `/etc/balistid/wg-key`, root's 0600. The relay requires `balistid-net`.
4. The range runs this unit and table unchanged, with real WireGuard over a veth to a network namespace that
   stands in for the Pi (endpoint 192.0.2.2), keys made at boot. litewitness and `balistid-pi` run in that
   namespace. The guest's interfaces are then exactly `balistid-lan`, `balistid0` and `lo`; `pci_net` still
   proves the VM has no NIC (amends ADR 0009). Self-test facts: `pi_reach`, other uids refused and the relay
   through, and `ledger_net`, the ledger's process seeing only loopback. The guest posts to the witness as the
   relay's uid.
5. `systemd_exposure` scores `balistid-net` with the recorder's services (1.5 offline). The Pi's own firewall
   and its IPv6 addresses come with the Pi (L12).

## Alternatives considered

- wg-quick: a root shell script with hook lines. systemd-networkd beside NetworkManager: two managers of one
  host's routes. NetworkManager's WireGuard profile: host state outside the repository (R1).
- nftables.service with our include: its `flush ruleset` on reload removes the table silently.
- Plain veth in the range: tests the relay's allowlist but not this unit, the table or the tunnel before L12.
- Matching the relay's cgroup instead of its uid: the path changes on restart; systemd's `NFTSet=` keeps it but
  binds the table to unit start order.

## Consequences

- Amends ENGINEERING.md R13 and ADR 0007 points 4 and Consequences: besides `balistid-auditstat`, only
  `balistid-net` holds a capability, `CAP_NET_ADMIN`, for its start at boot.
- Residuals: root can flush the table (A2 is root; T21 is A4); an orphaned socket's late retransmits to the Pi
  are dropped (a cut bundle alarms, fail safe); IPv6 to the Pi's LAN is open from the host until L12; the
  subnet can collide with a network the host joins, and changing it is a commit.
- 9.5 host preconditions: NetworkManager leaves `balistid0` unmanaged; nothing flushes the ruleset after boot;
  the Pi has a fixed LAN address.
