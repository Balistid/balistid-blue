"""Tests for deploy/net (ADR 0006 point 2, ADR 0032): the unit loads the relay-only firewall before it makes the
tunnel, holds CAP_NET_ADMIN and nothing else, and the table, the tunnel and the relay name the same addresses.

As for the relay, each section is compared whole and the forbidden directives are checked by name; the one
directive allowed beyond them is AmbientCapabilities, the netlink capability nft, ip and wg need.
"""

from __future__ import annotations

import shlex
import unittest
from pathlib import Path

import test_relay_deploy as relay
from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN, lines as collector_lines
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
NET = REPO / "deploy" / "net"
FILES = {"balistid-net.service", "nftables.conf", "sysusers.conf"}
FORBIDDEN = COLLECTOR_FORBIDDEN - {"AmbientCapabilities"}
PI, HOST, PORT, MARK, RELAY_PORT = "10.207.57.2", "10.207.57.1", "51820", "0x4a1d", "7381"
TABLE = "/usr/local/lib/balistid/nftables.conf"

SERVICE_UNIT = {
    "Description": ["Balistid Blue net: the relay-only firewall and the tunnel to the Pi"],
    "DefaultDependencies": ["no"],
    "After": ["local-fs.target systemd-sysusers.service nftables.service firewalld.service"],
    "Before": ["network-pre.target shutdown.target"],
    "Wants": ["network-pre.target"],
    "Conflicts": ["shutdown.target"],
}
# The table first: a line runs only when the one before it succeeded, so no tunnel exists without it.
EXEC_START = [
    f"/usr/bin/nft -D PI_ENDPOINT=${{BALISTID_PI_ENDPOINT}} -f {TABLE}",
    "/usr/bin/ip link add balistid0 type wireguard",
    f"/usr/bin/wg set balistid0 listen-port {PORT} fwmark {MARK} private-key %d/wg-key peer ${{BALISTID_PI_KEY}} "
    f"allowed-ips {PI}/32 endpoint ${{BALISTID_PI_ENDPOINT}}:{PORT}",
    f"/usr/bin/ip address add {HOST} peer {PI} dev balistid0",
    "/usr/bin/ip link set balistid0 up",
]
SERVICE = {
    "Type": "oneshot",
    "RemainAfterExit": "yes",
    "User": "balistid-net",
    "Group": "balistid-net",
    "AmbientCapabilities": "CAP_NET_ADMIN",
    "CapabilityBoundingSet": "CAP_NET_ADMIN",
    "EnvironmentFile": "/etc/balistid/net.env",
    "LoadCredential": "wg-key:/etc/balistid/wg-key",
    "ExecStart": EXEC_START,
    "ExecStopPost": "-/usr/bin/ip link delete balistid0",
    "StandardOutput": "null",
    "StandardError": "null",
    "UMask": "0077",
    "NoExecPaths": "/ /tmp -/dev/shm",
    "ExecPaths": "/usr/bin/nft /usr/bin/ip /usr/bin/wg /usr/lib",
    "RestrictAddressFamilies": "AF_NETLINK AF_UNIX",
    **{k: v for k, v in relay.SERVICE.items() if k in {
        "DevicePolicy", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "PrivateIPC", "RemoveIPC",
        "NoNewPrivileges", "LockPersonality", "MemoryDenyWriteExecute", "RestrictNamespaces", "RestrictRealtime",
        "RestrictSUIDSGID", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
        "ProtectControlGroups", "ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset",
        "SystemCallArchitectures", "SystemCallFilter", "SystemCallErrorNumber"}},
}
SYSUSERS = [("u", "balistid-net", "-", "Balistid Blue net")]
# Only the relay's uid reaches the Pi's tunnel address; WireGuard's own UDP, a kernel socket no uid matches,
# reaches its LAN address only with the mark no unprivileged socket can set; the Pi reaches only the relay;
# nothing is forwarded to either address or the tunnel. Each refusal is logged with the version and its reason,
# bounded per reason, the uid only where a local socket sent it; its counter keeps every one.
TABLE_LINES = [
    f"define PI = {PI}",
    f"define HOST = {HOST}",
    f"define WG_PORT = {PORT}",
    f"define WG_MARK = {MARK}",
    "define RELAY_CT = 0x4a1e",
    f"define RELAY_PORT = {RELAY_PORT}",
    "table inet balistid",
    "delete table inet balistid",
    "table inet balistid {",
    "chain output {",
    "type filter hook output priority filter; policy accept;",
    'ip daddr $PI meta l4proto tcp meta skuid "balistid-relay" ct mark set $RELAY_CT accept',
    "ip daddr $PI meta l4proto tcp ct state established ct mark $RELAY_CT accept",
    'ip daddr $PI limit rate 10/minute log prefix "balistid-net 1 drop to-pi-not-relay: " level warn flags skuid',
    "ip daddr $PI counter drop",
    "ip daddr $PI_ENDPOINT meta mark $WG_MARK udp sport $WG_PORT udp dport $WG_PORT accept",
    'ip daddr $PI_ENDPOINT limit rate 10/minute log prefix "balistid-net 1 drop to-endpoint-not-wireguard: " '
    "level warn flags skuid",
    "ip daddr $PI_ENDPOINT counter drop",
    "}",
    "chain input {",
    "type filter hook input priority filter; policy accept;",
    'iifname "balistid0" ct state established accept',
    'iifname "balistid0" ip saddr $PI ip daddr $HOST tcp dport $RELAY_PORT accept',
    'iifname "balistid0" limit rate 10/minute log prefix "balistid-net 1 drop from-tunnel-not-relay-port: " level warn',
    'iifname "balistid0" counter drop',
    'ip saddr $PI limit rate 10/minute log prefix "balistid-net 1 drop pi-address-off-tunnel: " level warn',
    "ip saddr $PI counter drop",
    'ip daddr $HOST limit rate 10/minute log prefix "balistid-net 1 drop host-address-off-tunnel: " level warn',
    "ip daddr $HOST counter drop",
    "}",
    "chain forward {",
    "type filter hook forward priority filter; policy accept;",
    'iifname "balistid0" limit rate 10/minute log prefix "balistid-net 1 drop forward-from-tunnel: " level warn',
    'iifname "balistid0" counter drop',
    'oifname "balistid0" limit rate 10/minute log prefix "balistid-net 1 drop forward-to-tunnel: " level warn',
    'oifname "balistid0" counter drop',
    'ip daddr { $PI, $PI_ENDPOINT } limit rate 10/minute log prefix "balistid-net 1 drop forward-to-pi: " level warn',
    "ip daddr { $PI, $PI_ENDPOINT } counter drop",
    "}",
    "}",
]


def unit_problems(text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    want = {"Unit": SERVICE_UNIT, "Service": {k: v if isinstance(v, list) else [v] for k, v in SERVICE.items()},
            "Install": {"WantedBy": ["sysinit.target"]}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    return problems


def table_lines(text: str) -> list[str]:
    if "\\" in text or "include" in text:
        raise ValueError("a continuation or an include the test would not follow")
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def service_text() -> str:
    return (NET / "balistid-net.service").read_text()


class NetDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in NET.iterdir()}, FILES)

    def test_unit_has_exactly_the_decided_settings(self):
        self.assertEqual(unit_problems(service_text()), [])

    def test_table_is_exactly_the_decided_rules(self):
        self.assertEqual(table_lines((NET / "nftables.conf").read_text()), TABLE_LINES)

    def test_relay_and_tunnel_agree(self):
        argv = shlex.split(parse_unit(relay.service_text())["Service"]["ExecStart"][0])
        self.assertEqual(argv[1:], ["-submit", f"http://{PI}:7380/add-checkpoint", "-listen", f"{HOST}:{RELAY_PORT}"])
        self.assertEqual(parse_unit(relay.service_text())["Service"]["IPAddressAllow"], [f"{PI}/32"])

    def test_range_drop_ins_change_only_ordering(self):
        # The range runs the installed argv and sandbox of the unit and the relay (ADR 0032, point 4).
        for name in ("balistid-net-range.conf", "balistid-relay-range.conf"):
            with self.subTest(name=name):
                self.assertEqual(set(parse_unit((REPO / "range" / name).read_text())), {"Unit"})

    def test_sysusers(self):
        self.assertEqual(collector_lines("sysusers.conf", (NET / "sysusers.conf").read_text()), SYSUSERS)

    def test_widened_service_fails(self):
        text = service_text()
        for old, new in (
            ("User=balistid-net", "User=root"),
            ("CapabilityBoundingSet=CAP_NET_ADMIN", "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"),
            ("AmbientCapabilities=CAP_NET_ADMIN", "AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=no"),
            ("StandardError=null", "StandardError=journal"),
            ("ExecStart=/usr/bin/nft", "ExecStart=-/usr/bin/nft"),
            ("RestrictAddressFamilies=AF_NETLINK AF_UNIX", "RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET"),
            ("ExecPaths=/usr/bin/nft /usr/bin/ip /usr/bin/wg /usr/lib", "ExecPaths=/usr"),
            ("RemainAfterExit=yes", "RemainAfterExit=yes\nExecStartPre=/usr/bin/ip link add balistid0 type wireguard"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, text)
                self.assertTrue(unit_problems(text.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
