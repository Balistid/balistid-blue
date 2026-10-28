"""Tests for deploy/relay (ADR 0006, 0026): the service and the user carry exactly the decided settings, and
their paths agree with the relay's code and the ledger's unit.

As for the ledger, each section is compared whole and the forbidden directives are checked by name; the
one directive allowed beyond the ledger's is SupplementaryGroups, the ledger's group to read its log.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN, lines as collector_lines
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
RELAY = REPO / "deploy" / "relay"
BINARY = "/usr/local/lib/balistid/balistid-relay"
FILES = {"sysusers.conf", "balistid-relay.service"}
FORBIDDEN = COLLECTOR_FORBIDDEN - {"SupplementaryGroups"}

SERVICE_UNIT = {
    "Description": ["Balistid Blue relay: the ledger's checkpoints to the witness"],
    "After": ["balistid-ledger.service network.target"],
    "StartLimitIntervalSec": ["0"],
}
# ADR 0007 (own uid, no privilege), 0006 (no key on the relay, only the witness's address).
SERVICE = {
    "Type": "notify",
    "Restart": "always",
    "RestartSec": "5s",
    "User": "balistid-relay",
    "Group": "balistid-relay",
    "SupplementaryGroups": "balistid-ledger",
    "EnvironmentFile": "/etc/balistid/relay.env",
    "ExecStart": f"{BINARY} -submit ${{BALISTID_WITNESS_URL}}",
    "StateDirectory": "balistid/relay",
    "StateDirectoryMode": "0750",
    "UMask": "0077",
    "MemoryMax": "48M",
    "MemorySwapMax": "0",
    "NoExecPaths": "/ /var/lib/balistid /tmp -/dev/shm",
    "ExecPaths": BINARY,
    "IPAddressDeny": "any",
    "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    "DevicePolicy": "closed",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "disconnected",
    "PrivateDevices": "yes",
    "PrivateIPC": "yes",
    "RemoveIPC": "yes",
    "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "",
    "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes",
    "RestrictNamespaces": "yes",
    "RestrictRealtime": "yes",
    "RestrictSUIDSGID": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes",
    "ProtectClock": "yes",
    "ProtectHostname": "yes",
    "ProtectProc": "invisible",
    "ProcSubset": "pid",
    "SystemCallArchitectures": "native",
    "SystemCallFilter": ["@system-service",
                         "~@keyring memfd_create execveat process_vm_readv process_vm_writev"],
    "SystemCallErrorNumber": "EPERM",
}
SYSUSERS = [("u", "balistid-relay", "-", "Balistid Blue relay")]


def unit_problems(text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    want = {"Unit": SERVICE_UNIT, "Service": {k: v if isinstance(v, list) else [v] for k, v in SERVICE.items()},
            "Install": {"WantedBy": ["multi-user.target"]}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    return problems


def service_text() -> str:
    return (RELAY / "balistid-relay.service").read_text()


class RelayDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in RELAY.iterdir()}, FILES)

    def test_unit_has_exactly_the_decided_settings(self):
        self.assertEqual(unit_problems(service_text()), [])

    def test_exec_start_takes_the_relays_defaults(self):
        main = (REPO / "cmd" / "balistid-relay" / "main.go").read_text()
        defaults = dict(re.findall(r'flag\.String\("([a-z-]+)", "([^"]*)"', main))
        argv = shlex.split(parse_unit(service_text())["Service"]["ExecStart"][0])
        self.assertEqual(argv, [BINARY, "-submit", "${BALISTID_WITNESS_URL}"])
        self.assertEqual(defaults["submit"], "")  # no witness unless the install names one
        self.assertEqual(defaults["state"], "/var/lib/" + parse_unit(service_text())["Service"]["StateDirectory"][0])
        ledger = parse_unit((REPO / "deploy" / "ledger" / "balistid-ledger.service").read_text())["Service"]
        self.assertIn(f"-log {defaults['log']} ", ledger["ExecStart"][0] + " ")
        self.assertEqual(ledger["Group"], SERVICE["SupplementaryGroups"].split())

    def test_sysusers(self):
        self.assertEqual(collector_lines("sysusers.conf", (RELAY / "sysusers.conf").read_text()), SYSUSERS)

    def test_widened_service_fails(self):
        text = service_text()
        for old, new in (
            ("User=balistid-relay", "User=root"),
            ("IPAddressDeny=any", "IPAddressDeny="),
            ("SupplementaryGroups=balistid-ledger", "SupplementaryGroups=balistid-ledger balistid-collector"),
            ("CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_NET_RAW"),
            ("ProtectSystem=strict", "ProtectSystem=full"),
            ("UMask=0077", "UMask=0022"),
            ("ExecPaths=/usr/local/lib/balistid/balistid-relay", "ExecPaths=/usr"),
            ("Restart=always", "Restart=always\nLoadCredential=ledger-key:/etc/balistid/ledger-key"),
            ("Restart=always", "Restart=always\nReadWritePaths=/var/lib/balistid/ledger"),
            ("Restart=always", "Restart=always\nIPAddressAllow=any"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, text)
                self.assertTrue(unit_problems(text.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
