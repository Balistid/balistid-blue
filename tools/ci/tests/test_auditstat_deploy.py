"""Tests for deploy/auditstat (ADR 0038 point 1, ADR 0007): the one long-running unit with a capability carries
exactly the decided settings: CAP_AUDIT_CONTROL and nothing else, netlink and no other address family, no exec,
audit.log hidden, and the initial namespaces audit netlink needs.

As for the relay, each section is compared whole and the forbidden directives are checked by name; the one
directive allowed beyond the collector's is AmbientCapabilities, as for the net unit.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN, lines as collector_lines
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
AUDITSTAT = REPO / "deploy" / "auditstat"
BINARY = "/usr/local/lib/balistid/balistid-auditstat"
FILES = {"sysusers.conf", "balistid-auditstat.service"}
FORBIDDEN = COLLECTOR_FORBIDDEN - {"AmbientCapabilities"} | {"PrivateUsers", "PrivatePIDs", "PrivateNetwork",
                                                              "SupplementaryGroups"}

SERVICE_UNIT = {
    "Description": ["Balistid Blue auditstat: the kernel's audit status for the collector"],
    "After": ["systemd-sysusers.service"],
    "StartLimitIntervalSec": ["0"],
}
SERVICE = {
    "Type": "exec",
    "Restart": "always",
    "RestartSec": "1s",
    "User": "balistid-auditstat",
    "Group": "balistid-auditreport",
    "AmbientCapabilities": "CAP_AUDIT_CONTROL",
    "CapabilityBoundingSet": "CAP_AUDIT_CONTROL",
    "ExecStart": BINARY,
    "RuntimeDirectory": "balistid-auditstat",
    "RuntimeDirectoryMode": "0750",
    "UMask": "0027",
    "MemoryMax": "32M",
    "MemorySwapMax": "0",
    "TasksMax": "16",
    "NoExecPaths": "/ /tmp -/dev/shm",
    "ExecPaths": BINARY,
    "InaccessiblePaths": "/var/log/audit",
    "IPAddressDeny": "any",
    "RestrictAddressFamilies": "AF_NETLINK",
    "DevicePolicy": "closed",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "disconnected",
    "PrivateDevices": "yes",
    "PrivateIPC": "yes",
    "RemoveIPC": "yes",
    "NoNewPrivileges": "yes",
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
SYSUSERS = [("g", "balistid-auditreport", "-"), ("u", "balistid-auditstat", "-", "Balistid Blue auditstat")]


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
    return (AUDITSTAT / "balistid-auditstat.service").read_text()


class AuditstatDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in AUDITSTAT.iterdir()}, FILES)

    def test_unit_has_exactly_the_decided_settings(self):
        self.assertEqual(unit_problems(service_text()), [])

    def test_report_lands_in_the_runtime_directory(self):
        report = (REPO / "internal" / "auditstat" / "report.go").read_text()
        path = re.findall(r'const ReportPath = "([^"]*)"', report)
        service = parse_unit(service_text())["Service"]
        self.assertEqual(shlex.split(service["ExecStart"][0]), [BINARY])
        self.assertEqual(path, ["/run/" + service["RuntimeDirectory"][0] + "/report"])

    def test_threads_stay_under_tasks_max(self):
        # Go's runtime threads grow with GOMAXPROCS, its default the host's CPUs; past TasksMax a new thread
        # aborts the process (runtime throw "newosproc"), so main pins it far below the unit's limit.
        main = (REPO / "cmd" / "balistid-auditstat" / "main.go").read_text()
        procs = [int(n) for n in re.findall(r"runtime\.GOMAXPROCS\((\d+)\)", main)]
        tasks = int(parse_unit(service_text())["Service"]["TasksMax"][0])
        self.assertEqual(len(procs), 1)
        self.assertLessEqual(procs[0] * 4, tasks)

    def test_sysusers(self):
        self.assertEqual(collector_lines("sysusers.conf", (AUDITSTAT / "sysusers.conf").read_text()), SYSUSERS)

    def test_widened_service_fails(self):
        text = service_text()
        for old, new in (
            ("User=balistid-auditstat", "User=root"),
            ("Group=balistid-auditreport", "Group=balistid-auditlog"),
            ("AmbientCapabilities=CAP_AUDIT_CONTROL", "AmbientCapabilities=CAP_AUDIT_CONTROL CAP_AUDIT_WRITE"),
            ("CapabilityBoundingSet=CAP_AUDIT_CONTROL", "CapabilityBoundingSet=CAP_AUDIT_CONTROL CAP_KILL"),
            ("RestrictAddressFamilies=AF_NETLINK", "RestrictAddressFamilies=AF_NETLINK AF_UNIX"),
            ("RestrictAddressFamilies=AF_NETLINK", "RestrictAddressFamilies=AF_NETLINK AF_INET"),
            ("InaccessiblePaths=/var/log/audit", "InaccessiblePaths="),
            ("NoNewPrivileges=yes", "NoNewPrivileges=no"),
            ("ExecPaths=/usr/local/lib/balistid/balistid-auditstat", "ExecPaths=/usr"),
            ("RuntimeDirectoryMode=0750", "RuntimeDirectoryMode=0755"),
            ("UMask=0027", "UMask=0022"),
            ("ProtectSystem=strict", "ProtectSystem=full"),
            ("Restart=always", "Restart=always\nPrivateUsers=yes"),
            ("Restart=always", "Restart=always\nPrivatePIDs=yes"),
            ("Restart=always", "Restart=always\nSupplementaryGroups=balistid-auditlog"),
            ("Restart=always", "Restart=always\nReadWritePaths=/var/log/audit"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, text)
                self.assertTrue(unit_problems(text.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
