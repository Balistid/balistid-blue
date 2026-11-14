"""Tests for deploy/judge (ADR 0074, point 1): the judge's oneshot runs as the collector's uid, so its unit is what
keeps it from the collector: its own PID namespace, no network and no socket, the store read-only, a /tmp that is
not the store's device, no exec outside its binary, and bounds beside the recorder.

As for the other units, the sections are compared whole and the forbidden directives are checked by name, and the
settings that matter most are also asserted on their own, so a looser comparison keeps them.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
JUDGE = REPO / "deploy" / "judge"
BINARY = "/usr/local/lib/balistid/balistid-judge"
STORE = "/var/lib/balistid/collector"
FILES = {"balistid-judge.service"}
# No other uid's groups, no user namespace that would remap the collector's files, no restart, no slice.
FORBIDDEN = COLLECTOR_FORBIDDEN | {"SupplementaryGroups", "PrivateUsers", "Restart", "Slice", "AmbientCapabilities"}

SERVICE_UNIT = {"Description": ["Balistid Blue judge: the recording days from the sealed store"]}
SERVICE = {
    "Type": "oneshot",
    "User": "balistid-collector",
    "Group": "balistid-collector",
    "ExecStart": BINARY,
    "StateDirectory": "balistid/judge",
    "StateDirectoryMode": "0755",
    "ReadOnlyPaths": STORE,
    "UMask": "0022",
    "MemoryMax": "1536M",
    "MemorySwapMax": "0",
    "TimeoutStartSec": "2h",
    "Nice": "19",
    "CPUSchedulingPolicy": "idle",
    "IOSchedulingClass": "idle",
    "NoExecPaths": "/ /var/lib/balistid/judge /tmp /var/tmp -/dev/shm",
    "ExecPaths": BINARY,
    "InaccessiblePaths": "/var/log/audit",
    "PrivateNetwork": "yes",
    "PrivatePIDs": "yes",
    "RestrictAddressFamilies": "none",
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
# Each of these alone keeps the judge from the collector it shares a uid with.
NAMED = {"User": ["balistid-collector"], "Group": ["balistid-collector"], "Type": ["oneshot"],
         "ReadOnlyPaths": [STORE], "PrivateNetwork": ["yes"], "PrivatePIDs": ["yes"], "PrivateTmp": ["disconnected"],
         "RestrictAddressFamilies": ["none"], "ProtectSystem": ["strict"], "NoNewPrivileges": ["yes"],
         "CapabilityBoundingSet": [""]}


def unit_problems(text: str) -> list[str]:
    sections = parse_unit(text, "deploy/judge/balistid-judge.service")
    service = sections.get("Service", {})
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    want = {"Unit": SERVICE_UNIT, "Service": {k: v if isinstance(v, list) else [v] for k, v in SERVICE.items()}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    problems += [f"{k} is not {v}" for k, v in NAMED.items() if service.get(k) != v]
    for key in ("MemoryMax", "TimeoutStartSec"):
        if key not in service:
            problems.append(f"{key} is missing")
    if "Install" in sections:
        problems.append("an [Install] section: something would start it at boot")
    return problems


def service_text() -> str:
    return (JUDGE / "balistid-judge.service").read_text()


class JudgeDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in JUDGE.iterdir()}, FILES)

    def test_unit_has_exactly_the_decided_settings(self):
        self.assertEqual(unit_problems(service_text()), [])

    def test_exec_start_is_the_binary_the_installer_writes(self):
        service = parse_unit(service_text())["Service"]
        self.assertEqual(shlex.split(service["ExecStart"][0]), [BINARY])
        table = (REPO / "internal" / "install" / "judge.go").read_text()
        self.assertIn(f'"balistid-judge", "{BINARY.removeprefix("/")}", 0o755', table)
        self.assertIsNotNone(re.search(r'"balistid-judge\.service", "etc/systemd/system/balistid-judge\.service", 0o644', table))

    def test_the_store_is_the_collectors_and_the_unit_writes_only_its_own_directory(self):
        collector = parse_unit((REPO / "deploy" / "collector" / "balistid-collector.service").read_text())["Service"]
        self.assertEqual(collector["StateDirectory"], ["balistid/collector"])
        self.assertEqual(parse_unit(service_text())["Service"]["ReadOnlyPaths"], [STORE])

    def test_widened_service_fails(self):
        text = service_text()
        for old, new in (
            ("User=balistid-collector", "User=root"),
            ("Group=balistid-collector", "Group=balistid-auditlog"),
            ("Type=oneshot", "Type=simple"),
            ("ReadOnlyPaths=/var/lib/balistid/collector", "ReadOnlyPaths="),
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("PrivatePIDs=yes\n", ""),
            ("PrivateTmp=disconnected", "PrivateTmp=yes"),
            ("RestrictAddressFamilies=none", "RestrictAddressFamilies=AF_UNIX"),
            ("ProtectSystem=strict", "ProtectSystem=full"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=no"),
            ("CapabilityBoundingSet=\n", "CapabilityBoundingSet=CAP_KILL\n"),
            ("NoExecPaths=/ /var/lib/balistid/judge /tmp /var/tmp -/dev/shm",
             "NoExecPaths=/ /var/lib/balistid/judge /tmp -/dev/shm"),
            ("MemoryMax=1536M\n", ""),
            ("TimeoutStartSec=2h\n", ""),
            ("UMask=0022", "UMask=0077"),
            ("Type=oneshot", "Type=oneshot\nReadWritePaths=/var/lib/balistid/collector"),
            ("Type=oneshot", "Type=oneshot\nSupplementaryGroups=balistid-ledgerlink"),
            ("Type=oneshot", "Type=oneshot\nPrivateUsers=yes"),
            ("Type=oneshot", "Type=oneshot\nRestart=always"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, text)
                self.assertTrue(unit_problems(text.replace(old, new)))
        with self.subTest(new="[Install]"):
            self.assertTrue(unit_problems(text + "\n[Install]\nWantedBy=multi-user.target\n"))


if __name__ == "__main__":
    unittest.main()
