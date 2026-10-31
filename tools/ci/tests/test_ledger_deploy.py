"""Tests for deploy/ledger (ADR 0027): the service, the user and the directories carry exactly the decided
settings, and their paths agree with the ledger's and the collector's code.

As for the collector, each section is compared whole and the forbidden directives are checked by name.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN, lines as collector_lines
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
LEDGER = REPO / "deploy" / "ledger"
BINARY = "/usr/local/lib/balistid/balistid-ledger"
STATE = "/var/lib/balistid/ledger"
SOCKET = "/run/balistid-ledger/ledger.sock"
FILES = {"sysusers.conf", "tmpfiles.conf", "balistid-ledger.service"}
# The one directive allowed beyond the collector's: the relay's group, to read its cosigned checkpoint (0029).
FORBIDDEN = COLLECTOR_FORBIDDEN - {"SupplementaryGroups"}

SERVICE_UNIT = {
    "Description": ["Balistid Blue ledger: the collector's stream into the signed log"],
    "DefaultDependencies": ["no"],
    "After": ["local-fs.target systemd-tmpfiles-setup.service systemd-sysusers.service"],
    "Before": ["shutdown.target"],
    "Conflicts": ["shutdown.target"],
    "StartLimitIntervalSec": ["0"],
}
# ADR 0007 (own uid, no privilege, no network), 0006 (the key only through a credential), 0027.
SERVICE = {
    "Type": "notify",
    "Restart": "always",
    "RestartSec": "1s",
    "User": "balistid-ledger",
    "Group": "balistid-ledger",
    "SupplementaryGroups": "balistid-relay",
    "ExecStart": f"{BINARY} -log {STATE}/log -socket {SOCKET}",
    "LoadCredential": "ledger-key:/etc/balistid/ledger-key",
    "StateDirectory": "balistid/ledger",
    "StateDirectoryMode": "0750",
    "RuntimeDirectory": "balistid-ledger",
    "RuntimeDirectoryMode": "0755",
    "UMask": "0027",
    "MemoryMax": "128M",  # with the collector's 384M within acceptance rss_mib (512 MiB for floor 0)
    "MemorySwapMax": "0",
    "TimeoutStopSec": "90s",
    "NoExecPaths": f"/ {STATE} /run/balistid-ledger /tmp -/dev/shm",
    "ExecPaths": BINARY,
    "PrivateNetwork": "yes",
    "RestrictAddressFamilies": "AF_UNIX",
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
TMPFILES = [
    ("d", STATE, "0750", "balistid-ledger", "balistid-ledger", "-"),
    ("d", f"{STATE}/log", "0750", "balistid-ledger", "balistid-ledger", "-"),
]
SYSUSERS = [("u", "balistid-ledger", "-", "Balistid Blue ledger"), ("g", "balistid-relay", "-")]


def unit_problems(text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    want = {"Unit": SERVICE_UNIT, "Service": {k: v if isinstance(v, list) else [v] for k, v in SERVICE.items()},
            "Install": {"WantedBy": ["sysinit.target"]}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    return problems


def lines(name: str) -> list[tuple[str, ...]]:
    return collector_lines(name, (LEDGER / name).read_text())


def service_text() -> str:
    return (LEDGER / "balistid-ledger.service").read_text()


class LedgerDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in LEDGER.iterdir()}, FILES)

    def test_unit_has_exactly_the_decided_settings(self):
        self.assertEqual(unit_problems(service_text()), [])

    def test_exec_start_takes_the_ledgers_defaults(self):
        main = (REPO / "cmd" / "balistid-ledger" / "main.go").read_text()
        defaults = dict(re.findall(r'flag\.String\("([a-z-]+)", "([^"]*)"', main))
        argv = shlex.split(parse_unit(service_text())["Service"]["ExecStart"][0])
        given = dict(zip((a[1:] for a in argv[1::2]), argv[2::2]))
        self.assertEqual(argv[0], BINARY)
        self.assertEqual(given, {"log": defaults["log"], "socket": defaults["socket"]})
        self.assertEqual(defaults["key"], "")  # the credential below, never a path in argv
        self.assertIn('filepath.Join(creds, "ledger-key")', main)

    def test_range_drop_in_adds_only_the_cap(self):
        # ADR 0036: only the image may lower the cap, through one variable the log-cap trial overrides;
        # its default is host_log_cap_gib, and the installed argv has no -cap-bytes.
        main = (REPO / "cmd" / "balistid-ledger" / "main.go").read_text()
        self.assertRegex(main, r'capBytes        = 10 << 30\n')
        self.assertRegex(main, r'flag\.Uint64\("cap-bytes", 0, "range only \(ADR 0036\)')
        drop_in = parse_unit((REPO / "range" / "balistid-ledger-range.conf").read_text())["Service"]
        installed = shlex.split(parse_unit(service_text())["Service"]["ExecStart"][0])
        self.assertNotIn("-cap-bytes", installed)
        self.assertEqual(set(drop_in), {"Environment", "ExecStart"})
        self.assertEqual(drop_in["Environment"], [f"BALISTID_RANGE_LEDGER_CAP={10 << 30}"])
        self.assertEqual(drop_in["ExecStart"][0], "")
        self.assertEqual([shlex.split(v) for v in drop_in["ExecStart"][1:]],
                         [installed + ["-cap-bytes", "${BALISTID_RANGE_LEDGER_CAP}"]])

    def test_paths_agree_across_files(self):
        service = parse_unit(service_text())["Service"]
        self.assertEqual(STATE, "/var/lib/" + service["StateDirectory"][0])
        self.assertEqual(SOCKET, f"/run/{service['RuntimeDirectory'][0]}/ledger.sock")
        self.assertIn(f"{STATE}/log", [entry[1] for entry in lines("tmpfiles.conf")])
        self.assertEqual(service["LoadCredential"][0].split(":")[0], "ledger-key")
        collector = (REPO / "cmd" / "balistid-collector" / "main.go").read_text()
        self.assertIn(f'ledgerSocket = "{SOCKET}"', collector)
        # The relay's cosigned checkpoint, in the relay's state directory (ADR 0029, point 1).
        main = (REPO / "cmd" / "balistid-ledger" / "main.go").read_text()
        relay = parse_unit((REPO / "deploy" / "relay" / "balistid-relay.service").read_text())["Service"]
        self.assertIn(f'flag.String("relay", "/var/lib/{relay["StateDirectory"][0]}/"+cosign.Name,', main)
        self.assertEqual(relay["Group"], service["SupplementaryGroups"])

    def test_tmpfiles(self):
        self.assertEqual(lines("tmpfiles.conf"), TMPFILES)

    def test_sysusers(self):
        self.assertEqual(lines("sysusers.conf"), SYSUSERS)

    def test_widened_service_fails(self):
        text = service_text()
        for old, new in (
            ("User=balistid-ledger", "User=root"),
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies=AF_UNIX AF_INET"),
            ("CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_DAC_OVERRIDE"),
            ("LoadCredential=ledger-key:/etc/balistid/ledger-key", "LoadCredential=ledger-key:/var/tmp/ledger-key"),
            ("StateDirectoryMode=0750", "StateDirectoryMode=0755"),
            ("UMask=0027", "UMask=0022"),
            ("ExecPaths=/usr/local/lib/balistid/balistid-ledger", "ExecPaths=/usr"),
            ("MemoryMax=128M", "MemoryMax=infinity"),
            ("TimeoutStopSec=90s", "TimeoutStopSec=10s"),
            ("SupplementaryGroups=balistid-relay", "SupplementaryGroups=balistid-relay balistid-collector"),
            ("SupplementaryGroups=balistid-relay", "SupplementaryGroups=balistid-collector"),
            ("Restart=always", "Restart=always\nReadWritePaths=/var/lib"),
            ("[Service]", "OnFailure=x.service\n[Service]"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, text)
                self.assertTrue(unit_problems(text.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
