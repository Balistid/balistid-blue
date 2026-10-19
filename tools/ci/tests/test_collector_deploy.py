"""Tests for deploy/collector (ADR 0016, 0017): the socket, the service, the user and the directories
carry exactly the decided settings, and nothing that would widen them.

Each section is compared whole, so a directive added, dropped, repeated or changed fails; the
forbidden directives are also checked by name, so that list survives a looser comparison.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_runner_deploy import docs_budget, parse_unit

REPO = Path(__file__).resolve().parents[3]
COLLECTOR = REPO / "deploy" / "collector"
BINARY = "/usr/local/lib/balistid/balistid-collector"
STATE = "/var/lib/balistid/collector"
SOCKET_PATH = "/run/balistid/collector.sock"
FILES = {"sysusers.conf", "tmpfiles.conf", "balistid-collector.service", "balistid-collector.socket"}

# ADR 0016, point 1: only root and Laurel's group reach the socket; one listener, not one per connection.
SOCKET = {
    "Unit": {
        "Description": ["Balistid Blue collector: the socket Laurel writes to"],
        "DefaultDependencies": ["no"],
        "After": ["systemd-sysusers.service"],
        "Before": ["sockets.target auditd.service shutdown.target"],
        "Conflicts": ["shutdown.target"],
    },
    "Socket": {
        "ListenStream": [SOCKET_PATH],
        "Accept": ["no"],
        "SocketGroup": ["_laurel"],
        "SocketMode": ["0660"],
        "RemoveOnStop": ["yes"],
    },
    "Install": {"WantedBy": ["sockets.target"]},
}
SERVICE_UNIT = {
    "Description": ["Balistid Blue collector: Laurel's records into the raw store"],
    "DefaultDependencies": ["no"],
    "Requires": ["balistid-collector.socket"],
    "After": ["balistid-collector.socket local-fs.target systemd-tmpfiles-setup.service systemd-sysusers.service"],
    "Before": ["auditd.service shutdown.target"],
    "Conflicts": ["shutdown.target"],
    "StartLimitIntervalSec": ["0"],
}
# ADR 0007 (own uid, no privilege), 0016 (memory), 0017 (notify, watchdog, no exec; T18).
SERVICE = {
    "Type": "notify",
    "WatchdogSec": "10s",
    "Restart": "always",
    "RestartSec": "1s",
    "User": "balistid-collector",
    "Group": "balistid-collector",
    "ExecStart": f"{BINARY} -store {STATE}/store -canary {STATE}/canary -rule-version adr-0004-v1",
    "StateDirectory": "balistid/collector",
    "StateDirectoryMode": "0700",
    "UMask": "0077",
    "MemoryMax": "384M",  # within acceptance rss_mib (512 MiB for all of floor 0)
    "MemorySwapMax": "0",
    "NoExecPaths": f"/ {STATE} /tmp -/dev/shm",
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
    "SystemCallArchitectures": "native",
    # An allowlist, then what is taken out of it: exec by another path, other processes' memory.
    "SystemCallFilter": ["@system-service",
                         "~@keyring memfd_create execveat process_vm_readv process_vm_writev"],
    "SystemCallErrorNumber": "EPERM",
}
# Directives that would give the collector root, capabilities, the network, a shared or a dynamic uid,
# or a way to run another program. Checked in every section of both units, whatever their value.
FORBIDDEN = {"AmbientCapabilities", "DynamicUser", "SetUID", "SetGID", "SupplementaryGroups",
             "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "ReadWritePaths", "BindPaths",
             "JoinsNamespaceOf", "OnFailure", "OnSuccess", "PermissionsStartOnly"}

TMPFILES = [
    ("d", "/var/lib/balistid", "0755", "root", "root", "-"),
    ("d", STATE, "0700", "balistid-collector", "balistid-collector", "-"),
    ("d", f"{STATE}/store", "0700", "balistid-collector", "balistid-collector", "-"),
    ("d", f"{STATE}/canary", "0700", "balistid-collector", "balistid-collector", "-"),
]
SYSUSERS = [("u", "balistid-collector", "-", "Balistid Blue collector")]


def unit_problems(name: str, text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"{name}: [{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    if name.endswith(".socket"):
        want = SOCKET
    else:
        want = {"Unit": SERVICE_UNIT, "Service": {k: v if isinstance(v, list) else [v] for k, v in SERVICE.items()},
                "Install": {"WantedBy": ["sysinit.target"]}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"{name}: [{section}] is not exactly the decided settings")
    return problems


def lines(name: str, text: str | None = None) -> list[tuple[str, ...]]:
    text = (COLLECTOR / name).read_text() if text is None else text
    # systemd-tmpfiles and -sysusers expand C escapes and % specifiers, which shlex does not.
    if docs_budget.unreadable_line(text.encode()) or "\\" in text or "%" in text:
        raise ValueError(f"{name}: a line the tests would read differently from systemd")
    return [tuple(shlex.split(line)) for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def deployed_service() -> dict[str, list[str]]:
    """The [Service] section of the unit as committed, not the expected values above."""
    return parse_unit((COLLECTOR / "balistid-collector.service").read_text())["Service"]


class CollectorDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in COLLECTOR.iterdir()}, FILES)

    def test_units_have_exactly_the_decided_settings(self):
        for name in ("balistid-collector.socket", "balistid-collector.service"):
            with self.subTest(name=name):
                self.assertEqual(unit_problems(name, (COLLECTOR / name).read_text()), [])

    def test_exec_start_takes_the_collectors_own_flags_and_defaults(self):
        main = (REPO / "cmd" / "balistid-collector" / "main.go").read_text()
        defaults = dict(re.findall(r'flag\.String\("([a-z-]+)", "([^"]*)"', main))
        [exec_start] = deployed_service()["ExecStart"]
        argv = shlex.split(exec_start)
        self.assertEqual(argv[0], BINARY)
        self.assertEqual(argv[1::2], [f"-{f}" for f in defaults])
        given = dict(zip((a[1:] for a in argv[1::2]), argv[2::2]))
        for flag in ("store", "canary"):
            self.assertEqual(given[flag], defaults[flag], flag)

    def test_paths_agree_across_files(self):
        service = deployed_service()
        argv = shlex.split(service["ExecStart"][0])
        dirs = [entry[1] for entry in lines("tmpfiles.conf")]
        for flag in ("-store", "-canary"):
            self.assertIn(argv[argv.index(flag) + 1], dirs)
        self.assertEqual(STATE, "/var/lib/" + service["StateDirectory"][0])
        self.assertEqual(service["ExecPaths"], [argv[0]])
        self.assertIn(SOCKET_PATH, (REPO / "adr").joinpath(
            next(p.name for p in (REPO / "adr").iterdir() if p.name.startswith("0016-"))).read_text())

    def test_rule_version_names_the_installed_rules(self):
        argv = shlex.split(SERVICE["ExecStart"])
        version = argv[argv.index("-rule-version") + 1]
        rules = (REPO / "deploy" / "audit" / "balistid.rules").read_text().splitlines()
        self.assertEqual([l for l in rules if l.startswith("## version: ")],
                         [f"## version: {version} (the collector's -rule-version names it in its started record)"])

    def test_tmpfiles(self):
        self.assertEqual(lines("tmpfiles.conf"), TMPFILES)

    def test_sysusers(self):
        self.assertEqual(lines("sysusers.conf"), SYSUSERS)

    def test_lines_systemd_would_read_differently_are_refused(self):
        tmpfiles = (COLLECTOR / "tmpfiles.conf").read_text()
        for planted in (tmpfiles.replace("/canary", "/c\\anary"), tmpfiles.replace("/store", "/%h"),
                        tmpfiles + "# c\u2028d /var/lib/x 0777 root root -\n", tmpfiles.replace("0700", "0700\u00a0", 1)):
            with self.subTest(planted=planted[-40:]), self.assertRaises(ValueError):
                lines("tmpfiles.conf", planted)


class UnitCheckTest(unittest.TestCase):
    """The check itself: every way to widen a unit is caught."""

    def text(self, name: str) -> str:
        return (COLLECTOR / name).read_text()

    def test_widened_service_fails(self):
        name = "balistid-collector.service"
        for old, new in (
            ("User=balistid-collector", "User=root"),
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=yes\nAmbientCapabilities=CAP_SYS_ADMIN"),
            ("CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_DAC_OVERRIDE"),
            ("NoExecPaths=/ /var/lib/balistid/collector /tmp -/dev/shm", "NoExecPaths=/"),
            ("ExecPaths=/usr/local/lib/balistid/balistid-collector", "ExecPaths=/usr"),
            ("RestrictAddressFamilies=AF_UNIX", "RestrictAddressFamilies=AF_UNIX AF_INET"),
            ("MemoryMax=384M", "MemoryMax=384M\nMemoryMax=infinity"),
            ("UMask=0077", "UMask=0022"),
            ("Type=notify\n", ""),
            ("WatchdogSec=10s", "WatchdogSec=0"),
            ("StateDirectoryMode=0700", "StateDirectoryMode=0755"),
            ("SystemCallFilter=~@keyring memfd_create execveat process_vm_readv process_vm_writev",
             "SystemCallFilter=~@keyring"),
            ("SystemCallErrorNumber=EPERM", "SystemCallErrorNumber=EPERM\nExecStartPre=/bin/sh -c x"),
            ("Restart=always", "Restart=always\nReadWritePaths=/var/lib"),
            ("[Service]", "OnFailure=x.service\n[Service]"),
            ("WantedBy=sysinit.target", "WantedBy=multi-user.target"),
            ("Before=auditd.service shutdown.target", "Before=shutdown.target"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, self.text(name))
                self.assertTrue(unit_problems(name, self.text(name).replace(old, new)))

    def test_widened_socket_fails(self):
        name = "balistid-collector.socket"
        for old, new in (
            ("SocketMode=0660", "SocketMode=0666"),
            ("SocketGroup=_laurel", "SocketGroup=users"),
            ("Accept=no", "Accept=no\nSocketUser=nobody"),
            ("Accept=no", "Accept=yes"),
            ("ListenStream=/run/balistid/collector.sock", "ListenStream=/tmp/collector.sock"),
            ("ListenStream=/run/balistid/collector.sock",
             "ListenStream=/run/balistid/collector.sock\nListenStream=127.0.0.1:9"),
            ("[Socket]", "[Socket]\nExecStartPre=/bin/true"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, self.text(name))
                self.assertTrue(unit_problems(name, self.text(name).replace(old, new)))


if __name__ == "__main__":
    unittest.main()
