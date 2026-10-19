"""Tests for deploy/runner (ADR 0011): the units, users and directories root installs for the range
runner carry exactly the decided settings, and nothing that would widen them.

Each unit's [Service] section is compared whole, so a directive added, dropped, repeated or changed
fails; the forbidden directives are also checked by name, so that list survives a looser comparison.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "ci"))
import docs_budget  # noqa: E402
RUNNER = REPO / "deploy" / "runner"
BINARY = "/usr/local/lib/balistid/balistid-runner"
STATE = "/var/lib/balistid-runner"
FILES = {"install", "sysusers.conf", "tmpfiles.conf", "balistid-runner-build.service",
         "balistid-runner-tick.service", "balistid-runner-tick.timer"}

# Both services (ADR 0011, point 1; ENGINEERING.md 7 for GOMEMLIMIT and the umask).
COMMON = {
    "Type": "oneshot",
    "User": "balistid-runner",
    "Group": "balistid-runner",
    "StateDirectory": "balistid-runner",
    "StateDirectoryMode": "0700",
    "UMask": "0027",
    "MemorySwapMax": "0",
    "DevicePolicy": "closed",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "",
    "LockPersonality": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "ProtectClock": "yes",
    "RestrictRealtime": "yes",
    "SystemCallArchitectures": "native",
}
SERVICES = {
    "balistid-runner-build.service": {
        **COMMON,
        "ExecStart": f"{BINARY} build --state {STATE} --objects /var/lib/balistid/objects",
        "Environment": "GOMEMLIMIT=128MiB",
        "MemoryMax": "3G",  # acceptance runner_build_memory_gib
        "TimeoutStartSec": "30min",
        "ProtectKernelTunables": "yes",
        "ProtectKernelLogs": "yes",
    },
    # No RestrictSUIDSGID on either unit: the image needs its setuid files, and on the tick its seccomp
    # filter turns bwrap's open_tree into ENOSYS (first install, 2026-10-07).
    # No ProtectKernelTunables or ProtectKernelLogs: their mounts over /proc make bwrap's new /proc
    # fail with EPERM in its user namespace.
    "balistid-runner-tick.service": {
        **COMMON,
        "ExecStart": (f"{BINARY} tick --state {STATE} --inbox /var/lib/balistid/inbox"
                      " --results /var/lib/balistid/results"),
        "SupplementaryGroups": "kvm",
        "ReadWritePaths": "/var/lib/balistid/results",
        "Environment": "GOMEMLIMIT=192MiB",
        "MemoryMax": "2560M",  # acceptance runner_job_memory_gib
        "TasksMax": "256",
        "CPUSchedulingPolicy": "idle",
        "TimeoutStartSec": "40min",
        "PrivateNetwork": "yes",
        "DeviceAllow": "/dev/kvm rw",
        # An allowlist, then what is taken out of it; the tick's keyctl check expects EPERM (R7).
        "SystemCallFilter": ["@system-service @mount", "~@keyring @aio process_vm_readv process_vm_writev"],
        "SystemCallErrorNumber": "EPERM",
        "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
        "IPAddressDeny": "any",
        "PrivateIPC": "yes",
        "RemoveIPC": "yes",
    },
}
TIMER = {"OnBootSec": "10min", "OnUnitInactiveSec": "15min"}
# [Unit] holds only a description, so no Wants=, OnSuccess= or JoinsNamespaceOf= can join another unit.
DESCRIPTIONS = {
    "balistid-runner-build.service": "Balistid Blue range runner: build its image",
    "balistid-runner-tick.service": "Balistid Blue range runner: one evidence run or agent job",
    "balistid-runner-tick.timer": "Balistid Blue range runner: tick every 15 minutes",
}
# Directives that would give the runner root, capabilities, the network during a job, or take away
# the user namespaces bwrap and mkosi need. Checked in every section, whatever their value.
FORBIDDEN = {"AmbientCapabilities", "RestrictNamespaces", "PrivateUsers", "DynamicUser",
             "PrivateDevices", "SetUID", "SetGID"}

TMPFILES = [
    ("d", "/var/lib/balistid", "0755", "root", "root", "-"),
    ("d", "/var/lib/balistid/results", "0750", "balistid-runner", "balistid-agents", "-"),
    ("d", "/var/lib/balistid/results/agent", "2750", "balistid-runner", "balistid-agents", "-"),
    ("d", "/var/lib/balistid/results/evidence", "2750", "balistid-runner", "balistid-agents", "-"),
    ("d", "/var/lib/balistid/results/acceptance", "2750", "balistid-runner", "balistid-agents", "-"),
]
SYSUSERS = [
    ("u", "balistid-runner", "-", "Balistid Blue range runner"),
    ("g", "balistid-agents", "-"),
]


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    """Sections of a unit file, each mapping a directive to all its values in order. Continuation
    lines are refused, so no directive can hide on the next line, and so is any line outside the gate's
    allowlist: Python and systemd end lines at different characters (U+2028 and U+0085 only Python, NUL
    only systemd) and strip different spaces."""
    if number := docs_budget.unreadable_line(text.encode()):
        raise ValueError(f"line {number}: outside the root-installed line allowlist")
    sections: dict[str, dict[str, list[str]]] = {}
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.endswith("\\"):
            raise ValueError(f"line {number}: continuation line")
        if stripped.startswith("[") and stripped.endswith("]"):
            current = sections.setdefault(stripped[1:-1], {})
            continue
        key, sep, value = stripped.partition("=")
        if current is None or not sep:
            raise ValueError(f"line {number}: not a directive in a section")
        current.setdefault(key.strip(), []).append(value.strip())
    return sections


def service_problems(name: str, text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"{name}: [{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    service = sections.get("Service", {})
    if service.get("User") == ["root"]:
        problems.append(f"{name}: User=root")
    if service != {k: v if isinstance(v, list) else [v] for k, v in SERVICES[name].items()}:
        problems.append(f"{name}: [Service] is not exactly the decided settings")
    if sections.get("Unit") != {"Description": [DESCRIPTIONS[name]]}:
        problems.append(f"{name}: [Unit] is not exactly its description")
    if set(sections) != {"Unit", "Service"}:
        problems.append(f"{name}: sections {sorted(sections)}; the install or its timer starts it")
    return problems


def lines(name: str) -> list[list[str]]:
    text = (RUNNER / name).read_text()
    # systemd-tmpfiles and -sysusers expand C escapes and % specifiers, which shlex does not.
    if docs_budget.unreadable_line(text.encode()) or "\\" in text or "%" in text:
        raise ValueError(f"{name}: a line the tests would read differently from systemd")
    return [shlex.split(line) for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class RunnerDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in RUNNER.iterdir()}, FILES)

    def test_services_have_exactly_the_decided_settings(self):
        for name in SERVICES:
            with self.subTest(name=name):
                self.assertEqual(service_problems(name, (RUNNER / name).read_text()), [])

    def test_exec_start_is_absolute_with_exactly_the_runner_flags(self):
        # The flags each command takes, from the runner itself, so the units follow its usage.
        main = (REPO / "cmd" / "balistid-runner" / "main.go").read_text()
        for command in ("build", "tick"):
            with self.subTest(command=command):
                flags = re.search(rf'"{command}": \{{([^}}]*)\}}', main)
                self.assertIsNotNone(flags)
                want = re.findall(r'"([a-z]+)"', flags.group(1))
                argv = shlex.split(SERVICES[f"balistid-runner-{command}.service"]["ExecStart"])
                self.assertEqual(argv[0], BINARY)
                self.assertTrue(Path(argv[0]).is_absolute())
                self.assertEqual(argv[1], command)
                self.assertEqual(argv[2::2], [f"--{f}" for f in want])
                for path in argv[3::2]:
                    self.assertTrue(path.startswith("/") and os.path.normpath(path) == path, path)

    def test_paths_agree_across_files(self):
        tick = shlex.split(SERVICES["balistid-runner-tick.service"]["ExecStart"])
        results = tick[tick.index("--results") + 1]
        self.assertEqual(SERVICES["balistid-runner-tick.service"]["ReadWritePaths"], results)
        self.assertEqual(STATE, "/var/lib/" + COMMON["StateDirectory"])
        self.assertIn(results, [entry[1] for entry in TMPFILES])

    def test_tick_has_no_network_and_kvm_only(self):
        tick = parse_unit((RUNNER / "balistid-runner-tick.service").read_text())["Service"]
        self.assertEqual(tick["PrivateNetwork"], ["yes"])
        self.assertEqual(tick["DeviceAllow"], ["/dev/kvm rw"])
        build = parse_unit((RUNNER / "balistid-runner-build.service").read_text())["Service"]
        self.assertNotIn("DeviceAllow", build)
        self.assertNotIn("SupplementaryGroups", build)
        self.assertEqual(build["DevicePolicy"], ["closed"])

    def test_timer(self):
        timer = parse_unit((RUNNER / "balistid-runner-tick.timer").read_text())
        self.assertEqual(set(timer), {"Unit", "Timer", "Install"})
        self.assertEqual(timer["Unit"], {"Description": [DESCRIPTIONS["balistid-runner-tick.timer"]]})
        self.assertEqual(timer["Timer"], {k: [v] for k, v in TIMER.items()})
        self.assertEqual(timer["Install"], {"WantedBy": ["timers.target"]})
        self.assertNotIn("Persistent", timer["Timer"])

    def test_tmpfiles(self):
        self.assertEqual([tuple(entry) for entry in lines("tmpfiles.conf")], TMPFILES)

    def test_sysusers(self):
        self.assertEqual([tuple(entry) for entry in lines("sysusers.conf")], SYSUSERS)


class ServiceCheckTest(unittest.TestCase):
    """The check itself: every way to widen a unit is caught."""

    NAME = "balistid-runner-tick.service"

    def text(self) -> str:
        return (RUNNER / self.NAME).read_text()

    def test_forbidden_or_changed_directives_fail(self):
        for old, new in (
            ("User=balistid-runner", "User=root"),
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=yes\nAmbientCapabilities=CAP_SYS_ADMIN"),
            ("LockPersonality=yes", "LockPersonality=yes\nRestrictNamespaces=yes"),
            ("LockPersonality=yes", "LockPersonality=yes\nPrivateUsers=yes"),
            ("CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_SYS_ADMIN"),
            ("MemoryMax=2560M", "MemoryMax=2560M\nMemoryMax=infinity"),
            ("ReadWritePaths=/var/lib/balistid/results", "ReadWritePaths=/var/lib/balistid"),
            ("DeviceAllow=/dev/kvm rw", "DeviceAllow=/dev/kvm rw\nDeviceAllow=char-misc rw"),
            ("UMask=0027", ""),
            ("[Service]", "JoinsNamespaceOf=balistid-collector.service\n[Service]"),
            ("[Service]", "OnSuccess=x.service\n[Service]"),
            ("SystemCallFilter=@system-service @mount", "SystemCallFilter=~@clock @debug @module @raw-io"),
            ("SystemCallFilter=@system-service @mount", "SystemCallFilter=@system-service @mount @privileged"),
            ("SystemCallFilter=~@keyring @aio process_vm_readv process_vm_writev\n", ""),
            ("SystemCallFilter=~@keyring @aio process_vm_readv process_vm_writev", "SystemCallFilter=~@aio"),
            ("SystemCallFilter=@system-service @mount\nSystemCallFilter=~@keyring @aio process_vm_readv process_vm_writev",
             "SystemCallFilter=~@keyring @aio process_vm_readv process_vm_writev\nSystemCallFilter=@system-service @mount"),
            ("SystemCallErrorNumber=EPERM", "SystemCallErrorNumber=ENOSYS"),
            ("SystemCallErrorNumber=EPERM", "SystemCallErrorNumber=EPERM\nSystemCallLog=@keyring"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, self.text())
                self.assertTrue(service_problems(self.NAME, self.text().replace(old, new)))

    def test_install_section_fails(self):
        enabled = self.text() + "[Install]\nWantedBy=multi-user.target\n"
        self.assertTrue(service_problems(self.NAME, enabled))

    def test_line_outside_the_allowlist_is_refused(self):
        for line in ("# x\x00User=root", "# x\rUser=root", "# x\u2028User=root", "# x\x85User=root",
                     "NoNewPrivileges=yes\u00a0", "# " + "x" * 199):
            with self.subTest(line=line[:12]), self.assertRaises(ValueError):
                parse_unit(f"[Service]\n{line}\n")
        self.assertEqual(parse_unit("[Service]\n# " + "x" * 198 + "\n"), {"Service": {}})

    def test_continuation_line_is_refused(self):
        with self.assertRaises(ValueError):
            parse_unit("[Service]\nExecStart=/bin/x \\\n  --flag\n")


if __name__ == "__main__":
    unittest.main()
