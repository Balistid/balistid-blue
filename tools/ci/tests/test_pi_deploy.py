"""Tests for deploy/pi (ADR 0031): the watcher's units and user carry exactly the decided settings, and their
paths and flags agree with cmd/balistid-pi.

As for the relay, each section is compared whole and the forbidden directives are checked by name; the one
allowed beyond the collector's is OnFailure, the alert that the watcher failed.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_collector_deploy import FORBIDDEN as COLLECTOR_FORBIDDEN, lines as collector_lines
from test_relay_deploy import SERVICE as RELAY_SERVICE
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
PI = REPO / "deploy" / "pi"
BINARY = "/usr/local/lib/balistid/balistid-pi"
FILES = {"sysusers.conf", "balistid-pi.service", "balistid-pi-failed.service"}
FORBIDDEN = COLLECTOR_FORBIDDEN - {"OnFailure"}
ENV = "/etc/balistid-pi/pi.env"
CREDENTIAL = "ntfy-token:/etc/balistid-pi/ntfy-token"

# The relay's sandbox, without what is the relay's own: its group, its address allowlist, its state.
SANDBOX = {k: v for k, v in RELAY_SERVICE.items() if k not in {
    "Type", "Restart", "RestartSec", "User", "Group", "SupplementaryGroups", "EnvironmentFile", "ExecStart",
    "StateDirectory", "StateDirectoryMode", "MemoryMax", "NoExecPaths", "ExecPaths", "IPAddressDeny", "IPAddressAllow",
    "RemoveIPC"}}

WATCHER_UNIT = {
    "Description": ["Balistid Blue Pi: verify the host's log and alert the phone"],
    "OnFailure": ["balistid-pi-failed.service"],
    "StartLimitIntervalSec": ["0"],
}
WATCHER = {
    **SANDBOX,
    "Type": "notify",
    "WatchdogSec": "2min",
    "Restart": "always",
    "RestartSec": "30s",
    "RestartSteps": "5",
    "RestartMaxDelaySec": "10min",
    "User": "balistid-pi",
    "Group": "balistid-pi",
    "EnvironmentFile": ENV,
    "LoadCredential": CREDENTIAL,
    "ExecStart": f"{BINARY} -origin ${{BALISTID_PI_ORIGIN}} -witness ${{BALISTID_PI_WITNESS}} "
                 "-relay ${BALISTID_PI_RELAY} -ntfy ${BALISTID_PI_NTFY}",
    "StateDirectory": "balistid-pi",
    "StateDirectoryMode": "0750",
    "MemoryMax": "128M",
    "NoExecPaths": "/ /var/lib/balistid-pi /tmp -/dev/shm",
    "ExecPaths": BINARY,
    "RemoveIPC": "yes",
}
FAILED_UNIT = {"Description": ["Balistid Blue Pi: alert that the watcher failed"]}
FAILED = {
    **SANDBOX,
    "Type": "oneshot",
    "User": "balistid-pi",
    "Group": "balistid-pi",
    "EnvironmentFile": ENV,
    "LoadCredential": CREDENTIAL,
    "ExecStart": f"{BINARY} -alert-failed -ntfy ${{BALISTID_PI_NTFY}}",
    "TimeoutStartSec": "30s",
    "MemoryMax": "64M",
    "NoExecPaths": "/ /tmp -/dev/shm",
    "ExecPaths": BINARY,
}
SYSUSERS = [("u", "balistid-pi", "-", "Balistid Blue Pi watcher")]


def unit_problems(text: str, unit: dict, service: dict, install: dict | None) -> list[str]:
    sections = parse_unit(text)
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    want = {"Unit": unit, "Service": {k: v if isinstance(v, list) else [v] for k, v in service.items()}}
    if install is not None:
        want["Install"] = install
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    return problems


def watcher_problems(text: str) -> list[str]:
    return unit_problems(text, WATCHER_UNIT, WATCHER, {"WantedBy": ["multi-user.target"]})


def text(name: str) -> str:
    return (PI / name).read_text()


class PiDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in PI.iterdir()}, FILES)

    def test_units_have_exactly_the_decided_settings(self):
        self.assertEqual(watcher_problems(text("balistid-pi.service")), [])
        self.assertEqual(unit_problems(text("balistid-pi-failed.service"), FAILED_UNIT, FAILED, None), [])

    def test_exec_start_matches_the_flags(self):
        main = (REPO / "cmd" / "balistid-pi" / "main.go").read_text()
        flags = set(re.findall(r'flag\.(?:String|Int64|Bool)\("([a-z-]+)"', main))
        defaults = dict(re.findall(r'flag\.String\("([a-z-]+)", "([^"]*)"', main))
        argv = shlex.split(parse_unit(text("balistid-pi.service"))["Service"]["ExecStart"][0])
        self.assertTrue({a[1:] for a in argv[1::2]} <= flags)
        self.assertEqual(defaults["state"], "/var/lib/" + WATCHER["StateDirectory"])
        for name in ("origin", "witness", "relay", "ntfy"):
            self.assertEqual(defaults[name], "")  # nothing to watch or alert unless the Pi's config names it
        self.assertIn(f'tokenName   = "{CREDENTIAL.split(":")[0]}"', main)

    def test_range_drop_in_adds_only_the_quiet_cap(self):
        # ADR 0036: only the image shortens the quiet cap; its argv is the installed one plus -quiet, whose
        # default keeps announced_quiet_max_h on a real Pi.
        main = (REPO / "cmd" / "balistid-pi" / "main.go").read_text()
        self.assertRegex(main, r'flag\.Duration\("quiet", 0, "range only \(ADR 0036\)')
        drop_in = parse_unit((REPO / "range" / "balistid-pi-range.conf").read_text())["Service"]
        installed = shlex.split(parse_unit(text("balistid-pi.service"))["Service"]["ExecStart"][0])
        self.assertNotIn("-quiet", installed)
        self.assertEqual(set(drop_in), {"NetworkNamespacePath", "EnvironmentFile", "Environment", "SetCredential",
                                        "ExecStart"})
        self.assertEqual(drop_in["ExecStart"][0], "")
        self.assertEqual([shlex.split(v) for v in drop_in["ExecStart"][1:]], [installed + ["-quiet", "20m"]])

    def test_sysusers(self):
        self.assertEqual(collector_lines("sysusers.conf", text("sysusers.conf")), SYSUSERS)

    def test_widened_service_fails(self):
        unit = text("balistid-pi.service")
        for old, new in (
            ("User=balistid-pi", "User=root"),
            ("User=balistid-pi", "User=litewitness"),
            ("LoadCredential=ntfy-token:/etc/balistid-pi/ntfy-token", "Environment=NTFY_TOKEN=tk_x"),
            ("CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_NET_RAW"),
            ("ProtectSystem=strict", "ProtectSystem=full"),
            ("UMask=0077", "UMask=0022"),
            ("ExecPaths=/usr/local/lib/balistid/balistid-pi", "ExecPaths=/usr"),
            ("Restart=always", "Restart=always\nSupplementaryGroups=litewitness"),
            ("Restart=always", "Restart=always\nReadWritePaths=/var/lib/litewitness"),
            ("Type=notify", "Type=simple"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, unit)
                self.assertTrue(watcher_problems(unit.replace(old, new)))


if __name__ == "__main__":
    unittest.main()
