"""Tests for deploy/announce (ADR 0030): the two announcement units carry exactly the decided settings, run
the ledger's binary as its uid with its sandbox, and their order around the relay and sleep holds.

As for the ledger, each section is compared whole and the forbidden directives are checked by name.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from test_ledger_deploy import (FORBIDDEN as LEDGER_FORBIDDEN, SERVICE as LEDGER_SERVICE, SOCKET,
                                service_text as ledger_text)
from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
ANNOUNCE = REPO / "deploy" / "announce"
BINARY = "/usr/local/lib/balistid/balistid-ledger"
FILES = {"balistid-announce.service", "balistid-announce-suspend.service"}
# The one directive allowed beyond the ledger's: the stop that announces a shutdown.
FORBIDDEN = LEDGER_FORBIDDEN - {"ExecStop"}
# The ledger's sandbox, without its process, directories, credential and limits: these units only ask.
SANDBOX = {k: v for k, v in LEDGER_SERVICE.items() if k not in {
    "Type", "Restart", "RestartSec", "ExecStart", "LoadCredential", "StateDirectory", "StateDirectoryMode",
    "RuntimeDirectory", "RuntimeDirectoryMode", "UMask", "MemoryMax", "TimeoutStopSec", "NoExecPaths",
    "RemoveIPC"}}
SANDBOX |= {"UMask": "0077", "MemoryMax": "64M", "NoExecPaths": "/ /tmp -/dev/shm"}

UNITS = {
    "balistid-announce.service": (
        {"Description": ["Balistid Blue: announce a clean shutdown to the witness"],
         "After": ["balistid-relay.service"]},
        {"Type": "oneshot", "RemainAfterExit": "yes", "ExecStop": f"{BINARY} -announce shutdown",
         "TimeoutStopSec": "30s"},
        "multi-user.target"),
    "balistid-announce-suspend.service": (
        {"Description": ["Balistid Blue: announce a suspend to the witness"], "Before": ["sleep.target"]},
        {"Type": "oneshot", "ExecStart": f"{BINARY} -announce suspend", "TimeoutStartSec": "30s"},
        "sleep.target"),
}


def unit_problems(name: str, text: str) -> list[str]:
    sections = parse_unit(text)
    problems = [f"[{s}] {k}" for s, d in sections.items() for k in d if k in FORBIDDEN]
    unit, process, wanted_by = UNITS[name]
    service = {k: v if isinstance(v, list) else [v] for k, v in (process | SANDBOX).items()}
    want = {"Unit": unit, "Service": service, "Install": {"WantedBy": [wanted_by]}}
    for section in sorted(set(sections) | set(want)):
        if sections.get(section) != want.get(section):
            problems.append(f"[{section}] is not exactly the decided settings")
    return problems


def text(name: str) -> str:
    return (ANNOUNCE / name).read_text()


class AnnounceDeployTest(unittest.TestCase):
    def test_exact_file_set(self):
        self.assertEqual({p.name for p in ANNOUNCE.iterdir()}, FILES)

    def test_units_have_exactly_the_decided_settings(self):
        for name in FILES:
            with self.subTest(name=name):
                self.assertEqual(unit_problems(name, text(name)), [])

    def test_they_run_as_the_ledger_with_its_sandbox(self):
        ledger = parse_unit(ledger_text())["Service"]
        for name in FILES:
            service = parse_unit(text(name))["Service"]
            for key in ("User", "Group", "SupplementaryGroups", "ExecPaths", "SystemCallFilter", "PrivateNetwork"):
                with self.subTest(name=name, key=key):
                    self.assertEqual(service[key], ledger[key])

    def test_the_client_takes_the_ledgers_defaults(self):
        main = (REPO / "cmd" / "balistid-ledger" / "main.go").read_text()
        defaults = dict(re.findall(r'flag\.String\("([a-z-]+)", "([^"]*)"', main))
        # The control socket sits beside the collector's, in the ledger's runtime directory.
        self.assertEqual(defaults["control"], SOCKET.rsplit("/", 1)[0] + "/control.sock")
        for name, key in (("balistid-announce.service", "ExecStop"), ("balistid-announce-suspend.service", "ExecStart")):
            argv = shlex.split(parse_unit(text(name))["Service"][key][0])
            with self.subTest(name=name):
                self.assertEqual(argv[0], BINARY)
                self.assertEqual(argv[1], "-announce")
                self.assertIn(argv[2], {"shutdown", "suspend"})
                self.assertEqual(len(argv), 3)

    def test_widened_units_fail(self):
        for name, old, new in (
            ("balistid-announce.service", "User=balistid-ledger", "User=root"),
            ("balistid-announce.service", "After=balistid-relay.service", "Before=balistid-relay.service"),
            ("balistid-announce.service", "ExecStop=/usr/local/lib/balistid/balistid-ledger -announce shutdown",
             "ExecStop=/bin/sh -c true"),
            ("balistid-announce.service", "RemainAfterExit=yes", "RemainAfterExit=no"),
            ("balistid-announce.service", "PrivateNetwork=yes", "PrivateNetwork=no"),
            ("balistid-announce.service", "Type=oneshot", "Type=oneshot\nRuntimeDirectory=balistid-ledger"),
            ("balistid-announce-suspend.service", "Before=sleep.target", "After=sleep.target"),
            ("balistid-announce-suspend.service", "WantedBy=sleep.target", "WantedBy=multi-user.target"),
            ("balistid-announce-suspend.service", "Type=oneshot", "Type=oneshot\nExecStop=/bin/true"),
            ("balistid-announce-suspend.service", "CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_KILL"),
            ("balistid-announce-suspend.service", "[Service]", "OnFailure=x.service\n[Service]"),
        ):
            with self.subTest(name=name, new=new):
                self.assertIn(old, text(name))
                self.assertTrue(unit_problems(name, text(name).replace(old, new)))


if __name__ == "__main__":
    unittest.main()
