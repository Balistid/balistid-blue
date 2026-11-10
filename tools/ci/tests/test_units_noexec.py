"""Tests for the no-exec rule across deploy/ (T18): a unit that gets a private /tmp lists it in NoExecPaths, and
/var/tmp beside it wherever systemd mounts a private one, because the remount of / skips the unit's own mounts.

PrivateTmp=disconnected with DefaultDependencies=no and no mount dependency on /var leaves the host's /var/tmp in
place (systemd.exec(5), table "Summary for PrivateTmp=disconnected"); that one is under the noexec of /.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
OFF = {"", "no", "false", "off", "0"}
# The runner executes bwrap and QEMU and has no NoExecPaths at all (ADR 0011).
EXECUTING = {"balistid-runner-build.service", "balistid-runner-tick.service"}
# Early-boot units: no private /var/tmp, see above.
HOST_VAR_TMP = {"balistid-collector.service", "balistid-ledger.service", "balistid-net.service"}


def last(section: dict[str, list[str]], key: str) -> str:
    return (section.get(key) or [""])[-1].strip().lower()


def private_tmp(sections: dict[str, dict[str, list[str]]]) -> str:
    service = sections.get("Service", {})
    value = last(service, "PrivateTmp")
    if value in OFF and last(service, "DynamicUser") not in OFF:
        return "disconnected"
    return "" if value in OFF else value


def private_var_tmp(sections: dict[str, dict[str, list[str]]]) -> bool:
    unit, service = sections.get("Unit", {}), sections.get("Service", {})
    mode = private_tmp(sections)
    if mode != "disconnected":
        return mode != ""
    waits = [p for k in ("RequiresMountsFor", "WantsMountsFor") for v in unit.get(k, []) for p in v.split()]
    var_mount = any(p.startswith("/var") for p in waits)
    rooted = "RootDirectory" in service or "RootImage" in service
    return last(unit, "DefaultDependencies") != "no" or var_mount or rooted


def noexec_problems(text: str) -> list[str]:
    sections = parse_unit(text)
    if not private_tmp(sections):
        return []
    want = {"/", "/tmp"} | ({"/var/tmp"} if private_var_tmp(sections) else set())
    listed = {p.lstrip("-+") for v in sections.get("Service", {}).get("NoExecPaths", []) for p in v.split()}
    return [f"NoExecPaths lacks {p}" for p in sorted(want - listed)]


def units() -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(REPO.glob("deploy/*/*.service"))}


class UnitsNoExecTest(unittest.TestCase):
    def test_every_unit_with_a_private_tmp_keeps_it_noexec(self):
        checked = {name: text for name, text in units().items() if name not in EXECUTING}
        self.assertGreater(len(checked), len(HOST_VAR_TMP))
        for name, text in checked.items():
            with self.subTest(unit=name):
                self.assertTrue(private_tmp(parse_unit(text)))
                self.assertEqual(noexec_problems(text), [])

    def test_only_the_early_boot_units_keep_the_hosts_var_tmp(self):
        host = {name for name, text in units().items() if private_tmp(parse_unit(text)) and not private_var_tmp(parse_unit(text))}
        self.assertEqual(host, HOST_VAR_TMP)

    def test_the_executing_units_are_the_ones_without_noexec_paths(self):
        bare = {name for name, text in units().items() if "NoExecPaths" not in parse_unit(text).get("Service", {})}
        self.assertEqual(bare, EXECUTING)

    def test_a_unit_missing_a_private_mount_fails(self):
        relay = units()["balistid-relay.service"]
        line = "NoExecPaths=/ /var/lib/balistid /tmp /var/tmp -/dev/shm"
        self.assertIn(line, relay)
        for new, problem in (
            (line.replace(" /var/tmp", ""), "NoExecPaths lacks /var/tmp"),
            (line.replace(" /tmp /var/tmp", " /var/tmp"), "NoExecPaths lacks /tmp"),
            (line.replace("=/ ", "="), "NoExecPaths lacks /"),
        ):
            with self.subTest(new=new):
                self.assertEqual(noexec_problems(relay.replace(line, new)), [problem])
        for mode in ("yes", "true"):
            text = relay.replace(line, line.replace(" /var/tmp", "")).replace("PrivateTmp=disconnected", f"PrivateTmp={mode}")
            self.assertEqual(noexec_problems(text), ["NoExecPaths lacks /var/tmp"])

    def test_an_early_boot_unit_that_waits_for_var_needs_var_tmp(self):
        ledger = units()["balistid-ledger.service"]
        self.assertEqual(noexec_problems(ledger), [])
        for old, new in (
            ("DefaultDependencies=no\n", ""),
            ("DefaultDependencies=no", "DefaultDependencies=no\nRequiresMountsFor=/var"),
            ("DefaultDependencies=no", "DefaultDependencies=no\nWantsMountsFor=/var/tmp"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, ledger)
                self.assertEqual(noexec_problems(ledger.replace(old, new)), ["NoExecPaths lacks /var/tmp"])


if __name__ == "__main__":
    unittest.main()
