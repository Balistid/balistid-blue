"""Tests for probe_noexec.py's arguments; the probe itself needs root and systemd, so it runs in probe.yml."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import probe_noexec  # noqa: E402
from test_units_noexec import units  # noqa: E402


def props(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "-p"]


class ProbeArgsTest(unittest.TestCase):
    def test_the_relay_runs_with_its_mount_sandbox_only(self):
        args, dirs = probe_noexec.run_args(units()["balistid-relay.service"])
        p = props(args)
        self.assertEqual(p[0], "ExecPaths=/usr")
        self.assertIn("NoExecPaths=/ /var/lib/balistid/relay /tmp /var/tmp -/dev/shm", p)
        self.assertIn("StateDirectory=balistid/relay", p)
        self.assertIn("PrivateTmp=disconnected", p)
        self.assertFalse([x for x in p if x.split("=")[0] in ("User", "ExecStart", "IPAddressAllow")])
        self.assertEqual(dirs, ["/dev/shm", "/tmp", "/var/lib/balistid/relay", "/var/tmp"])
        self.assertEqual(args[-len(dirs) - 4:-len(dirs)], ["/bin/sh", "-c", probe_noexec.SCRIPT, "sh"])

    def test_values_keep_their_order_so_a_reset_survives(self):
        line = "NoExecPaths=/ /var/lib/balistid/relay /tmp /var/tmp -/dev/shm"
        text = units()["balistid-relay.service"].replace(line, f"{line}\nNoExecPaths=")
        p = [x for x in props(probe_noexec.run_args(text)[0]) if x.startswith("NoExecPaths=")]
        self.assertEqual(p[-1], "NoExecPaths=")
        self.assertEqual(len(p), 2)

    def test_an_early_boot_unit_keeps_its_unit_settings(self):
        p = props(probe_noexec.run_args(units()["balistid-ledger.service"])[0])
        self.assertIn("DefaultDependencies=no", p)
        self.assertIn("RuntimeDirectory=balistid-ledger", p)

    def test_every_probed_unit_builds(self):
        for name, text in units().items():
            if name not in probe_noexec.EXECUTING:
                with self.subTest(unit=name):
                    args, dirs = probe_noexec.run_args(text)
                    self.assertIn("/tmp", dirs)
                    self.assertTrue([x for x in props(args) if x.startswith("NoExecPaths=")])


if __name__ == "__main__":
    unittest.main()
