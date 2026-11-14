"""Tests for probe_noexec.py's arguments; the probe itself needs root and systemd, so it runs in probe.yml."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import probe_noexec  # noqa: E402
from test_units_noexec import noexec_problems, units  # noqa: E402


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
        self.assertIn("User=balistid-relay", p)
        self.assertIn("SupplementaryGroups=balistid-ledger", p)
        self.assertIn("ExecPaths=-/usr/local/lib/balistid/balistid-relay", p)
        self.assertFalse([x for x in p if x.split("=")[0] in ("ExecStart", "IPAddressAllow", "MemoryMax")])
        self.assertEqual(dirs, ["/dev/shm", "/tmp", "/var/lib/balistid/relay", "/var/tmp"])
        self.assertEqual(args[-len(dirs) - 4:-len(dirs)], ["/usr/bin/python3", "-I", "-c", probe_noexec.INSIDE])

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
        self.assertNotIn("/var/tmp", probe_noexec.run_args(units()["balistid-ledger.service"])[1])

    def test_the_judge_reads_the_store_read_only(self):
        p = props(probe_noexec.run_args(units()["balistid-judge.service"])[0])
        self.assertIn("ReadOnlyPaths=/var/lib/balistid/collector", p)

    def test_every_control_puts_back_one_hole(self):
        labels = [label for label, _, _ in probe_noexec.controls()]
        self.assertEqual(len(labels), 7)
        for label, text, want in probe_noexec.controls():
            with self.subTest(control=label):
                self.assertTrue(any(want in problem for problem in noexec_problems(text)))

    def test_every_probed_unit_builds(self):
        for name, text in units().items():
            if name not in probe_noexec.EXECUTING:
                with self.subTest(unit=name):
                    args, dirs = probe_noexec.run_args(text)
                    self.assertIn("/tmp", dirs)
                    self.assertTrue([x for x in props(args) if x.startswith("User=")])
                    self.assertTrue([x for x in props(args) if x.startswith("NoExecPaths=")])


if __name__ == "__main__":
    unittest.main()
