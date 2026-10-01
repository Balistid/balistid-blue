"""Tests for the pin-check gate: the pinned zizmor binary with zizmor.yml must reject every unpinned
`uses:` spelling GitHub accepts and pass hash-pinned workflows.

The binary comes from the ZIZMOR environment variable (CI installs it pinned by sha256). Without it
the tests fail instead of skipping: a gate whose tests did not run is not a tested gate (R6).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CONFIG = REPO / "zizmor.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
HEADER = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n"

# Each body is the steps block of one workflow; every one must yield an unpinned-uses finding.
UNPINNED_STEPS = {
    "tag": "      - uses: octo-org/act@v1\n",
    "branch": "      - uses: octo-org/act@main\n",
    "short_sha": "      - uses: octo-org/act@3d3c42e\n",
    "quoted_key": '      - "uses": octo-org/act@v1\n',
    "explicit_key": "      - ? uses\n        : octo-org/act@v1\n",
    "flow_mapping": "      - {uses: octo-org/act@v1}\n",
    "anchor_alias": "      - uses: &ref octo-org/act@v1\n      - uses: *ref\n",
    # First-party actions get no exception: the gate requires a hash for every owner.
    "first_party_tag": "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n",
}
UNPINNED_REUSABLE = "on: push\npermissions: {}\njobs:\n  a:\n    uses: octo-org/r/.github/workflows/x.yml@v1\n"
# GitHub decodes this key to "uses"; zizmor cannot audit it and must stop with an error, not pass.
ESCAPED_KEY = HEADER + '      - "u\\x73es": octo-org/act@v1\n'

PINNED = HEADER + (
    f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
    "        with:\n"
    "          persist-credentials: false\n"
    "      - run: |\n"
    "          echo 'uses: octo-org/act@v1'\n"
)
PINNED_REUSABLE = f"on: push\npermissions: {{}}\njobs:\n  a:\n    uses: octo-org/r/.github/workflows/x.yml@{SHA}\n"


def zizmor_binary() -> str:
    path = os.environ.get("ZIZMOR", "")
    if not path or not os.access(path, os.X_OK):
        raise AssertionError("set ZIZMOR to the pinned zizmor binary; these tests do not skip")
    return path


def audit(text: str) -> tuple[int, list[dict] | None]:
    """Run the gate on one workflow. Returns (exit code, findings or None if output is not JSON)."""
    with tempfile.TemporaryDirectory() as tmp:
        workflow = Path(tmp) / "w.yml"
        workflow.write_text(text)
        proc = subprocess.run(
            [zizmor_binary(), "--offline", "--format", "json", "--config", str(CONFIG), str(workflow)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    try:
        return proc.returncode, json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.returncode, None


def unpinned(findings: list[dict] | None) -> int:
    return sum(1 for f in findings or [] if f.get("ident") == "unpinned-uses")


class ZizmorGateTest(unittest.TestCase):
    def test_ci_runs_the_audit_these_tests_cover(self):
        self.assertIn('"$RUNNER_TEMP/zizmor" --offline --config zizmor.yml .github/workflows/', CI.read_text())

    def test_unpinned_steps_fail(self):
        for name, steps in UNPINNED_STEPS.items():
            with self.subTest(name):
                code, findings = audit(HEADER + steps)
                self.assertNotEqual(code, 0)
                self.assertGreaterEqual(unpinned(findings), 1, findings)

    def test_every_aliased_step_is_reported(self):
        _code, findings = audit(HEADER + UNPINNED_STEPS["anchor_alias"])
        self.assertEqual(unpinned(findings), 2, findings)

    def test_unpinned_reusable_workflow_fails(self):
        code, findings = audit(UNPINNED_REUSABLE)
        self.assertNotEqual(code, 0)
        self.assertEqual(unpinned(findings), 1, findings)

    def test_escaped_key_stops_the_gate(self):
        code, _findings = audit(ESCAPED_KEY)
        self.assertNotEqual(code, 0)

    def test_hash_pinned_workflows_pass(self):
        for name, text in {"steps": PINNED, "reusable": PINNED_REUSABLE}.items():
            with self.subTest(name):
                self.assertEqual(audit(text), (0, []))


if __name__ == "__main__":
    unittest.main()
