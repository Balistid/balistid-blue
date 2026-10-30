"""The nightly fuzz workflow runs every fuzz target of the repository, long enough for fuzz_hours."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FUZZ = REPO / ".github" / "workflows" / "fuzz.yml"
ROW = re.compile(r"^\s+- \{ pkg: (\./[a-z0-9/_-]+), target: (Fuzz\w+), minutes: (\d+) \}$", re.M)
FUNC = re.compile(r"^func (Fuzz\w+)\(f \*testing\.F\) \{$", re.M)
# Code that only the range guest runs on its own input; everything else reads input on the host or the Pi.
GUEST_ONLY = {"./cmd/balistid-range-guest", "./internal/rangeguest"}


def repository_targets() -> set[tuple[str, str]]:
    targets = set()
    for path in REPO.glob("**/*_test.go"):
        pkg = "./" + path.parent.relative_to(REPO).as_posix()
        targets.update((pkg, name) for name in FUNC.findall(path.read_text(encoding="utf-8")))
    return targets


def matrix() -> list[tuple[str, str, int]]:
    return [(pkg, target, int(minutes)) for pkg, target, minutes in ROW.findall(FUZZ.read_text(encoding="utf-8"))]


class Matrix(unittest.TestCase):
    def test_every_fuzz_target_runs_once(self) -> None:
        rows = matrix()
        listed = [(pkg, target) for pkg, target, _ in rows]
        self.assertEqual(len(listed), len(set(listed)), "a target listed twice")
        self.assertEqual(set(listed), repository_targets())

    def test_every_matrix_line_is_a_row(self) -> None:
        # A row the pattern misses would hide a target from the comparison above.
        text = FUZZ.read_text(encoding="utf-8")
        self.assertEqual(text.count("- { pkg:"), len(matrix()))

    def test_host_and_pi_parsers_fuzz_an_hour(self) -> None:
        for pkg, target, minutes in matrix():
            with self.subTest(target=target):
                self.assertEqual(minutes, 10 if pkg in GUEST_ONLY else 60)
                self.assertLess(minutes + 10, int(re.search(r"timeout-minutes: (\d+)", FUZZ.read_text()).group(1)))


class Workflow(unittest.TestCase):
    def test_reads_only_and_runs_on_schedule_or_by_hand(self) -> None:
        text = FUZZ.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^on:\n  schedule:\n    - cron: \"[0-9 *]+\"\n  workflow_dispatch:\n\n")
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n\n")
        self.assertIn("persist-credentials: false", text)
        for needle in ("secrets.", "github.token", "pull_request", "actions/upload-artifact@", "continue-on-error"):
            self.assertNotIn(needle, text)

    def test_matrix_values_reach_the_shell_only_through_the_environment(self) -> None:
        for line in re.findall(r"(?m)^\s+(?:- )?run: (.*)$", FUZZ.read_text(encoding="utf-8")):
            self.assertNotIn("${{", line)
        self.assertNotRegex(FUZZ.read_text(encoding="utf-8"), r"(?s)run: \|.*\$\{\{")


if __name__ == "__main__":
    unittest.main()
