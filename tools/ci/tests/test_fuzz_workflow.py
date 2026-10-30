"""The nightly fuzz workflow runs every fuzz target of the repository, long enough for fuzz_hours."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
FUZZ = REPO / ".github" / "workflows" / "fuzz.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
ROW = re.compile(r"^          - \{ pkg: (\./[a-z0-9/_-]+), target: (Fuzz\w+), minutes: (\d+) \}$")
# Any spelling gofmt keeps: another parameter name, a comment after the brace.
FUNC = re.compile(r"^func (Fuzz\w*)\(\s*\w+\s+\*testing\.F\s*\)", re.M)
# Code that only the range guest runs on its own output; everything else reads input on the host or the Pi.
GUEST_ONLY = {"./cmd/balistid-range-guest", "./internal/rangeguest"}
RUN = "go test -run '^$' -fuzz \"^${TARGET}\\$\" -fuzztime \"${MINUTES}m\" \"$PKG\" || rc=$?"


def text() -> str:
    return FUZZ.read_text(encoding="utf-8")


def repository_targets() -> set[tuple[str, str]]:
    targets = set()
    for path in REPO.glob("**/*_test.go"):
        pkg = "./" + path.parent.relative_to(REPO).as_posix()
        targets.update((pkg, name) for name in FUNC.findall(path.read_text(encoding="utf-8")))
    return targets


def matrix() -> list[tuple[str, str, int]]:
    """The rows between include: and the job's env:, every line of which must be a row."""
    block = re.search(r"(?ms)^        include:\n(.*?)^    env:\n", text())
    if block is None:
        raise AssertionError("fuzz.yml has no matrix include block before the job's env")
    rows = []
    for line in block.group(1).splitlines():
        m = ROW.match(line)
        if m is None:
            raise AssertionError(f"not a matrix row: {line!r}")
        rows.append((m.group(1), m.group(2), int(m.group(3))))
    return rows


class Matrix(unittest.TestCase):
    def test_every_fuzz_target_runs_once(self) -> None:
        listed = [(pkg, target) for pkg, target, _ in matrix()]
        self.assertEqual(len(listed), len(set(listed)), "a target listed twice")
        self.assertEqual(set(listed), repository_targets())

    def test_no_row_outside_the_matrix(self) -> None:
        self.assertEqual(text().count("{ pkg:"), len(matrix()))

    def test_host_and_pi_parsers_fuzz_an_hour(self) -> None:
        timeout = int(re.search(r"(?m)^    timeout-minutes: (\d+)$", text()).group(1))
        for pkg, target, minutes in matrix():
            with self.subTest(target=target):
                self.assertEqual(minutes, 10 if pkg in GUEST_ONLY else 60)
                self.assertLess(minutes + 10, timeout)

    def test_guest_only_packages_are_imported_only_by_the_guest(self) -> None:
        for path in REPO.glob("**/*.go"):
            rel = path.relative_to(REPO).as_posix()
            if rel.startswith(("cmd/balistid-range-guest/", "internal/rangeguest/")):
                continue
            with self.subTest(file=rel):
                self.assertNotIn('balistid-blue/internal/rangeguest"', path.read_text(encoding="utf-8"))


class Workflow(unittest.TestCase):
    def test_runs_nightly_or_by_hand_with_read_only_rights(self) -> None:
        t = text()
        self.assertRegex(t, r"(?m)^on:\n  schedule:\n    - cron: \"23 1 \* \* \*\"\n  workflow_dispatch:\n\n")
        self.assertRegex(t, r"(?m)^permissions:\n  contents: read\n\n")
        self.assertIn("persist-credentials: false", t)
        for needle in ("secrets.", "github.token", "pull_request", "actions/upload-artifact@", "continue-on-error",
                       "ref:", "max-parallel", "|| true", "fail-fast: true"):
            self.assertNotIn(needle, t)
        self.assertNotRegex(t, r"\btimeout \d")

    def test_each_job_fuzzes_its_row_for_its_minutes(self) -> None:
        t = text()
        for line in ("      PKG: ${{ matrix.pkg }}\n", "      TARGET: ${{ matrix.target }}\n",
                     "      MINUTES: ${{ matrix.minutes }}\n", f"          {RUN}\n", '          exit "$rc"\n'):
            self.assertIn(line, t)
        self.assertEqual(t.count("go test"), 1)
        self.assertEqual(re.findall(r"(?m)^\s+if: (.*)$", t), ["failure() || cancelled()"])

    def test_matrix_values_reach_the_shell_only_through_the_environment(self) -> None:
        steps = text().split("    steps:\n", 1)[1]
        self.assertNotIn("${{", steps)

    def test_go_is_the_one_ci_pins(self) -> None:
        for key in ("GO_VERSION", "GO_SHA256"):
            pin = re.compile(rf'(?m)^  {key}: "([^"]+)"$')
            with self.subTest(key=key):
                self.assertEqual(pin.search(text()).group(1), pin.search(CI.read_text(encoding="utf-8")).group(1))


if __name__ == "__main__":
    unittest.main()
