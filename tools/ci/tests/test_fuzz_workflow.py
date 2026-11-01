"""The nightly fuzz workflow runs every fuzz target the compiler lists, long enough for fuzz_hours."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "ci"))

import fuzz_matrix  # noqa: E402

FUZZ = REPO / ".github" / "workflows" / "fuzz.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
LIST = "go test -list '^Fuzz' -json ./... > \"$RUNNER_TEMP/list.json\""
MATRIX = "python3 tools/ci/fuzz_matrix.py < \"$RUNNER_TEMP/list.json\" >> \"$GITHUB_OUTPUT\""
RUN = "go test -run '^$' -fuzz \"^${TARGET}\\$\" -fuzztime \"${MINUTES}m\" \"$PKG\" || rc=$?"
MOD = "github.com/Balistid/balistid-blue/"


def text() -> str:
    return FUZZ.read_text(encoding="utf-8")


def event(action: str, package: str = MOD + "internal/store", output: str | None = None) -> str:
    e = {"Action": action, "Package": package}
    if output is not None:
        e["Output"] = output
    return json.dumps(e)


def listing(*names: tuple[str, str]) -> list[str]:
    """A built package listing as go test -json prints it: start, one output per name, the ok line, pass."""
    lines = []
    for package, name in names:
        lines += [event("start", MOD + package), event("output", MOD + package, name + "\n"),
                  event("output", MOD + package, f"ok  \t{MOD}{package}\t0.004s\n"), event("pass", MOD + package)]
    return lines


class Matrix(unittest.TestCase):
    def test_every_listed_target_is_one_row_with_its_minutes(self) -> None:
        rows = fuzz_matrix.rows(listing(("internal/store", "FuzzReadSeals"), ("internal/rangeguest", "FuzzParsers"),
                                        ("cmd/balistid-range-guest", "FuzzHealthKind")))
        self.assertEqual(rows, [
            {"pkg": "./cmd/balistid-range-guest", "target": "FuzzHealthKind", "minutes": 10},
            {"pkg": "./internal/rangeguest", "target": "FuzzParsers", "minutes": 10},
            {"pkg": "./internal/store", "target": "FuzzReadSeals", "minutes": 60},
        ])

    def test_packages_without_tests_or_targets_add_nothing(self) -> None:
        lines = listing(("internal/store", "FuzzReadSeals"))
        lines += [event("start", MOD + "cmd/balistid"), event("skip", MOD + "cmd/balistid"),
                  event("output", MOD + "cmd/balistid", f"?   \t{MOD}cmd/balistid\t[no test files]\n")]
        self.assertEqual(len(fuzz_matrix.rows(lines)), 1)

    def test_a_listing_that_cannot_tell_its_targets_fails(self) -> None:
        good = listing(("internal/store", "FuzzReadSeals"))
        cases = {
            "build failed": good + [event("build-fail", MOD + "internal/watch")],
            "test binary failed": good + [event("fail", MOD + "internal/watch")],
            "nothing listed": [event("start"), event("pass")],
            "listed twice": good + listing(("internal/store", "FuzzReadSeals")),
            "another module": good + [event("output", "example.com/x", "FuzzX\n")],
            "module root": good + [event("output", MOD.rstrip("/"), "FuzzX\n")],
            "name with a newline inside": good + [event("output", output="FuzzX\nFuzzY\n")],
            "name with a space": good + [event("output", output="FuzzX y\n")],
            "upper-case package": good + [event("output", MOD + "internal/Store", "FuzzX\n")],
            "not json": good + ["Fuzz"],
        }
        for case, lines in cases.items():
            with self.subTest(case=case), self.assertRaises((ValueError, json.JSONDecodeError)):
                fuzz_matrix.rows(lines)

    def test_host_and_pi_parsers_fuzz_an_hour_within_the_job_timeout(self) -> None:
        self.assertEqual((fuzz_matrix.GUEST_MINUTES, fuzz_matrix.HOST_MINUTES), (10, 60))
        timeout = int(re.search(r"(?ms)^  fuzz:\n.*?^    timeout-minutes: (\d+)$", text()).group(1))
        self.assertLess(fuzz_matrix.HOST_MINUTES + 10, timeout)

    def test_guest_only_packages_are_imported_only_by_the_guest(self) -> None:
        for path in REPO.glob("**/*.go"):
            rel = path.relative_to(REPO).as_posix()
            if rel.startswith(tuple(p.removeprefix("./") + "/" for p in fuzz_matrix.GUEST_ONLY)):
                continue
            with self.subTest(file=rel):
                self.assertNotIn('balistid-blue/internal/rangeguest"', path.read_text(encoding="utf-8"))


class Workflow(unittest.TestCase):
    def test_runs_nightly_or_by_hand_with_read_only_rights(self) -> None:
        t = text()
        self.assertRegex(t, r"(?m)^on:\n  schedule:\n    - cron: \"23 1 \* \* \*\"\n  workflow_dispatch:\n\n")
        self.assertRegex(t, r"(?m)^permissions:\n  contents: read\n\n")
        self.assertEqual(t.count("persist-credentials: false"), 2)
        for needle in ("secrets.", "github.token", "pull_request", "actions/upload-artifact@", "continue-on-error",
                       "ref:", "max-parallel", "|| true", "fail-fast: true", "{ pkg:"):
            self.assertNotIn(needle, t)
        self.assertNotRegex(t, r"\btimeout \d")

    def test_the_matrix_is_the_compilers_listing(self) -> None:
        t = text()
        for line in (f"          {LIST}\n", f"          {MATRIX}\n", "      matrix: ${{ steps.list.outputs.matrix }}\n",
                     "    needs: targets\n", "        include: ${{ fromJSON(needs.targets.outputs.matrix) }}\n"):
            self.assertIn(line, t)
        self.assertEqual(t.count("go test"), 2)

    def test_each_job_fuzzes_its_row_for_its_minutes(self) -> None:
        t = text()
        for line in ("      PKG: ${{ matrix.pkg }}\n", "      TARGET: ${{ matrix.target }}\n",
                     "      MINUTES: ${{ matrix.minutes }}\n", f"          {RUN}\n", '          exit "$rc"\n'):
            self.assertIn(line, t)
        self.assertEqual(re.findall(r"(?m)^\s+if: (.*)$", t), ["failure() || cancelled()"])

    def test_expressions_stay_out_of_steps(self) -> None:
        """Matrix values reach the shell only through the environment."""
        lines = sorted(ln.strip() for ln in text().splitlines() if "${{" in ln)
        self.assertEqual(lines, sorted([
            "matrix: ${{ steps.list.outputs.matrix }}", "include: ${{ fromJSON(needs.targets.outputs.matrix) }}",
            "PKG: ${{ matrix.pkg }}", "TARGET: ${{ matrix.target }}", "MINUTES: ${{ matrix.minutes }}",
        ]))

    def test_go_is_the_one_ci_pins(self) -> None:
        for key in ("GO_VERSION", "GO_SHA256"):
            pin = re.compile(rf'(?m)^  {key}: "([^"]+)"$')
            with self.subTest(key=key):
                self.assertEqual(pin.search(text()).group(1), pin.search(CI.read_text(encoding="utf-8")).group(1))


if __name__ == "__main__":
    unittest.main()
