"""The nightly fuzz workflow runs every fuzz target in the tracked test files, long enough for fuzz_hours."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "ci"))

import fuzz_matrix  # noqa: E402

FUZZ = REPO / ".github" / "workflows" / "fuzz.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
MATRIX = "run: python3 tools/ci/fuzz_matrix.py >> \"$GITHUB_OUTPUT\""
RUN = "go test -run '^$' -fuzz \"^${TARGET}\\$\" -fuzztime \"${MINUTES}m\" \"$PKG\" | tee \"$RUNNER_TEMP/fuzz.log\""
FUZZED = "if [ \"$rc\" -eq 0 ] && ! grep -q '^fuzz: elapsed: ' \"$RUNNER_TEMP/fuzz.log\"; then"
TEST = 'package x\n\nimport "testing"\n\n'


def text() -> str:
    return FUZZ.read_text(encoding="utf-8")


def tracked(pattern: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", "--", pattern], check=True, capture_output=True)
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


class Matrix(unittest.TestCase):
    def test_every_fuzz_function_is_one_row_with_its_minutes(self) -> None:
        rows = fuzz_matrix.rows({
            "internal/store/seal_test.go": TEST + "func FuzzReadSeals(f *testing.F) {}\nfunc FuzzA_2(*testing.F) {}\n",
            "internal/rangeguest/parse_test.go": TEST + "func FuzzParsers(\n\tf *testing.F,\n) {}\n",
            "cmd/balistid-range-guest/kind_test.go": TEST + "func Fuzz(_ *testing.F) {}\n",
        })
        self.assertEqual(rows, [
            {"pkg": "./cmd/balistid-range-guest", "target": "Fuzz", "minutes": 10},
            {"pkg": "./internal/rangeguest", "target": "FuzzParsers", "minutes": 10},
            {"pkg": "./internal/store", "target": "FuzzA_2", "minutes": 60},
            {"pkg": "./internal/store", "target": "FuzzReadSeals", "minutes": 60},
        ])

    def test_only_what_go_test_takes_for_a_fuzz_test(self) -> None:
        body = TEST + "\n".join([
            "func Fuzzer(f *testing.F) {}", "func FuzzT(t *testing.T) {}", "func (s) FuzzM(f *testing.F) {}",
            "\tfunc FuzzIndented(f *testing.F) {}", "// func FuzzComment(f *testing.F) {}",
            "func FuzzTwo(f *testing.F, n int) {}", "func FuzzReal(f *testing.F) {}"])
        rows = fuzz_matrix.rows({"internal/store/a_test.go": body})
        self.assertEqual([r["target"] for r in rows], ["FuzzReal"])

    def test_directories_go_skips_add_nothing(self) -> None:
        fuzz = TEST + "func FuzzX(f *testing.F) {}\n"
        files = {f"internal/{d}/a_test.go": fuzz for d in ("testdata", "_old", ".claude/wt", "vendor/x", "store")}
        self.assertEqual(fuzz_matrix.rows(files), [{"pkg": "./internal/store", "target": "FuzzX", "minutes": 60}])

    def test_a_listing_the_matrix_cannot_use_fails(self) -> None:
        fuzz = TEST + "func FuzzX(f *testing.F) {}\n"
        cases = {
            "nothing found": {"internal/store/a_test.go": TEST},
            "listed twice": {"internal/store/a_test.go": fuzz, "internal/store/b_test.go": fuzz},
            "module root": {"root_test.go": fuzz},
            "upper-case package": {"internal/Store/a_test.go": fuzz},
            "dot in a package": {"internal/st.ore/a_test.go": fuzz},
        }
        for case, files in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                fuzz_matrix.rows(files)

    def test_the_repository_lists_its_targets(self) -> None:
        """What the nightly run will list, checked on every pull request."""
        got = subprocess.run([sys.executable, str(REPO / "tools/ci/fuzz_matrix.py")], cwd=REPO, check=True,
                             capture_output=True, text=True).stdout
        self.assertTrue(got.startswith("matrix=") and got.endswith("\n") and got.count("\n") == 1)
        rows = json.loads(got.removeprefix("matrix="))
        self.assertGreater(len(rows), 0)
        for row in rows:
            with self.subTest(row=row):
                self.assertEqual(row["minutes"], 10 if row["pkg"] in fuzz_matrix.GUEST_ONLY else 60)

    def test_host_and_pi_parsers_fuzz_an_hour_within_the_job_timeout(self) -> None:
        self.assertEqual((fuzz_matrix.GUEST_MINUTES, fuzz_matrix.HOST_MINUTES), (10, 60))
        timeout = int(re.search(r"(?ms)^  fuzz:\n.*?^    timeout-minutes: (\d+)$", text()).group(1))
        self.assertLess(fuzz_matrix.HOST_MINUTES + 10, timeout)

    def test_guest_only_packages_are_imported_only_by_the_guest(self) -> None:
        guest = tuple(p.removeprefix("./") + "/" for p in fuzz_matrix.GUEST_ONLY)
        for rel in tracked("*.go"):
            if rel.startswith(guest):
                continue
            with self.subTest(file=rel):
                self.assertNotRegex((REPO / rel).read_text(encoding="utf-8"),
                                    r"balistid-blue/internal/rangeguest[\"`]")


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

    def test_the_matrix_comes_from_the_source_alone(self) -> None:
        t = text()
        targets = re.search(r"(?ms)^  targets:\n(.*?)^  fuzz:\n", t).group(1)
        self.assertIn(f"        {MATRIX}\n", targets)
        for needle in ("go ", "go_gate", "GO_"):
            self.assertNotIn(needle, targets)
        for line in ("      matrix: ${{ steps.list.outputs.matrix }}\n", "    needs: targets\n",
                     "        include: ${{ fromJSON(needs.targets.outputs.matrix) }}\n"):
            self.assertIn(line, t)
        self.assertEqual(t.count("go test"), 1)

    def test_each_job_fuzzes_its_row_for_its_minutes(self) -> None:
        t = text()
        for line in ("      PKG: ${{ matrix.pkg }}\n", "      TARGET: ${{ matrix.target }}\n",
                     "      MINUTES: ${{ matrix.minutes }}\n", f"          {RUN}\n", "          rc=${PIPESTATUS[0]}\n",
                     f"          {FUZZED}\n", '            echo "no fuzzing ran for $TARGET"; rc=1\n',
                     '          exit "$rc"\n'):
            self.assertIn(line, t)
        self.assertEqual(re.findall(r"(?m)^\s+if: (.*)$", t), ["failure() || cancelled()"])

    def test_a_run_passes_only_when_go_passed_and_fuzzed(self) -> None:
        """The step's own script, under both shells Actions may use, with a stand-in go."""
        script = re.search(r"(?ms)^      - name: Fuzz one target\n.*?^        run: \|\n(.*?)^      - ", text()).group(1)
        cases = {"fuzzed": ("fuzz: elapsed: 0s, gathering baseline coverage", 0, 0),
                 "matched no target": ("testing: warning: no fuzz tests to fuzz\nPASS", 0, 1),
                 "crashed": ("fuzz: elapsed: 3s\n--- FAIL: FuzzX", 1, 1),
                 "build failed": ("cannot find package", 2, 2)}
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "go"
            for case, (out, go_rc, want) in cases.items():
                fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{out}'\nexit {go_rc}\n", encoding="utf-8")
                fake.chmod(0o755)
                for shell in (["bash", "-e"], ["bash", "--noprofile", "--norc", "-eo", "pipefail"]):
                    env = {"PATH": f"{tmp}:{os.environ['PATH']}", "RUNNER_TEMP": tmp, "TARGET": "FuzzX",
                           "MINUTES": "1", "PKG": "./internal/x"}
                    got = subprocess.run([*shell, "-c", script], env=env, capture_output=True, check=False)
                    with self.subTest(case=case, shell=shell[-1]):
                        self.assertEqual(got.returncode, want)

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
