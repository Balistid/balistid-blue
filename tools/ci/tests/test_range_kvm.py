"""Tests for tools/ci/range_kvm.py and its CI job (ADR 0028): the self-test runs only on a GitHub-hosted
runner with KVM, from pinned inputs, without secrets or extra capabilities, and every way it cannot run
fails the job instead of skipping it (R6)."""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "ci"))
import range_kvm  # noqa: E402

CI = REPO / ".github" / "workflows" / "ci.yml"
TRIAL_WORKFLOW = REPO / ".github" / "workflows" / "range-trial.yml"
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


class Recorder:
    """Stands in for subprocess.run; the docker call returns exit."""

    def __init__(self, exit: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.exit = exit

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
        if argv[0] == "docker":
            print("docker ran")
        return subprocess.CompletedProcess(argv, self.exit if argv[0] == "docker" else 0)


def ci_job(name: str) -> str:
    text = CI.read_text(encoding="utf-8")
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
    if m is None:
        raise AssertionError(f"ci.yml has no job {name}")
    return m.group(1)


class Pins(unittest.TestCase):
    def test_image_is_pinned_by_digest(self) -> None:
        self.assertRegex(range_kvm.IMAGE, r"^docker\.io/library/archlinux@sha256:[0-9a-f]{64}$")

    def test_host_tools_come_from_a_dated_snapshot(self) -> None:
        self.assertRegex(range_kvm.SNAPSHOT, r"^\d{4}/\d{2}/\d{2}$")
        self.assertIn("archive.archlinux.org/repos/%s/", range_kvm.CONTAINER_SCRIPT)
        self.assertNotIn("pacman -Sy ", range_kvm.CONTAINER_SCRIPT)

    def test_docker_gets_kvm_and_no_added_privilege(self) -> None:
        argv = range_kvm.docker_argv(Path("/r"), Path("/s"), Path("/c"), 1001)
        self.assertIn("/dev/kvm", argv)
        self.assertIn("/r:/src:ro", argv)
        for wide in ("--privileged", "--cap-add", "--network=host", "--pid=host", "--userns=host"):
            self.assertFalse(any(a.startswith(wide) for a in argv), wide)
        envs = [argv[i + 1] for i, a in enumerate(argv) if a in ("--env", "-e")]
        self.assertEqual(envs, [f"SNAPSHOT={range_kvm.SNAPSHOT}", "RANGE_UID=1001"])
        self.assertEqual(argv[argv.index(range_kvm.IMAGE) + 1:][:3], ["/usr/bin/bash", "-c", range_kvm.CONTAINER_SCRIPT])

    def test_the_build_runs_unprivileged_with_a_fixed_environment(self) -> None:
        script = range_kvm.CONTAINER_SCRIPT
        self.assertIn("exec runuser -u range -- /usr/bin/env -i ", script)
        user_part = script.split("exec runuser", 1)[1]
        self.assertNotIn("sudo", user_part)
        self.assertIn("GOTOOLCHAIN=local", user_part)
        self.assertIn('"$HOME/balistid-range" run "$image"', user_part)
        # A trial's name is data from the environment, never part of the script's text (ADR 0037).
        self.assertIn('RANGE_TRIAL="${RANGE_TRIAL:-}" PATH=/usr/bin', script)
        self.assertIn('"$HOME/balistid-range" trial "$RANGE_TRIAL" "$image"', user_part)

    def test_a_trial_goes_in_by_environment_only(self) -> None:
        argv = range_kvm.docker_argv(Path("/r"), Path("/s"), Path("/c"), 1001, "silence-ledger")
        envs = [argv[i + 1] for i, a in enumerate(argv) if a in ("--env", "-e")]
        self.assertEqual(envs, [f"SNAPSHOT={range_kvm.SNAPSHOT}", "RANGE_UID=1001", "RANGE_TRIAL=silence-ledger"])
        self.assertNotIn("silence-ledger", range_kvm.CONTAINER_SCRIPT)


class FailsClosed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.kvm = self.work / "kvm"
        # The test's temporary directory is small; one test below raises the need again.
        patch = mock.patch.object(range_kvm, "MIN_FREE", 0)
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def main(self, env=HOSTED, run=None, kvm=None) -> tuple[int, Recorder]:
        rec = run or Recorder()
        code = range_kvm.main(["--work", str(self.work / "w"), "--repo", str(self.work)], env=env, run=rec,
                              kvm=kvm or self.kvm, sysctl=self.work / "no-sysctl")
        return code, rec

    def test_a_bad_trial_name_fails_before_anything_runs(self) -> None:
        for name in ("", "Silence", "a b", "x" * 33, "../x", "$(id)", "a;b"):
            rec = Recorder()
            with contextlib.redirect_stderr(io.StringIO()):
                code = range_kvm.main(["--work", str(self.work / "w"), "--repo", str(self.work), "--trial", name],
                                      env=HOSTED, run=rec, kvm=Path("/dev/null"), sysctl=self.work / "no-sysctl")
            self.assertEqual((code, rec.calls), (1, []), name)

    def test_refuses_outside_a_github_hosted_runner(self) -> None:
        for env in ({}, {"GITHUB_ACTIONS": "true"}, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
            code, rec = self.main(env=env, kvm=Path("/dev/null"))
            self.assertEqual(code, 1, env)
            self.assertEqual(rec.calls, [], env)

    def test_missing_kvm_fails_instead_of_skipping(self) -> None:
        code, rec = self.main()
        self.assertEqual(code, 1)
        self.assertEqual(rec.calls, [])

    def test_kvm_that_is_not_a_device_fails(self) -> None:
        self.kvm.write_text("")
        code, rec = self.main()
        self.assertEqual(code, 1)
        self.assertEqual(rec.calls, [])

    def test_too_little_disk_fails(self) -> None:
        with mock.patch.object(range_kvm, "MIN_FREE", 1 << 62):
            code, rec = self.main(kvm=Path("/dev/null"))
        self.assertEqual(code, 1)
        self.assertEqual(rec.calls, [])

    def test_a_failed_self_test_fails_the_job(self) -> None:
        code, rec = self.main(run=Recorder(exit=1), kvm=Path("/dev/null"))
        self.assertEqual(code, 1)
        self.assertEqual(rec.calls[-1][0], "docker")

    def test_a_passing_self_test_passes(self) -> None:
        code, rec = self.main(kvm=Path("/dev/null"))
        self.assertEqual(code, 0)
        self.assertEqual(rec.calls[0][:3], ["sudo", "tee", "/etc/udev/rules.d/99-kvm4all.rules"])

    def test_workflow_commands_are_off_while_the_build_prints(self) -> None:
        for exit in (0, 1):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.main(run=Recorder(exit=exit), kvm=Path("/dev/null"))
            lines = out.getvalue().splitlines()
            at = lines.index("docker ran")
            stop = re.fullmatch(r"::stop-commands::([0-9a-f]{32})", lines[at - 1])
            self.assertIsNotNone(stop, lines)
            self.assertEqual(lines[at + 1:at + 3], ["", f"::{stop[1]}::"])

    def result(self, body: str, run_id: str = "20261030T054612Z-2d22e141") -> Path:
        state = self.work / "w" / "state"
        out = state / "balistid-range" / "results" / run_id
        out.mkdir(parents=True)
        (out / "result.json").write_text(body, encoding="utf-8")
        return state

    def test_a_failed_verdict_becomes_one_escaped_annotation(self) -> None:
        state = self.result('{"verdict": "FAIL", "reason": "pi_reach=\\"x\\"\\n::set-output name=a::b\\r 100%"}')
        line = range_kvm.verdict_annotation(state)
        self.assertEqual(line, "::error title=range-kvm self-test::FAIL: pi_reach=\"x\"%0A::set-output name=a::b%0D 100%25")
        self.assertNotRegex(line, "[\r\n]")

    def test_a_passing_run_or_none_gives_no_annotation_and_garbage_one(self) -> None:
        self.assertIsNone(range_kvm.verdict_annotation(self.work / "w" / "state"))
        state = self.result('{"verdict": "PASS", "reason": "all facts"}')
        self.assertIsNone(range_kvm.verdict_annotation(state))
        self.result("[1, 2]", run_id="20261030T060000Z-ffffffff")
        self.assertIn("could not be read", range_kvm.verdict_annotation(state))
        self.result('{"verdict": "PASS"}', run_id="zzz-not-a-run")  # sorts last, never chosen
        self.assertIn("could not be read", range_kvm.verdict_annotation(state))

    def test_a_planted_link_or_fifo_is_not_read(self) -> None:
        state = self.result('{"verdict": "FAIL", "reason": "r"}')
        target = state / "balistid-range" / "results" / "20261030T070000Z-00000000"
        target.mkdir()
        (target / "result.json").symlink_to(state / "balistid-range" / "results" / "20261030T054612Z-2d22e141" / "result.json")
        self.assertIn("could not be read", range_kvm.verdict_annotation(state))
        fifo = state / "balistid-range" / "results" / "20261030T080000Z-11111111"
        fifo.mkdir()
        os.mkfifo(fifo / "result.json")
        self.assertIn("could not be read", range_kvm.verdict_annotation(state))

    def test_an_expected_verdict_gets_no_annotation(self) -> None:
        # The launcher exits 0 when a control gives its expected MISS: no error for the run (ADR 0037).
        self.result('{"verdict": "MISS", "reason": "control missed as required"}')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = range_kvm.main(["--work", str(self.work / "w"), "--repo", str(self.work), "--trial", "rate-control-drop"],
                                  env=HOSTED, run=Recorder(exit=0), kvm=Path("/dev/null"), sysctl=self.work / "no-sysctl")
        self.assertEqual(code, 0)
        self.assertNotIn("::error", out.getvalue())

    def test_a_failed_run_without_result_is_annotated(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.main(run=Recorder(exit=1), kvm=Path("/dev/null"))
        self.assertEqual(out.getvalue().splitlines()[-1],
                         "::error title=range-kvm self-test::no result: the build or self-test failed (exit 1)")

    def test_the_annotation_comes_after_workflow_commands_are_back(self) -> None:
        out = io.StringIO()
        with mock.patch.object(range_kvm, "verdict_annotation", return_value="::error::FAIL"), \
                contextlib.redirect_stdout(out):
            self.main(run=Recorder(exit=1), kvm=Path("/dev/null"))
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[-1], "::error::FAIL")
        self.assertRegex(lines[-2], r"::[0-9a-f]{32}::")


class Workflow(unittest.TestCase):
    def test_job_runs_the_script_with_no_secret_or_write_permission(self) -> None:
        job = ci_job("range-kvm")
        runs = re.findall(r"(?m)^\s+(?:- )?run: (.*)$", job)
        self.assertEqual(runs, ['python3 tools/ci/range_kvm.py --work "$RUNNER_TEMP/range"'])
        self.assertIn("persist-credentials: false", job)
        # The workflow's contents: read applies, and the state directory the tested code writes is never uploaded.
        for needle in ("secrets.", "github.token", "permissions:", "continue-on-error", "|| true", "actions/upload-artifact@"):
            self.assertNotIn(needle, job)
        self.assertNotRegex(job, r"(?m)^    if:")
        self.assertRegex(CI.read_text(encoding="utf-8"), r"(?m)^permissions:\n  contents: read\n\n")

    def test_job_tests_the_tree_that_would_land(self) -> None:
        # Like every other job: the merge commit, whose workflow then runs its own script.
        self.assertNotIn("ref:", ci_job("range-kvm"))


class TrialWorkflow(unittest.TestCase):
    def test_dispatch_runs_one_trial_with_the_payload_from_env(self) -> None:
        # repository_dispatch runs main's definition, so the dispatched commit cannot rewrite it (ADR 0037).
        text = TRIAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^on:\n  repository_dispatch:\n    types: \[range-trial\]\n\n")
        self.assertNotIn("workflow_dispatch", text)
        runs = re.findall(r"(?m)^\s+(?:- )?run: (.*)$", text)
        self.assertEqual(runs, ["""'[[ "$SHA" =~ ^[0-9a-f]{40}$ && "$TRIAL" =~ ^[a-z0-9-]{1,32}$ ]]'""",
                                'python3 tools/ci/range_kvm.py --work "$RUNNER_TEMP/range" --trial "$TRIAL"'])
        payload = "${{ github.event.client_payload.sha }}", "${{ github.event.client_payload.trial }}"
        self.assertEqual(re.findall(r"\$\{\{.*?\}\}", text), [payload[0], payload[1], payload[0], payload[1]])
        self.assertIn(f"          ref: {payload[0]}\n", text)
        # The check runs before the checkout, and only env and the checkout's ref take the payload.
        self.assertLess(text.index("=~ ^[0-9a-f]{40}$"), text.index("actions/checkout@"))
        self.assertEqual(len(re.findall(r"(?m)^          (?:SHA|TRIAL|ref): \$\{\{", text)), 4)
        self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n")
        self.assertIn("persist-credentials: false", text)
        for needle in ("secrets.", "github.token", "pull_request", "continue-on-error", "|| true", "actions/upload-artifact@"):
            self.assertNotIn(needle, text)
        self.assertEqual(re.findall(r"uses: (\S+)", text), re.findall(r"uses: (actions/checkout@\S+)", CI.read_text(encoding="utf-8"))[:1])


if __name__ == "__main__":
    unittest.main()
