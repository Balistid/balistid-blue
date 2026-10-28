"""Tests for tools/ci/range_kvm.py and its CI job (ADR 0028): the self-test runs only on a GitHub-hosted
runner with KVM, from pinned inputs, without secrets or extra capabilities, and every way it cannot run
fails the job instead of skipping it (R6)."""

from __future__ import annotations

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
HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


class Recorder:
    """Stands in for subprocess.run; the docker call returns exit."""

    def __init__(self, exit: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.exit = exit

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
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

    def test_docker_gets_kvm_and_no_privilege(self) -> None:
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


class Workflow(unittest.TestCase):
    def test_job_runs_the_script_with_no_secret_or_write_permission(self) -> None:
        job = ci_job("range-kvm")
        self.assertIn("python3 tools/ci/range_kvm.py --work", job)
        self.assertIn("persist-credentials: false", job)
        self.assertNotIn("secrets.", job)
        self.assertNotIn("permissions:", job)  # the workflow's contents: read applies
        self.assertRegex(CI.read_text(encoding="utf-8"), r"(?m)^permissions:\n  contents: read\n")

    def test_job_checks_out_the_pull_requests_head(self) -> None:
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", ci_job("range-kvm"))


if __name__ == "__main__":
    unittest.main()
