"""Tests for tools/ci/release.py (ADR 0011, point 1): the manifest root checks, the local build that
must match CI's, and the bootstrap command that refuses a hash CI did not print (T37).
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import release  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
TRIGGER = ("name: ci\n\non:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\n"
           "  # The merge queue's group commit runs every job before it lands (ADR 0041).\n"
           "  merge_group:\n    types: [checks_requested]\n"
           "  # Weekly on main, so govulncheck sees advisories published without a new commit.\n"
           "  schedule:\n    - cron: \"17 5 * * 1\"\n")


def go_code(src: str) -> str:
    """Go source without comments, so a commented-out declaration does not count."""
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL))

# ci.yml go-release, the whole job: the build, the bundle, the printed hash and root command, the upload.
RELEASE_JOB = """
  go-release:
    needs: [go-static, go-test, go-race, selftest, docs-budget, pin-check, commit-lint, secrets, workflow-lint]
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    env:
      GOFLAGS: -mod=readonly
      GOWORK: "off"
      GOTOOLCHAIN: local
      CGO_ENABLED: "0"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Install Go (pinned by sha256) and check it against go.mod
        run: |
          curl -fsSLo "$RUNNER_TEMP/go.tgz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
          echo "$GO_SHA256  $RUNNER_TEMP/go.tgz" | sha256sum -c -
          tar -xzf "$RUNNER_TEMP/go.tgz" -C "$RUNNER_TEMP"
          echo "$RUNNER_TEMP/go/bin" >> "$GITHUB_PATH"
          "$RUNNER_TEMP/go/bin/go" version
          python3 tools/ci/go_gate.py toolchain --go-mod go.mod \\
            --goversion "$("$RUNNER_TEMP/go/bin/go" env GOVERSION)" --expect "$GO_VERSION"
      - name: Reproducible release build (no built binary runs in this job)
        run: |
          flags="-X github.com/Balistid/balistid-blue/internal/buildinfo.Version=${GITHUB_SHA}"
          a="$RUNNER_TEMP/build-a" b="$RUNNER_TEMP/other/build-b"
          mkdir -p "$a" "$b" "$RUNNER_TEMP/home-b" "$RUNNER_TEMP/tmp-b"
          git archive HEAD | tar -x -C "$a"
          git archive HEAD | tar -x -C "$b"
          # balistid-pi runs on the maintainer's arm64 Pi, installed by the hash printed below (ADR 0031).
          for target in balistid:amd64 balistid-runner:amd64 balistid-pi:arm64; do
            cmd="${target%:*}" arch="${target#*:}"
            (cd "$a" && GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$cmd" "./cmd/$cmd")
            (cd "$b" && umask 077 && HOME="$RUNNER_TEMP/home-b" TMPDIR="$RUNNER_TEMP/tmp-b" \\
              GOPATH="$RUNNER_TEMP/gopath-b" GOCACHE="$RUNNER_TEMP/cache-b" GOARCH="$arch" \\
              go build -trimpath -buildvcs=false -ldflags "$flags" -o "$cmd" "./cmd/$cmd")
          done
          # No built binary runs in this job: one run here could change what is bundled before it is
          # hashed. test_release.py checks the -X path names the real variable (it is ignored silently).
          for cmd in balistid balistid-runner balistid-pi; do
            python3 tools/ci/go_gate.py same "$a/$cmd" "$b/$cmd"
            sha256sum "$a/$cmd"
          done
          python3 tools/ci/release.py manifest --binary "$a/balistid-runner" --deploy "$a/deploy/runner" \\
            --out "$RUNNER_TEMP/release"
          python3 tools/ci/release.py bundle --dir "$RUNNER_TEMP/release" --out "$RUNNER_TEMP/balistid-runner-bundle.tar"
      # Root types the hash of this step on a push to main (ADR 0011, point 1). A pull request runs its
      # own workflow and can print anything, so the main workflow prints no hash there.
      - name: Install bundle of the range runner
        if: github.event_name == 'push'
        run: |
          sha=$(sha256sum "$RUNNER_TEMP/balistid-runner-bundle.tar" | cut -d' ' -f1)
          echo "Bundle sha256 of the runner at $GITHUB_SHA: $sha"
          python3 tools/ci/release.py bootstrap "$sha"
      # The maintainer downloads this file and root checks it against the hash above (ADR 0011, point 1).
      - name: Upload the bundle
        if: github.event_name == 'push'
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: balistid-runner-bundle
          path: ${{ runner.temp }}/balistid-runner-bundle.tar
          if-no-files-found: error
          retention-days: 30
"""


def write_inputs(root: Path) -> tuple[Path, Path]:
    binary = root / "bin"
    binary.write_bytes(b"\x7fELF runner")
    deploy = root / "deploy"
    deploy.mkdir()
    for name in release.DEPLOY:
        (deploy / name).write_text(f"{name}\n")
    return binary, deploy


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.binary, self.deploy = write_inputs(self.tmp)
        self.out = self.tmp / "out"

    def test_manifest_lists_every_file_in_order_as_sha256sum_does(self):
        digest = release.manifest(self.binary, self.deploy, self.out)
        text = (self.out / "MANIFEST").read_text()
        self.assertEqual(digest, hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual([line.split("  ")[1] for line in text.splitlines()], list(release.FILES))
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), sorted([*release.FILES, "MANIFEST"]))
        check = subprocess.run(["sha256sum", "-c", "--strict", "MANIFEST"], cwd=self.out, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual((self.out / "install").stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.out / "tmpfiles.conf").stat().st_mode & 0o777, 0o644)

    def test_symlinked_or_missing_input_fails(self):
        (self.deploy / "install").unlink()
        with self.assertRaises(FileNotFoundError):
            release.manifest(self.binary, self.deploy, self.out)
        (self.deploy / "install").symlink_to(self.binary)
        with self.assertRaises(ValueError):
            release.manifest(self.binary, self.deploy, self.tmp / "out2")

    def test_existing_output_directory_fails(self):
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            release.manifest(self.binary, self.deploy, self.out)

    def test_manifest_covers_exactly_deploy_runner(self):
        self.assertEqual(set(release.DEPLOY), {p.name for p in (REPO / "deploy" / "runner").iterdir()})

    # The local build must produce CI's bytes, and nothing else may run in CI's release job: its tail is
    # pinned whole, and its build lines use release.py's flags.
    def test_build_equals_ci(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text()
        job = ci[ci.index("\n  go-release:"):ci.index("\n  selftest:")]
        self.assertEqual(job, RELEASE_JOB)
        self.assertEqual(ci[:ci.index("\npermissions:")], TRIGGER)
        self.assertIn(f'flags="{release.VERSION_FLAG}${{GITHUB_SHA}}"', RELEASE_JOB)
        builds = [line for line in RELEASE_JOB.splitlines() if "go build" in line]
        self.assertEqual(len(builds), 2)
        for line in builds:
            self.assertTrue(line.endswith("go " + " ".join(release.GO_BUILD) + ' "$flags" -o "$cmd" "./cmd/$cmd")'))
        for setting in ("GOFLAGS: -mod=readonly", 'GOWORK: "off"', 'CGO_ENABLED: "0"', "GOTOOLCHAIN: local"):
            self.assertIn(setting, job)

    # The weekly run has no commit range, so the two range checks skip it, and with them the release.
    def test_scheduled_run_skips_range_checks_and_release(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text()
        for job in ("docs-budget", "commit-lint"):
            self.assertIn(f"\n  {job}:\n    # A scheduled run has no commit range to check.\n"
                          "    if: github.event_name != 'schedule'\n", ci)
        self.assertEqual(ci.count("github.event_name != 'schedule'"), 2)
        self.assertIn("docs-budget", RELEASE_JOB.split("needs:")[1].splitlines()[0])

    # A merge group's range is its own, and only a push or a group lifts the Agent trailer for Dependabot (ADR 0041).
    def test_merge_group_checks_the_groups_range(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text()
        for job in ("docs-budget", "commit-lint"):
            body = ci[ci.index(f"\n  {job}:\n"):]
            body = body[:body.index("\n\n  ")]
            for line in ("          GROUP_BASE: ${{ github.event.merge_group.base_sha }}\n",
                         "          GROUP_HEAD: ${{ github.event.merge_group.head_sha }}\n"):
                with self.subTest(job=job, line=line):
                    self.assertIn(line, body)
        self.assertEqual(ci.count("--dependabot-pr"), 1)
        self.assertIn('          if [ "$EVENT" = "push" ] || [ "$EVENT" = "merge_group" ] || '
                      '[ "$PR_AUTHOR" = "dependabot[bot]" ]; then\n            set -- "$@" --dependabot-pr\n', ci)

    # The bundle is uploaded only after every other check of the same run passed, a job added later included.
    # range-kvm alone is advisory until the maintainer makes it required (ADR 0028, point 4).
    def test_release_needs_every_other_job(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text()
        jobs = set(re.findall(r"(?m)^  ([a-z0-9-]+):$", ci[ci.index("\njobs:"):]))
        needs = re.findall(r"(?m)^    needs: \[(.*)\]$", RELEASE_JOB)
        self.assertEqual(len(needs), 1)
        self.assertIn("range-kvm", jobs)
        self.assertEqual(set(needs[0].split(", ")), jobs - {"go-release", "range-kvm"})

    # -X with a path that names no variable is ignored silently; CI runs no built binary to see it.
    def test_version_flag_names_the_real_variable(self):
        module = re.findall(r"^module (\S+)$", (REPO / "go.mod").read_text(), re.MULTILINE)
        self.assertEqual(release.VERSION_FLAG, f"-X {module[0]}/internal/buildinfo.Version=")
        code = go_code((REPO / "internal/buildinfo/buildinfo.go").read_text())
        self.assertEqual(re.findall(r'(?m)^var Version = "dev"$', code), ['var Version = "dev"'])

    def test_a_commented_out_version_does_not_count(self):
        for src in ('/*\nvar Version = "dev"\n*/\n', '// var Version = "dev"\n'):
            self.assertEqual(re.findall(r'(?m)^var Version = "dev"$', go_code(src)), [])

    def test_build_refuses_a_commit_that_is_not_40_hex(self):
        for commit in ("main", "4d1be61", "A" * 40, "a" * 41):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                release.build(REPO, commit, self.out)


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        binary, deploy = write_inputs(self.tmp)
        release.manifest(binary, deploy, self.tmp / "files")

    def test_equal_inputs_give_equal_bytes(self):
        a = release.bundle(self.tmp / "files", self.tmp / "a.tar")
        b = release.bundle(self.tmp / "files", self.tmp / "b.tar")
        self.assertEqual(a, b)
        with tarfile.open(self.tmp / "a.tar") as tar:
            members = tar.getmembers()
        self.assertEqual([m.name for m in members], ["MANIFEST", *release.FILES])
        self.assertTrue(all(m.isreg() and m.uid == 0 and m.mtime == 0 for m in members))

    def test_a_link_in_the_directory_fails(self):
        (self.tmp / "files" / "install").unlink()
        (self.tmp / "files" / "install").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            release.bundle(self.tmp / "files", self.tmp / "a.tar")


class BootstrapTest(unittest.TestCase):
    """Runs the command CI prints, as root types it, with stand-ins for runuser (reads as the caller), logger
    and tar (both recorded) ahead of its fixed PATH, and a stand-in install that records how it ran."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.mark = self.tmp / "ran"
        self.log = self.tmp / "log"
        self.log.write_text("")
        binary, deploy = write_inputs(self.tmp)
        (deploy / "install").write_text(f'#!/bin/sh\necho "$0 $1 $2 $3" > {self.mark}\nls "$1" > {self.mark}.ls\n')
        release.manifest(binary, deploy, self.tmp / "files")
        self.stage = self.tmp / "stage"
        self.stage.mkdir()
        self.bundle = self.stage / release.BUNDLE
        self.digest = release.bundle(self.tmp / "files", self.bundle)
        # A broken variant may stop before its rm; the test removes every copy it caused.
        before = set(Path("/tmp").glob("balistid-install.*"))
        self.addCleanup(lambda: [shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                                 for p in set(Path("/tmp").glob("balistid-install.*")) - before])
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        for name, body in (("runuser", 'while [ "$1" != -- ]; do shift; done; shift; exec "$@"'),
                           ("logger", ":"), ("tar", f'/usr/bin/tar "$@"; r=$?; echo "unpacked $r" >> {self.log}; exit $r'), ("id", "echo 1000")):
            (self.stubs / name).write_text(f'#!/bin/sh\necho "{name} $*" >> {self.log}\n{body}\n')
            (self.stubs / name).chmod(0o755)

    def printed(self, digest: str) -> list[str]:
        out = subprocess.run([sys.executable, str(REPO / "tools/ci/release.py"), "bootstrap", digest],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(len(out), 4)
        argv = shlex.split(out[3])
        self.assertEqual(argv[:3], ["/usr/bin/env", "-i", f"PATH={release.ROOT_PATH}"])
        return [*argv[:2], f"PATH={self.stubs}:{release.ROOT_PATH}", *argv[3:]]

    def run_bootstrap(self, stage: str, digest: str, env: dict | None = None,
                      maintainer: str = "maint") -> subprocess.CompletedProcess:
        return subprocess.run(self.printed(digest), input=f"dir={stage}\nuser={maintainer}\n",
                              env=env or {"PATH": os.environ["PATH"]}, capture_output=True, text=True, timeout=90)

    def logged(self, name: str) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if line.startswith(name + " ")]

    def assert_ran_nothing(self, r: subprocess.CompletedProcess, mismatch: bool = True):
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.mark.exists())
        self.assertEqual(self.logged("tar"), [], "tar ran on bytes that failed the hash")
        want = ["logger -s -t balistid-install bundle does not match the typed sha256"] if mismatch else []
        want.append(f"logger -s -t balistid-install bootstrap stopped, status {r.returncode}")
        self.assertEqual(self.logged("logger"), want)
        self.log.write_text("")

    def run_variants(self, variants):
        """Runs each broken text of BOOTSTRAP under a wrong hash with a download that is a shell script:
        tar may be reached (a typo can skip the if) but never unpacks, install never runs, and nothing runs
        the download."""
        evil = self.tmp / "evil"
        evil.mkdir()
        hit = self.tmp / "executed"
        (evil / release.BUNDLE).write_text(f"touch {hit}\n")
        argv = self.printed("0" * 64)
        script = argv.index("-c") + 1
        for label, text in variants:
            subprocess.run([*argv[:script], text, *argv[script + 1:]], input=f"dir={evil}\nuser=maint\n",
                           env={"PATH": os.environ["PATH"]}, cwd=self.tmp, capture_output=True, text=True,
                           timeout=60)
            self.assertNotIn("unpacked 0", self.logged("unpacked"), label)
            self.assertFalse(self.mark.exists(), label)
            self.assertFalse(hit.exists(), label)
            self.log.write_text("")

    # Root types this by hand: no dropped character anywhere, and none of the typos that turned a test
    # into a command, a redirect or a background job in the gate, may unpack or run another bundle.
    def test_no_dropped_or_mistyped_character_passes_another_bundle(self):
        text = release.BOOTSTRAP
        variants = [(f"drop {i}: {text[max(0, i - 12):i + 12]!r}", text[:i] + text[i + 1:]) for i in range(len(text))]
        gate = range(text.index("hash=$("), text.index("else logger"))
        for c in "!:>&$":
            variants += [(f"{c!r} at {i}", text[:i] + c + text[i + 1:]) for i in gate]
            variants += [(f"{c!r} before {i}", text[:i] + c + text[i:]) for i in gate]
        self.run_variants(variants)

    def test_the_printed_hash_runs_the_checked_install_from_the_copy(self):
        r = self.run_bootstrap(str(self.stage), self.digest)
        self.assertEqual(r.returncode, 0, r.stderr)
        script, copy, user, digest = self.mark.read_text().split()
        self.assertEqual((script, user, digest), (f"{copy}/install", "maint", self.digest))
        self.assertTrue(copy.startswith("/tmp/balistid-install."))
        listed = sorted(Path(f"{self.mark}.ls").read_text().split())
        self.assertEqual(self.logged("tar"), [f"tar -xf {copy}/{self.digest} -C {copy}"])
        self.assertEqual(listed, sorted(["MANIFEST", self.digest, *release.FILES]))
        self.assertFalse(Path(copy).exists(), "the root-only copy outlived the bootstrap")
        self.assertEqual(self.logged("runuser"), [f"runuser -u maint -- cat -- {self.bundle}"])
        self.assertEqual(self.logged("logger"), [])

    def test_typed_stage_and_maintainer_are_never_parsed(self):
        marker = self.tmp / "expanded"
        for stage, user in ((f"/tmp/$(touch {marker})", "maint"), (str(self.stage), f"maint$(touch {marker})"),
                            (f"/tmp/`touch {marker}`", "maint")):
            with self.subTest(stage=stage, user=user):
                self.run_bootstrap(stage, self.digest, maintainer=user)
                self.assertFalse(marker.exists())

    def test_root_shell_environment_does_not_reach_the_check(self):
        tmpdir = self.tmp / "agent-tmp"
        tmpdir.mkdir()
        (self.tmp / "sha256sum").write_text("#!/bin/sh\nexit 0\n")
        (self.tmp / "sha256sum").chmod(0o755)
        env = {"PATH": f"{self.tmp}:{os.environ['PATH']}", "TMPDIR": str(tmpdir),
               "BASH_FUNC_sha256sum%%": "() { return 0; }"}
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), "0" * 64, env))
        self.assertEqual(list(tmpdir.iterdir()), [])

    def test_a_hash_ci_did_not_print_runs_nothing(self):
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), "0" * 64))

    def test_a_changed_bundle_runs_nothing(self):
        with self.bundle.open("ab") as f:
            f.write(b"\0" * 512)
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), self.digest))

    def test_a_fifo_does_not_hang_the_root_shell(self):
        self.bundle.unlink()
        os.mkfifo(self.bundle)
        r = self.run_bootstrap(str(self.stage), self.digest)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.mark.exists())
        self.assertNotIn("unpacked 0", self.logged("unpacked"))

    def test_a_bundle_over_the_cap_is_cut_and_refused(self):
        with self.bundle.open("r+b") as f:
            f.truncate((release.BUNDLE_MAX_MIB << 20) + 1)
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), release.sha256(self.bundle)))

    def test_an_empty_or_relative_stage_runs_nothing(self):
        for stage in ("", "relative/stage", "-"):
            with self.subTest(stage=stage):
                self.assert_ran_nothing(self.run_bootstrap(stage, self.digest), mismatch=False)

    def test_printed_command_has_no_placeholder_and_no_single_quote(self):
        self.assertNotIn("'", release.BOOTSTRAP)
        self.assertEqual(self.printed(self.digest)[-1], self.digest)
        self.assertNotIn("set -e", release.BOOTSTRAP)

    def test_lines_without_their_prefix_run_nothing(self):
        r = subprocess.run(self.printed(self.digest), input=f"{self.stage}\nmaint\n", env={"PATH": os.environ["PATH"]},
                           capture_output=True, text=True, timeout=60)
        self.assert_ran_nothing(r, mismatch=False)

    # A typo in the wrapper may make sh read commands from the typed lines (-s) or treat the script as
    # a file name: the typed lines must only assign, so a program planted at the typed path never runs.
    def test_a_mistyped_wrapper_runs_nothing_typed(self):
        hit = self.tmp / "executed"
        planted = self.tmp / "planted"
        planted.write_text(f"#!/bin/sh\ntouch {hit}\n")
        planted.chmod(0o755)
        argv = self.printed("0" * 64)
        flag = argv.index("-c")
        for letter in "abcdefghijklmnopqrstuvwxyz":
            with self.subTest(letter=letter):
                broken = [*argv[:flag], f"-{letter}", *argv[flag + 1:]]
                subprocess.run(broken, input=f"dir={planted}\nuser={planted}\n", env={"PATH": os.environ["PATH"]},
                               cwd=self.tmp, capture_output=True, text=True, timeout=60)
                self.assertFalse(hit.exists())
                self.assertFalse(self.mark.exists())

    def test_a_system_account_never_reads_the_bundle(self):
        (self.stubs / "id").write_text(f'#!/bin/sh\necho "id $*" >> {self.log}\necho 0\n')
        r = self.run_bootstrap(str(self.stage), self.digest, maintainer="root")
        self.assert_ran_nothing(r, mismatch=False)


STUBS = {
    # stat -c FORMAT -- PATH, exactly as install calls it: the state the test gives PATH; nothing given is
    # ENOENT as GNU stat words it in the C locale; "ERROR" is any other failure.
    "stat": '[ "$1" = -c ] && [ "$2" = "%U:%G %a %F" ] && [ "$3" = -- ] || exit 2; echo "stat $4" >> "$STUB_LOG"; '
            'v=$(/usr/bin/grep -F "$4	" "$STUB_STATE" | /usr/bin/cut -f2); '
            '[ "$v" = ERROR ] && { echo "stat: cannot statx \'$4\': Permission denied" >&2; exit 1; }; '
            '[ -n "$v" ] || { echo "stat: cannot statx \'$4\': No such file or directory" >&2; exit 1; }; echo "$v"',
    # STUB_ID_FAIL: right answer, failed status.
    "id": '[ $# -eq 1 ] && { echo "$STUB_UID"; [ -z "$STUB_ID_FAIL" ] || exit 7; exit 0; }; '
          '[ "$2" = ghost ] && exit 1; [ "$2" = daemon ] && { echo 2; exit 0; }; [ "$2" = nobody ] && { echo 65534; exit 0; }; echo 1000',
    # systemctl show -P PROPERTY UNIT: the value the test gives "PROPERTY UNIT"; nothing given is a unit not
    # installed yet (ActiveState inactive, every other property empty). STUB_FAIL: "1" no answer, "7" the
    # answer with a failed status; for every property, or only STUB_FAIL_PROP when that is set.
    # daemon-reload loads what is on disk: the answers become those of STUB_UNITS_AFTER.
    "systemctl": 'if [ "$1" = show ]; then [ "$2" = -P ] && [ $# -eq 4 ] || exit 2; f=; '
                 '[ -z "$STUB_FAIL_PROP" ] || [ "$STUB_FAIL_PROP" = "$3" ] && f=$STUB_FAIL; [ "$f" = 1 ] && exit 1; '
                 'v=$(/usr/bin/grep -F "$3 $4	" "$STUB_UNITS" | /usr/bin/cut -f2); '
                 '[ -n "$v" ] || [ "$3" != ActiveState ] || v=inactive; echo "$v"; '
                 '[ "$f" = 7 ] && exit 7; exit 0; else echo "systemctl $*" >> "$STUB_LOG"; '
                 '[ "$1" != daemon-reload ] || /usr/bin/cp "$STUB_UNITS_AFTER" "$STUB_UNITS"; fi',
}
WRITERS = ("install", "sync", "mv", "systemd-sysusers", "systemd-tmpfiles", "usermod", "logger")
LIB, STATE = "/usr/local/lib/balistid", "/var/lib/balistid"
UNITS = ("balistid-runner-tick.timer", "balistid-runner-tick.service", "balistid-runner-build.service")
ETC_DIRS = ("/etc/sysusers.d", "/etc/tmpfiles.d")


class InstallTest(unittest.TestCase):
    """Runs deploy/runner/install with only stand-ins on PATH: any other command it ran would fail."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        for name, body in STUBS.items():
            (bin_ / name).write_text(f"#!/bin/sh\n{body}\n")
        for name in WRITERS:
            (bin_ / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "$STUB_LOG"\n[ "$STUB_FAIL_WRITER" != {name} ]\n')
        for p in bin_.iterdir():
            p.chmod(0o755)
        self.copy = self.tmp / "copy"
        self.copy.mkdir()
        self.log = self.tmp / "log"
        self.log.write_text("")
        self.state = {str(self.copy): "root:root 700 directory"}
        self.units: dict[tuple[str, str], str] = {}  # (property, unit): value
        # After the reload: every unit from the file this install wrote, nothing else.
        self.after = {("FragmentPath", u): f"/etc/systemd/system/{u}" for u in UNITS}
        self.env = {"PATH": str(bin_), "STUB_LOG": str(self.log), "STUB_UID": "0", "STUB_FAIL": "", "STUB_ID_FAIL": "", "STUB_FAIL_WRITER": "",
                    "STUB_FAIL_PROP": "",
                    "STUB_STATE": str(self.tmp / "state"), "STUB_UNITS": str(self.tmp / "units"),
                    "STUB_UNITS_AFTER": str(self.tmp / "units-after")}

    hash = "ab" * 32

    def run_install(self, maintainer: str = "maint") -> subprocess.CompletedProcess:
        (self.tmp / "state").write_text("".join(f"{k}\t{v}\n" for k, v in self.state.items()))
        (self.tmp / "units").write_text("".join(f"{p} {u}\t{v}\n" for (p, u), v in self.units.items()))
        (self.tmp / "units-after").write_text("".join(f"{p} {u}\t{v}\n" for (p, u), v in self.after.items()))
        r = subprocess.run(["/bin/sh", str(REPO / "deploy/runner/install"), str(self.copy), maintainer, self.hash],
                           env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotIn("not found", r.stderr, "install ran a command that has no stand-in")
        return r

    def lines(self, kind: str) -> list[str]:
        out = []
        for line in self.log.read_text().splitlines():
            word = line.split()[0]
            if (kind == "log") == (word == "logger") and word in (*WRITERS, "systemctl"):
                out.append(line)
        return out

    def refused(self, r: subprocess.CompletedProcess, reason: str):
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.lines("write"), [], "a refusal wrote to the host")
        logged = self.lines("log")
        self.assertEqual(len(logged), 1)
        self.assertIn("logger -s -t balistid-install install stopped (ADR 0011): ", logged[0])
        self.assertIn(reason, logged[0])
        self.log.write_text("")

    def assert_first_install(self, r: subprocess.CompletedProcess):
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.copy

        def put(mode: str, src: str, dst: str) -> list[str]:
            return [f"install -m {mode} {c}/{src} {dst}.new", f"sync {dst}.new", f"mv -fT {dst}.new {dst}",
                    f"sync {dst.rsplit('/', 1)[0]}"]

        self.assertEqual(self.lines("write"), [
            f"install -d -o root -g root -m 0755 {LIB}",
            *put("0755", "balistid-runner", f"{LIB}/balistid-runner"),
            *(line for u in UNITS[::-1] for line in put("0644", u, f"/etc/systemd/system/{u}")),
            "install -d -m 0755 /etc/sysusers.d",
            "install -d -m 0755 /etc/tmpfiles.d",
            *put("0644", "sysusers.conf", "/etc/sysusers.d/balistid-runner.conf"),
            *put("0644", "tmpfiles.conf", "/etc/tmpfiles.d/balistid-runner.conf"),
            "systemd-sysusers /etc/sysusers.d/balistid-runner.conf",
            "systemd-tmpfiles --create /etc/tmpfiles.d/balistid-runner.conf",
            f"install -d -o maint -g balistid-runner -m 2750 {STATE}/inbox",
            f"install -d -o maint -g balistid-runner -m 2750 {STATE}/objects",
            "usermod -aG balistid-agents maint",
            "systemctl daemon-reload"])
        self.assertEqual(self.lines("log"),
                         [f"logger -s -t balistid-install installed (ADR 0011) runner bundle sha256 {self.hash} for maint"])
        self.log.write_text("")

    def test_first_install_writes_exactly_this_after_the_checks(self):
        self.assert_first_install(self.run_install())

    # A cut copy must never sit at a path systemd or the runner reads: only a rename reaches it.
    def test_a_target_changes_only_by_rename(self):
        self.assertEqual(self.run_install().returncode, 0)
        for target in (f"{LIB}/balistid-runner", *(f"/etc/systemd/system/{u}" for u in UNITS),
                       "/etc/sysusers.d/balistid-runner.conf", "/etc/tmpfiles.d/balistid-runner.conf"):
            with self.subTest(target=target):
                writes = [w for w in self.lines("write") if w.split()[0] in ("install", "mv") and w.split()[-1] == target]
                self.assertEqual(writes, [f"mv -fT {target}.new {target}"])

    def test_a_failed_write_is_logged_with_its_step(self):
        self.env["STUB_FAIL_WRITER"] = "systemd-sysusers"
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(self.lines("log"), ["logger -s -t balistid-install install stopped (ADR 0011): "
                                             "failed: systemd-sysusers /etc/sysusers.d/balistid-runner.conf, status 1"])

    def test_every_check_precedes_the_first_write(self):
        self.assertEqual(self.run_install().returncode, 0)
        words = [line.split()[0] for line in self.log.read_text().splitlines()]
        self.assertNotIn("stat", words[words.index("install"):])

    def test_reinstall_keeps_inbox_and_objects(self):
        self.state |= {LIB: "root:root 755 directory", STATE: "root:root 755 directory",
                       f"{STATE}/inbox": "maint:balistid-runner 2750 directory",
                       f"{STATE}/objects": "maint:balistid-runner 2750 directory",
                       **{path: "root:root 755 directory" for path in ETC_DIRS}}
        r = self.run_install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse([w for w in self.lines("write") if "/inbox" in w or "/objects" in w])

    def test_a_running_or_unknown_unit_refuses(self):
        for unit in UNITS:
            for active in ("active", "activating", "deactivating", "reloading", "x"):
                with self.subTest(unit=unit, active=active):
                    self.units = {("ActiveState", unit): active}
                    self.refused(self.run_install(), f"{unit} is {active}, not stopped")
        self.units = {}
        for fail in ("1", "7"):
            with self.subTest(fail=fail):
                self.env["STUB_FAIL"] = fail
                self.refused(self.run_install(), "cannot query balistid-runner-tick.timer")

    def test_a_drop_in_or_another_fragment_refuses(self):
        for unit in UNITS:
            for paths in (f"/etc/systemd/system/{unit}.d/override.conf",
                          f"/etc/systemd/system.control/{unit}.d/50-RestrictSUIDSGID.conf",
                          f"/run/systemd/system/{unit}.d/a.conf /usr/lib/systemd/system/{unit}.d/b.conf"):
                with self.subTest(unit=unit, drop_ins=paths):
                    self.units = {("DropInPaths", unit): paths}
                    self.refused(self.run_install(), f"{unit} has drop-ins: {paths}")
            for path in (f"/run/systemd/system/{unit}", f"/run/systemd/transient/{unit}",
                         f"/usr/lib/systemd/system/{unit}", f"/etc/systemd/system/{unit}.bak",
                         f"/x:/etc/systemd/system/{unit}", f"/x/etc/systemd/system/{unit}"):
                with self.subTest(unit=unit, fragment=path):
                    self.units = {("FragmentPath", unit): path}
                    self.refused(self.run_install(), f"{unit} is loaded from {path}, not /etc/systemd/system/{unit}")

    # systemd answers only for what it has loaded, so a drop-in for a unit with no file yet shows only
    # after the install's own reload; the install must stop there and not report itself installed.
    def test_a_drop_in_seen_only_after_the_reload_refuses(self):
        for unit in UNITS:
            for prop, value, reason in (
                    ("DropInPaths", f"/etc/systemd/system/{unit}.d/old.conf", f"{unit} has drop-ins"),
                    ("FragmentPath", f"/run/systemd/system/{unit}", f"{unit} is loaded from /run/systemd/system/{unit}"),
                    ("FragmentPath", "", f"{unit} is loaded from , not /etc/systemd/system/{unit}")):
                with self.subTest(unit=unit, prop=prop, value=value):
                    self.after = {("FragmentPath", u): f"/etc/systemd/system/{u}" for u in UNITS}
                    self.after[(prop, unit)] = value
                    r = self.run_install()
                    self.assertNotEqual(r.returncode, 0)
                    logged = self.lines("log")
                    self.assertEqual(len(logged), 1, logged)
                    self.assertIn("install stopped (ADR 0011): ", logged[0])
                    self.assertIn(reason, logged[0])
                    self.assertIn("systemctl daemon-reload", self.lines("write"))
                    self.log.write_text("")

    def test_a_unit_from_this_install_or_none_passes(self):
        for installed in (UNITS, UNITS[:1], ()):
            with self.subTest(installed=installed):
                self.units = {("FragmentPath", u): f"/etc/systemd/system/{u}" for u in installed}
                self.assert_first_install(self.run_install())

    def test_a_failed_unit_query_refuses(self):
        # "7" answers what passes (empty, or the expected path) and fails; the failure alone must refuse.
        self.units = {("FragmentPath", u): f"/etc/systemd/system/{u}" for u in UNITS}
        for prop in ("DropInPaths", "FragmentPath"):
            for fail in ("1", "7"):
                with self.subTest(prop=prop, fail=fail):
                    self.env |= {"STUB_FAIL": fail, "STUB_FAIL_PROP": prop}
                    self.refused(self.run_install(), f"cannot query {prop} of balistid-runner-tick.timer")

    def test_a_command_that_answers_right_but_fails_refuses(self):
        self.env["STUB_ID_FAIL"] = "1"
        self.refused(self.run_install(), "id failed")

    def test_a_stat_error_is_not_absent(self):
        for path in (LIB, STATE, f"{STATE}/inbox", f"{STATE}/objects", *ETC_DIRS):
            with self.subTest(path=path):
                self.state = {str(self.copy): "root:root 700 directory", path: "ERROR"}
                self.refused(self.run_install(), f"cannot stat {path}")

    def test_a_path_prepared_by_someone_else_refuses(self):
        for path, value in ((LIB, "maint:maint 755 directory"), (LIB, "root:root 777 directory"),
                            (LIB, "root:root 777 symbolic link"), (STATE, "maint:root 755 directory"),
                            (f"{STATE}/inbox", "maint:balistid-runner 777 directory"),
                            (f"{STATE}/inbox", "maint:balistid-runner 777 symbolic link"),
                            (f"{STATE}/objects", "other:balistid-runner 2750 directory"),
                            *((path, value) for path in ETC_DIRS
                              for value in ("root:root 750 directory", "root:root 644 regular file",
                                            "root:root 777 symbolic link", "maint:root 755 directory"))):
            with self.subTest(path=path, value=value):
                self.state = {str(self.copy): "root:root 700 directory", path: value}
                self.refused(self.run_install(), f"{path} is {value}, not ")

    def test_a_copy_that_is_not_root_only_refuses(self):
        for value in ("maint:maint 700 directory", "root:root 755 directory", "root:root 777 symbolic link"):
            with self.subTest(value=value):
                self.state = {str(self.copy): value}
                self.refused(self.run_install(), "is not a root-only copy")

    def test_not_root_or_a_bad_maintainer_refuses(self):
        for name, reason in (("root", "bad maintainer name"), ("", "bad maintainer name"),
                             ("MAINTAINER", "bad maintainer name"), ("1x", "bad maintainer name"),
                             ("a b", "bad maintainer name"), ("ghost", "no user ghost"),
                             ("daemon", "daemon is not a regular user"), ("nobody", "nobody is not a regular user")):
            with self.subTest(name=name):
                self.refused(self.run_install(name), reason)
        self.env["STUB_UID"] = "1000"
        self.refused(self.run_install(), "not root")


if __name__ == "__main__":
    unittest.main()
