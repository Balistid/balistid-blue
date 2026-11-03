"""Tests for tools/ci/release.py (ADR 0011, point 1; ADR 0058): MANIFEST v1, the local build that must match CI's,
and the first-install command that runs only an installer the typed key's signature names (T37).
"""

from __future__ import annotations

import concurrent.futures
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
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
PRINCIPAL, NAMESPACE = "maintainer@balistid.dev", "install@balistid.dev"


def go_code(src: str) -> str:
    """Go source without comments, so a commented-out declaration does not count."""
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL))

# ci.yml go-release, the whole job: the builds, the bundle, the printed MANIFEST and root command, the upload.
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
          for target in balistid:amd64 balistid-runner:amd64 balistid-install:amd64 balistid-pi:arm64; do
            cmd="${target%:*}" arch="${target#*:}"
            (cd "$a" && GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$cmd" "./cmd/$cmd")
            (cd "$b" && umask 077 && HOME="$RUNNER_TEMP/home-b" TMPDIR="$RUNNER_TEMP/tmp-b" \\
              GOPATH="$RUNNER_TEMP/gopath-b" GOCACHE="$RUNNER_TEMP/cache-b" GOARCH="$arch" \\
              go build -trimpath -buildvcs=false -ldflags "$flags" -o "$cmd" "./cmd/$cmd")
          done
          # No built binary runs in this job: one run here could change what is bundled before it is
          # hashed. test_release.py checks the -X path names the real variable (it is ignored silently).
          for cmd in balistid balistid-runner balistid-install balistid-pi; do
            python3 tools/ci/go_gate.py same "$a/$cmd" "$b/$cmd"
            sha256sum "$a/$cmd"
          done
          python3 tools/ci/release.py manifest --binary "$a/balistid-runner" --installer "$a/balistid-install" \\
            --deploy "$a/deploy/runner" --signers "$a/deploy/install/allowed_signers" --commit "$GITHUB_SHA" \\
            --out "$RUNNER_TEMP/release"
          python3 tools/ci/release.py bundle --dir "$RUNNER_TEMP/release" --out "$RUNNER_TEMP/balistid-runner-bundle.tar"
          cp "$RUNNER_TEMP/release/MANIFEST" "$RUNNER_TEMP/MANIFEST"
      # The maintainer signs a MANIFEST only if it equals the one this step prints on a push to main (ADR 0058,
      # point 1). A pull request runs its own workflow and can print anything, so the main workflow prints nothing there.
      - name: MANIFEST of the range runner and the first-install command
        if: github.event_name == 'push'
        run: |
          echo "MANIFEST of the runner at $GITHUB_SHA:"
          cat "$RUNNER_TEMP/MANIFEST"
          python3 tools/ci/release.py bootstrap --signers deploy/install/allowed_signers
      # The maintainer downloads both, signs the MANIFEST and installs with balistid-install (ADR 0058).
      - name: Upload the bundle and its MANIFEST
        if: github.event_name == 'push'
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: balistid-runner-bundle
          path: |
            ${{ runner.temp }}/balistid-runner-bundle.tar
            ${{ runner.temp }}/MANIFEST
          if-no-files-found: error
          retention-days: 30
"""


class Key:
    """A software signing key made at test runtime in a temp directory; nothing secret is committed. A missing
    ssh-keygen fails the test rather than skipping it."""

    def __init__(self, directory: Path):
        self.path = directory / "k"
        subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(self.path)], check=True)
        kind, blob = (self.path.parent / "k.pub").read_text().split()[:2]
        self.signers = f'{PRINCIPAL} namespaces="{NAMESPACE}" {kind} {blob}\n'
        out = subprocess.run([SSH_KEYGEN, "-l", "-f", f"{self.path}.pub"], check=True, capture_output=True, text=True)
        self.fingerprint = out.stdout.split()[1]

    def sign(self, manifest: Path, out: Path, namespace: str = NAMESPACE) -> None:
        sig = manifest.parent / (manifest.name + ".sig")
        sig.unlink(missing_ok=True)
        subprocess.run([SSH_KEYGEN, "-q", "-Y", "sign", "-f", str(self.path), "-n", namespace, str(manifest)], check=True)
        shutil.move(sig, out)


def write_inputs(root: Path, signers: str = "maintainer@balistid.dev x\n",
                 installer: str = "#!/bin/sh\n") -> tuple[Path, Path, Path, Path]:
    binary = root / "bin"
    binary.write_bytes(b"\x7fELF runner")
    inst = root / "installer"
    inst.write_text(installer)
    deploy = root / "deploy"
    deploy.mkdir()
    for name in release.DEPLOY:
        (deploy / name).write_text(f"{name}\n")
    keys = root / "allowed_signers"
    keys.write_text(signers)
    return binary, inst, deploy, keys


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.inputs = write_inputs(self.tmp)
        self.out = self.tmp / "out"

    def test_manifest_is_v1_with_every_file_sorted_as_sha256sum_writes_it(self):
        digest = release.manifest(*self.inputs, COMMIT, self.out)
        text = (self.out / "MANIFEST").read_text()
        self.assertEqual(digest, hashlib.sha256(text.encode()).hexdigest())
        lines = text.splitlines()
        self.assertEqual(lines[:3], ["balistid-manifest 1", "component runner", f"commit {COMMIT}"])
        self.assertEqual([line.split("  ")[1] for line in lines[3:]], sorted(release.FILES))
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), sorted([*release.FILES, "MANIFEST"]))
        check = subprocess.run(["sha256sum", "-c", "--strict", "-"], cwd=self.out, capture_output=True,
                               input="\n".join(lines[3:]) + "\n", text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        for name, mode in (("balistid-runner", 0o755), ("balistid-install", 0o755), ("tmpfiles.conf", 0o644),
                           ("allowed_signers", 0o644)):
            self.assertEqual((self.out / name).stat().st_mode & 0o777, mode, name)

    def test_symlinked_or_missing_input_fails(self):
        deploy = self.inputs[2]
        (deploy / "tmpfiles.conf").unlink()
        with self.assertRaises(FileNotFoundError):
            release.manifest(*self.inputs, COMMIT, self.out)
        (deploy / "tmpfiles.conf").symlink_to(self.inputs[0])
        with self.assertRaises(ValueError):
            release.manifest(*self.inputs, COMMIT, self.tmp / "out2")

    def test_existing_output_directory_fails(self):
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            release.manifest(*self.inputs, COMMIT, self.out)

    def test_a_commit_that_is_not_40_hex_fails(self):
        for commit in ("main", "4d1be61", "A" * 40, "a" * 41, ""):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                release.manifest(*self.inputs, commit, self.tmp / f"out-{len(commit)}")

    def test_manifest_covers_exactly_deploy_runner(self):
        self.assertEqual(set(release.DEPLOY), {p.name for p in (REPO / "deploy" / "runner").iterdir()})

    # What release.py bundles is what the installer's table installs, under the names it reads.
    def test_files_and_names_are_the_installers(self):
        runner = go_code((REPO / "internal/install/runner.go").read_text())
        table = runner[runner.index("var runnerTable = []target{"):]
        table = table[:table.index("\n}\n")]
        names = re.findall(r'^\t\{"([a-z0-9._-]+)", ', table, re.M)
        names += ["allowed_signers"] if "{signersName, " in table else []
        self.assertEqual(sorted(names), sorted(release.FILES))
        verify = go_code((REPO / "internal/install/verify.go").read_text())
        self.assertIn(f'bundleName  = "{release.BUNDLE}"', verify)
        self.assertIn(f'sigName     = "{release.SIG}"', verify)
        self.assertIn(f'signersName = "{release.SIGNERS}"', verify)
        self.assertIn("maxSigBytes = 4 << 10", verify)
        self.assertEqual(release.SIG_MAX_BYTES, 4 << 10)
        bundle = go_code((REPO / "internal/install/bundle.go").read_text())
        self.assertIn(f"MaxBundleBytes = {release.BUNDLE_MAX_MIB} << 20", bundle)

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
        for cmd in (release.BINARY, release.INSTALLER):
            self.assertIn(f" {cmd}:amd64 ", RELEASE_JOB)
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
        # range-kvm and mutation run on pull requests and the merge queue only, never on the push a release builds.
        self.assertEqual(set(needs[0].split(", ")), jobs - {"go-release", "range-kvm", "mutation"})

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
        release.manifest(*write_inputs(self.tmp), COMMIT, self.tmp / "files")

    def test_equal_inputs_give_equal_bytes(self):
        a = release.bundle(self.tmp / "files", self.tmp / "a.tar")
        b = release.bundle(self.tmp / "files", self.tmp / "b.tar")
        self.assertEqual(a, b)
        with tarfile.open(self.tmp / "a.tar") as tar:
            members = tar.getmembers()
        self.assertEqual([m.name for m in members], ["MANIFEST", *release.FILES])
        self.assertTrue(all(m.isreg() and m.uid == 0 and m.mtime == 0 for m in members))

    def test_a_link_in_the_directory_fails(self):
        (self.tmp / "files" / "tmpfiles.conf").unlink()
        (self.tmp / "files" / "tmpfiles.conf").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            release.bundle(self.tmp / "files", self.tmp / "a.tar")


class FingerprintTest(unittest.TestCase):
    def test_it_is_the_one_ssh_keygen_prints(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        key = Key(tmp)
        (tmp / "s").write_text(key.signers)
        self.assertEqual(release.fingerprint(tmp / "s"), key.fingerprint)
        for bad in ("", key.signers * 2, key.signers.rstrip("\n"), key.signers.replace(" ssh", "  ssh"),
                    key.signers.replace(key.signers.split()[3], "!!!!")):
            with self.subTest(bad=bad):
                (tmp / "s").write_text(bad)
                with self.assertRaises(ValueError):
                    release.fingerprint(tmp / "s")


class BootstrapTest(unittest.TestCase):
    """Runs the command CI prints, as root types it, with stand-ins for runuser (reads as the caller), logger
    and tar (both recorded) ahead of its fixed PATH, real ssh-keygen and runtime keys, and a stand-in
    balistid-install that records how it ran."""

    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.mark = self.tmp / "ran"
        self.log = self.tmp / "log"
        self.log.write_text("")
        self.key = Key(self.subdir("key"))
        self.stage = self.release(self.key, self.key, "stage")
        self.bundle = self.stage / release.BUNDLE
        # A broken variant may stop before its rm; the test removes every copy it caused.
        before = set(Path("/tmp").glob("balistid-install.*"))
        self.addCleanup(lambda: [shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                                 for p in set(Path("/tmp").glob("balistid-install.*")) - before])
        self.stubs = self.tmp / "stubs"
        self.stubs.mkdir()
        for name, body in (("runuser", 'while [ "$1" != -- ]; do shift; done; shift; exec "$@"'),
                           ("logger", ":"), ("tar", '/usr/bin/tar "$@"'), ("id", "echo 1000")):
            (self.stubs / name).write_text(f'#!/bin/sh\necho "{name} $*" >> {self.log}\n{body}\n')
            (self.stubs / name).chmod(0o755)

    def subdir(self, name: str) -> Path:
        d = self.tmp / name
        d.mkdir()
        return d

    def release(self, signer: Key, listed: Key, name: str, installer: str | None = None,
                namespace: str = NAMESPACE) -> Path:
        """A download directory: the bundle with listed's allowed_signers, its MANIFEST signed by signer."""
        work = self.subdir(name + "-work")
        script = installer or f'#!/bin/sh\necho "$0 $*" > {self.mark}\nls "$2" > {self.mark}.ls\n'
        release.manifest(*write_inputs(work, listed.signers, script), COMMIT, work / "files")
        stage = self.subdir(name)
        release.bundle(work / "files", stage / release.BUNDLE)
        signer.sign(work / "files" / "MANIFEST", stage / release.SIG, namespace)
        return stage

    def printed(self, signers: str | None = None) -> list[str]:
        (self.tmp / "signers").write_text(signers or self.key.signers)
        out = subprocess.run([sys.executable, str(REPO / "tools/ci/release.py"), "bootstrap", "--signers",
                              str(self.tmp / "signers")], capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual(len(out), 5)
        argv = shlex.split(out[4])
        self.assertEqual(argv[:3], ["/usr/bin/env", "-i", f"PATH={release.ROOT_PATH}"])
        return [*argv[:2], f"PATH={self.stubs}:{release.ROOT_PATH}", *argv[3:]]

    def run_bootstrap(self, stage: str, argv: list[str] | None = None, env: dict | None = None,
                      maintainer: str = "maint") -> subprocess.CompletedProcess:
        return subprocess.run(argv or self.printed(), input=f"dir={stage}\nuser={maintainer}\n",
                              env=env or {"PATH": os.environ["PATH"]}, capture_output=True, text=True, timeout=90)

    def logged(self, name: str) -> list[str]:
        return [line for line in self.log.read_text().splitlines() if line.startswith(name + " ")]

    def assert_ran_nothing(self, r: subprocess.CompletedProcess, unsigned: bool = True):
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.mark.exists(), "an installer ran")
        want = ["logger -s -t balistid-install the manifest is not signed by the typed key"] if unsigned else []
        want.append(f"logger -s -t balistid-install bootstrap stopped, status {r.returncode}")
        self.assertEqual(self.logged("logger"), want)
        self.log.write_text("")

    def test_the_signed_bundle_runs_its_installer_from_the_copy(self):
        r = self.run_bootstrap(str(self.stage))
        self.assertEqual(r.returncode, 0, r.stderr)
        script, verb, copy, user, fp = self.mark.read_text().split()
        installer = hashlib.sha256((self.tmp / "stage-work" / "files" / "balistid-install").read_bytes()).hexdigest()
        self.assertEqual((script, verb, user, fp), (f"{copy}/{installer}", "runner", "maint", self.key.fingerprint))
        self.assertTrue(copy.startswith("/tmp/balistid-install."))
        listed = sorted(Path(f"{self.mark}.ls").read_text().split())
        self.assertEqual(listed, sorted([release.BUNDLE, release.SIG, "k", "m", installer]))
        self.assertFalse(Path(copy).exists(), "the root-only copy outlived the bootstrap")
        self.assertEqual(self.logged("runuser"), [f"runuser -u maint -- cat -- {self.stage}/{release.BUNDLE}",
                                                  f"runuser -u maint -- cat -- {self.stage}/{release.SIG}"])
        self.assertEqual(self.logged("tar"), [f"tar -xOf {copy}/{release.BUNDLE} {m}"
                                              for m in (release.SIGNERS, "MANIFEST", release.INSTALLER)])
        self.assertEqual(self.logged("logger"), [])

    def test_another_signer_runs_nothing(self):
        other = Key(self.subdir("other-key"))
        for label, stage in (("its own key listed", self.release(other, other, "own")),
                             ("the maintainer's key listed", self.release(other, self.key, "listed"))):
            with self.subTest(label):
                self.assert_ran_nothing(self.run_bootstrap(str(stage)))

    def test_another_typed_fingerprint_runs_nothing(self):
        other = Key(self.subdir("other-key"))
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), self.printed(other.signers)))

    def test_another_namespace_runs_nothing(self):
        stage = self.release(self.key, self.key, "file-ns", namespace="file")
        self.assert_ran_nothing(self.run_bootstrap(str(stage)))

    def test_unsigned_runs_nothing(self):
        (self.stage / release.SIG).unlink()
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage)))

    def test_an_altered_manifest_runs_nothing(self):
        files = self.tmp / "stage-work" / "files"
        (files / "MANIFEST").write_text((files / "MANIFEST").read_text().replace("component runner", "component runnes"))
        self.bundle.unlink()
        release.bundle(files, self.bundle)
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage)))

    # The signature binds the MANIFEST; an installer that is not the one it names never runs, signed or not.
    def test_another_installer_under_a_good_signature_runs_nothing(self):
        files = self.tmp / "stage-work" / "files"
        (files / "balistid-install").write_text(f"#!/bin/sh\ntouch {self.mark}\n")
        self.bundle.unlink()
        release.bundle(files, self.bundle)
        r = self.run_bootstrap(str(self.stage))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.mark.exists())

    def test_typed_stage_and_maintainer_are_never_parsed(self):
        marker = self.tmp / "expanded"
        for stage, user in ((f"/tmp/$(touch {marker})", "maint"), (str(self.stage), f"maint$(touch {marker})"),
                            (f"/tmp/`touch {marker}`", "maint")):
            with self.subTest(stage=stage, user=user):
                self.run_bootstrap(stage, maintainer=user)
                self.assertFalse(marker.exists())

    # Root's shell may carry a PATH, TMPDIR or exported function that answers "Good" for any signature.
    def test_root_shell_environment_does_not_reach_the_check(self):
        tmpdir = self.tmp / "agent-tmp"
        tmpdir.mkdir()
        good = f'echo "Good \\"{NAMESPACE}\\" signature for {PRINCIPAL} with ED25519 key {self.key.fingerprint}"'
        (self.tmp / "ssh-keygen").write_text(f"#!/bin/sh\n{good}\n")
        (self.tmp / "ssh-keygen").chmod(0o755)
        other = Key(self.subdir("other-key"))
        env = {"PATH": f"{self.tmp}:{os.environ['PATH']}", "TMPDIR": str(tmpdir),
               "BASH_FUNC_ssh-keygen%%": f"() {{ {good}; }}"}
        self.assert_ran_nothing(self.run_bootstrap(str(self.release(other, other, "env")), env=env))
        self.assertEqual(list(tmpdir.iterdir()), [])

    def test_a_fifo_does_not_hang_the_root_shell(self):
        self.bundle.unlink()
        os.mkfifo(self.bundle)
        r = self.run_bootstrap(str(self.stage))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.mark.exists())

    def test_an_empty_or_relative_stage_runs_nothing(self):
        for stage in ("", "relative/stage", "-"):
            with self.subTest(stage=stage):
                self.assert_ran_nothing(self.run_bootstrap(stage))
                self.assertEqual(self.logged("runuser"), [])

    def test_printed_command_has_no_placeholder_and_no_single_quote(self):
        self.assertNotIn("'", release.BOOTSTRAP)
        self.assertEqual(self.printed()[-1], self.key.fingerprint)
        self.assertNotIn("set -e", release.BOOTSTRAP)

    def test_lines_without_their_prefix_run_nothing(self):
        r = subprocess.run(self.printed(), input=f"{self.stage}\nmaint\n", env={"PATH": os.environ["PATH"]},
                           capture_output=True, text=True, timeout=60)
        self.assert_ran_nothing(r)

    # A typo in the wrapper may make sh read commands from the typed lines (-s) or treat the script as
    # a file name: the typed lines must only assign, so a program planted at the typed path never runs.
    def test_a_mistyped_wrapper_runs_nothing_typed(self):
        hit = self.tmp / "executed"
        planted = self.tmp / "planted"
        planted.write_text(f"#!/bin/sh\ntouch {hit}\n")
        planted.chmod(0o755)
        argv = self.printed()
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
        self.assert_ran_nothing(self.run_bootstrap(str(self.stage), maintainer="root"))
        self.assertEqual(self.logged("runuser"), [])

    # Root types this by hand: no dropped character anywhere, and none of the typos that turned a test into a
    # command, a redirect or a background job in the gate, may run an installer the typed key did not sign.
    def test_no_dropped_or_mistyped_character_runs_another_installer(self):
        other = Key(self.subdir("other-key"))
        hit = self.tmp / "executed"
        evil = self.release(other, other, "evil", installer=f"#!/bin/sh\ntouch {hit}\n")
        text = release.BOOTSTRAP
        variants = [(f"drop {i}: {text[max(0, i - 12):i + 12]!r}", text[:i] + text[i + 1:]) for i in range(len(text))]
        gate = range(text.index("v=$("), text.index("*) logger"))
        for c in "!:>&$*":
            variants += [(f"{c!r} at {i}", text[:i] + c + text[i + 1:]) for i in gate]
            variants += [(f"{c!r} before {i}", text[:i] + c + text[i:]) for i in gate]
        # The evil release is live: typed with its own key's fingerprint, the unbroken command runs it.
        own = self.printed(other.signers)
        subprocess.run(own, input=f"dir={evil}\nuser=maint\n", env={"PATH": os.environ["PATH"]}, capture_output=True,
                       text=True, timeout=60)
        self.assertTrue(hit.exists())
        hit.unlink()
        argv = self.printed()
        script = argv.index("-c") + 1

        def run(variant: str) -> None:
            subprocess.run([*argv[:script], variant, *argv[script + 1:]], input=f"dir={evil}\nuser=maint\n",
                           env={"PATH": os.environ["PATH"]}, cwd=self.tmp, capture_output=True, text=True, timeout=60)

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(run, [v for _, v in variants]))
        if hit.exists() or self.mark.exists():
            for label, variant in variants:  # name the first variant that ran it
                hit.unlink(missing_ok=True)
                self.mark.unlink(missing_ok=True)
                run(variant)
                self.assertFalse(hit.exists() or self.mark.exists(), label)
            self.fail("an installer ran, but no variant alone runs it again")


if __name__ == "__main__":
    unittest.main()
