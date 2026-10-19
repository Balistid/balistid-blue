"""Tests for tools/ci/check.py. The Go tools are stubs written at runtime, so the tests need no Go
toolchain and never skip: a stub fails on a marker in the code it is given and logs its argv, the
environment and its RLIMIT_AS, which is what check.py is responsible for."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
CHECK = ROOT / "tools" / "ci" / "check.py"
CI_TEXT = (ROOT / check.CI_YML).read_text(encoding="utf-8")
PINS = check.read_ci(CI_TEXT)["pins"]
MODULE = "example.com/m"
LAST_LINE = re.compile(r"^CHECK fast (PASS|FAIL) head=([0-9a-f]{12}|unknown) dirty=(\d+|unknown) \d+s; CI also: \S.*$")
GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}

# One script serves as go, gofmt and golangci-lint, chosen by its file name.
STUB = r'''
import json, os, re, resource, sys, time
from pathlib import Path
cfg = json.loads((Path(__file__).parent / "stub.json").read_text())
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(cfg["log"], "a") as log:
    env = {k: v for k, v in os.environ.items() if k.startswith(("GO", "CGO_", "BALISTID_")) or k == "CI"}
    log.write(json.dumps({"tool": name, "self": sys.argv[0], "args": args, "env": env,
                          "as": resource.getrlimit(resource.RLIMIT_AS)[0]}) + "\n")
module = cfg["module"]

def pkg_dirs():
    out = []
    for d, subdirs, files in os.walk("."):
        subdirs[:] = sorted(s for s in subdirs if s not in ("testdata", ".git"))
        built = [f for f in files if f.endswith(".go") and "//go:build ignore" not in Path(d, f).read_text()]
        if built:
            out.append(os.path.normpath(d))
    return sorted(out)

def imports_of(d, test):
    found = set()
    for f in sorted(Path(d).glob("*.go")):
        if f.name.endswith("_test.go") == test:
            found |= set(re.findall(r'"(' + re.escape(module) + r'(?:/[a-z0-9]+)*)"', f.read_text()))
    return sorted(found)

def has(marker, targets):
    for t in targets:
        d = t[len(module) + 1:] if t.startswith(module + "/") else t.lstrip("./") or "."
        for f in Path(d).glob("*.go"):
            if marker in f.read_text():
                return True
    return False

if name == "gofmt":
    print("\n".join(f for f in args[1:] if "FMT_DEFECT" in Path(f).read_text()))
elif name == "golangci-lint":
    if args == ["version"]:
        print(f"golangci-lint has version {cfg['lint_version']} built with go1.27.2 from (unknown)")
        sys.exit(cfg["lint_rc"])
    else:
        sys.exit(1 if has("LINT_DEFECT", [a for a in args if not a.startswith("-")]) else 0)
elif args[:2] == ["env", "GOVERSION"]:
    print(cfg["goversion"])
elif args[:2] == ["env", "GOPATH"]:
    print(cfg["gopath"])
    sys.exit(cfg["gopath_rc"])
elif args[:2] == ["env", "GOROOT"]:
    print(cfg["goroot"])
elif args[0] == "list":
    if cfg.get("list_rc"):
        sys.exit("stub: go list failed")
    for d in pkg_dirs():
        path = module if d == "." else f"{module}/{d}"
        print(json.dumps({"ImportPath": path, "Dir": os.path.abspath(d),
                          "Imports": imports_of(d, False), "TestImports": imports_of(d, True)}))
elif args[0] == "vet":
    sys.exit(1 if has("VET_DEFECT", args[1:]) else 0)
elif args[0] == "test":
    pkgs = [a for a in args[1:] if not a.startswith("-")]
    if has("TEST_HANG", pkgs):
        time.sleep(60)
    sys.exit(1 if has("TEST_DEFECT", pkgs) else 0)
else:
    sys.exit(f"stub: unexpected {args}")
'''

SOURCES = {
    "go.mod": f"module {MODULE}\n\ngo 1.27\n",
    "README.md": "readme\n",
    "deploy/x.conf": "x\n",
    "a/a.go": "package a\n",
    "a/testdata/case.json": "{}\n",
    "b/b.go": f'package b\n\nimport _ "{MODULE}/a"\n',
    "c/c.go": "package c\n",
    "d/d.go": "package d\n",
    "d/d_test.go": f'package d\n\nimport _ "{MODULE}/a"\n',
    "e/e.go": f'package e\n\nimport _ "{MODULE}/b"\n',
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=GIT_ENV).stdout


class Sandbox:
    """A Go module on a main branch that origin/main points at, and the stub toolchain."""

    def __init__(self, tmp: str, lint_version: str = PINS["GOLANGCI_VERSION"],
                 goversion: str = f"go{PINS['GO_VERSION']}", lint_on_path: bool = True,
                 lint_rc: int = 0, gopath_rc: int = 0):
        base = Path(tmp)
        self.repo, self.bin, self.log = base / "repo", base / "bin", base / "log.jsonl"
        goroot, gopath = base / "goroot", base / "gopath"
        for d in (self.repo, self.bin, goroot / "bin", gopath / "bin"):
            d.mkdir(parents=True)
        script = f"#!{sys.executable}\n{STUB}"
        tools = [self.bin / "go", goroot / "bin" / "gofmt"]
        tools.append((self.bin if lint_on_path else base) / "golangci-lint")
        for tool in tools:
            tool.write_text(script)
            tool.chmod(0o755)
            (tool.parent / "stub.json").write_text(json.dumps({
                "log": str(self.log), "module": MODULE, "lint_version": lint_version,
                "goversion": goversion, "goroot": str(goroot), "gopath": str(gopath),
                "lint_rc": lint_rc, "gopath_rc": gopath_rc}))
        git(self.repo, "init", "-q", "-b", "main")
        (self.repo / ".github" / "workflows").mkdir(parents=True)
        (self.repo / check.CI_YML).write_text(CI_TEXT)
        for path, text in SOURCES.items():
            self.write(path, text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "--no-verify", "-m", "base")
        git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.repo, "switch", "-q", "-c", "work")

    def write(self, path: str, text: str) -> None:
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(text)

    def run(self, *extra: str, cwd: Path | None = None, repo: Path | None = None) -> tuple[int, list[str]]:
        env = {**GIT_ENV, "PATH": f"{self.bin}:{GIT_ENV['PATH']}", "GOEXPERIMENT": "arenas",
               "GOFLAGS": "-mod=mod", "CGO_ENABLED": "1", "CI": "false"}
        proc = subprocess.run([sys.executable, str(CHECK), "fast", "--repo", str(repo or self.repo), *extra],
                              capture_output=True, text=True, env=env, timeout=120, cwd=cwd)
        lines = proc.stdout.strip().splitlines()
        self.assert_last_line(lines, proc)
        return proc.returncode, lines

    @staticmethod
    def assert_last_line(lines: list[str], proc: subprocess.CompletedProcess) -> None:
        if not lines or not LAST_LINE.match(lines[-1]):
            raise AssertionError(f"bad last line\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")

    def calls(self, tool: str, first_arg: str | None = None) -> list[dict]:
        if not self.log.exists():
            return []
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [r for r in rows if r["tool"] == tool and (first_arg is None or r["args"][:1] == [first_arg])]

    def tested(self) -> set[str]:
        calls = self.calls("go", "test")
        return {a for c in calls for a in c["args"][1:] if not a.startswith("-")}


def pkgs(*names: str) -> set[str]:
    return {f"{MODULE}/{n}" for n in names}


class EndToEndTest(unittest.TestCase):
    def test_clean_main_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 0, lines)
            self.assertIn("CHECK fast PASS", lines[-1])
            self.assertIn("dirty=0", lines[-1])
            self.assertEqual(box.calls("go", "test"), [])

    def test_all_runs_every_step_on_every_package_and_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            rc, lines = box.run("--all")
            self.assertEqual(rc, 0, lines)
            self.assertEqual(box.tested(), pkgs("a", "b", "c", "d", "e"))
            for tool, arg in (("gofmt", None), ("go", "vet"), ("golangci-lint", "run")):
                self.assertTrue(box.calls(tool, arg), tool)
            self.assertNotIn("all-packages", lines[-1])

    def test_each_defect_fails_its_step(self):
        for marker, step in (("FMT_DEFECT", "gofmt -l"), ("VET_DEFECT", "go vet"),
                             ("LINT_DEFECT", "golangci-lint"), ("TEST_DEFECT", "go test")):
            with self.subTest(marker), tempfile.TemporaryDirectory() as tmp:
                box = Sandbox(tmp)
                box.write("c/c.go", f"package c\n\n// {marker}\n")
                rc, lines = box.run()
                self.assertEqual(rc, 1, lines)
                self.assertIn("CHECK fast FAIL", lines[-1])
                self.assertIn(f"FAIL {step}", lines)
                self.assertIn("dirty=1", lines[-1])

    def test_committed_defect_fails_on_a_clean_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("a/a.go", "package a\n\n// TEST_DEFECT\n")
            git(box.repo, "commit", "-q", "-am", "defect")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertIn("dirty=0", lines[-1])

    def test_untracked_file_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("c/new.go", "package c\n\n// VET_DEFECT\n")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertIn("FAIL go vet", lines)

    def test_selects_changed_package_and_its_importers_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("a/a.go", "package a\n\nconst X = 1\n")
            rc, lines = box.run()
            self.assertEqual(rc, 0, lines)
            # b imports a, e imports b, d's test imports a; c does not depend on a.
            self.assertEqual(box.tested(), pkgs("a", "b", "d", "e"))
            self.assertIn("CI also: all-packages", lines[-1])
            lint = box.calls("golangci-lint", "run")[0]["args"]
            base = git(box.repo, "rev-parse", "origin/main").strip()
            self.assertIn(f"--new-from-rev={base}", lint)
            self.assertEqual(sorted(a for a in lint if a.startswith("./")), ["./a", "./b", "./d", "./e"])

    def test_testdata_change_selects_its_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("a/testdata/case.json", "[]\n")
            box.run()
            self.assertEqual(box.tested(), pkgs("a", "b", "d", "e"))

    def test_docs_only_change_selects_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("README.md", "changed\n")
            rc, lines = box.run()
            self.assertEqual(rc, 0, lines)
            self.assertEqual(box.calls("go", "test"), [])
            self.assertEqual(box.calls("gofmt"), [])

    def test_unknown_path_or_module_file_selects_everything(self):
        for path in ("deploy/x.conf", "go.mod", ".golangci.yml", "range/new.conf", "tools/ci/seccomp_exec.py"):
            with self.subTest(path), tempfile.TemporaryDirectory() as tmp:
                box = Sandbox(tmp)
                text = (box.repo / path).read_text() if (box.repo / path).exists() else ""
                box.write(path, text + "\n")
                box.run()
                self.assertEqual(box.tested(), pkgs("a", "b", "c", "d", "e"))

    def test_environment_comes_from_ci_yml(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            rc, lines = box.run("--all")
            self.assertEqual(rc, 0, lines)
            test_call = box.calls("go", "test")[0]
            vet_call = box.calls("go", "vet")[0]
            for call in (test_call, vet_call):
                self.assertEqual(call["env"]["CI"], "true")
                self.assertEqual(call["env"]["GOFLAGS"], "-mod=readonly")
                self.assertEqual(call["env"]["GOWORK"], "off")
                self.assertEqual(call["env"]["GOTOOLCHAIN"], "local")
                self.assertEqual(call["env"]["CGO_ENABLED"], "0")
                self.assertEqual(call["env"]["GOENV"], "off")
                self.assertNotIn("GOEXPERIMENT", call["env"])
            self.assertEqual(test_call["env"].get("BALISTID_REQUIRE_SECCOMP_TEST"), "1")
            self.assertNotIn("BALISTID_REQUIRE_SECCOMP_TEST", vet_call["env"])
            self.assertIn("env dropped:  GOEXPERIMENT", lines)

    def test_go_test_runs_under_the_memory_limit_and_without_fuzzing(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.run("--all")
            call = box.calls("go", "test")[0]
            self.assertEqual(call["as"], check.AS_LIMIT)
            self.assertIn("-parallel=2", call["args"])
            self.assertTrue(any(a.startswith("-timeout=") for a in call["args"]))
            self.assertFalse(any(a.startswith("-fuzz") for a in call["args"]))
            self.assertNotEqual(box.calls("go", "vet")[0]["as"], check.AS_LIMIT)

    def test_golangci_pin_mismatch_fails_with_instructions(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp, lint_version="2.13.0")
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            problem = next(line for line in lines if line.startswith("FAIL golangci-lint 2.13.0"))
            self.assertIn(f"install v{PINS['GOLANGCI_VERSION']}", problem)
            self.assertEqual(box.calls("golangci-lint", "run"), [])

    def test_missing_golangci_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp, lint_on_path=False)
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertTrue(any("golangci-lint not found" in line for line in lines), lines)

    def test_golangci_path_and_sha256_are_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            _, lines = box.run()
            line = next(line for line in lines if line.startswith("golangci-lint: "))
            self.assertIn(str(box.bin / "golangci-lint"), line)
            self.assertRegex(line, r"sha256=[0-9a-f]{64}")

    def test_go_version_difference_is_a_warning_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp, goversion="go1.26.1")
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 0, lines)
            self.assertTrue(any(line.startswith("WARN go is 'go1.26.1'") for line in lines), lines)

    def test_missing_origin_main_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            git(box.repo, "update-ref", "-d", "refs/remotes/origin/main")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertTrue(any("git fetch origin" in line for line in lines), lines)

    def test_failed_version_query_fails_even_with_the_pinned_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp, lint_rc=23)
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertTrue(any("version (exit 23)" in line for line in lines), lines)
            self.assertEqual(box.calls("golangci-lint", "run"), [])

    def test_prerelease_golangci_is_not_the_release(self):
        for suffix in ("-rc.1", "-dev", "+dirty"):
            with self.subTest(suffix), tempfile.TemporaryDirectory() as tmp:
                box = Sandbox(tmp, lint_version=PINS["GOLANGCI_VERSION"] + suffix)
                git(box.repo, "switch", "-q", "main")
                rc, lines = box.run()
                self.assertEqual(rc, 1, lines)

    def test_failed_gopath_query_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp, gopath_rc=1)
            git(box.repo, "switch", "-q", "main")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertTrue(any("env GOPATH (exit 1)" in line for line in lines), lines)

    def test_changed_file_of_a_build_excluded_package_is_formatted(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            box.write("x/ex.go", "//go:build ignore\n\npackage x\n\n// FMT_DEFECT\n")
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertIn("FAIL gofmt -l", lines)
            self.assertIn("x/ex.go", box.calls("gofmt")[0]["args"])

    def test_changed_go_file_is_formatted_when_no_package_is_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            box = Sandbox(tmp)
            # go list fails here, so no package is selected; the file is still formatted.
            box.write("c/c.go", "package c\n\n// FMT_DEFECT\n")
            stub = box.bin / "stub.json"
            cfg = json.loads(stub.read_text())
            stub.write_text(json.dumps({**cfg, "list_rc": 1}))
            rc, lines = box.run()
            self.assertEqual(rc, 1, lines)
            self.assertIn("FAIL gofmt -l", lines)
            self.assertEqual(box.calls("go", "test"), [])

    def test_relative_golangci_path_is_one_file_for_hash_and_run(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as caller:
            box = Sandbox(tmp)
            real = Path(caller) / "lint" / "golangci-lint"
            real.parent.mkdir()
            real.write_text((box.bin / "go").read_text())
            real.chmod(0o755)
            (real.parent / "stub.json").write_text((box.bin / "stub.json").read_text())
            # A decoy at the same relative path under the repository must never run.
            box.write("lint/golangci-lint", "#!/bin/sh\nexit 0\n")
            (box.repo / "lint" / "golangci-lint").chmod(0o755)
            (box.repo / "lint" / "stub.json").write_text((box.bin / "stub.json").read_text())
            rc, lines = box.run("--golangci-lint", "lint/golangci-lint", cwd=Path(caller))
            self.assertEqual(rc, 0, lines)
            shown = next(line for line in lines if line.startswith("golangci-lint: "))
            self.assertIn(f"golangci-lint: {real.resolve()} sha256=", shown)
            ran = {c["self"] for c in box.calls("golangci-lint")}
            self.assertEqual(ran, {str(real.resolve())})

    def test_git_failure_still_prints_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as plain:
            box = Sandbox(tmp)
            rc, lines = box.run(repo=Path(plain))
            self.assertEqual(rc, 1, lines)
            self.assertRegex(lines[-1], r"^CHECK fast FAIL head=unknown dirty=unknown ")
            self.assertTrue(any(line.startswith("FAIL ") for line in lines[:-1]), lines)


class ReadCiTest(unittest.TestCase):
    def test_reads_pins_and_env_of_the_real_workflow(self):
        ci = check.read_ci(CI_TEXT)
        self.assertRegex(ci["pins"]["GO_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(ci["pins"]["GOLANGCI_VERSION"], r"^\d+\.\d+\.\d+$")
        for job in (check.STATIC_JOB, check.TEST_JOB):
            env, _ = ci["jobs"][job]
            self.assertEqual(env["GOFLAGS"], "-mod=readonly")
            self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(ci["jobs"][check.TEST_JOB][1], {"BALISTID_REQUIRE_SECCOMP_TEST": "1"})
        self.assertEqual(ci["ci_only"], [label for label, _ in check.CI_ONLY])

    def test_every_job_is_known(self):
        # A new job may run a check check.py does not; this test makes CI_ONLY be reviewed then.
        jobs = re.findall(r"^  ([a-z0-9-]+):$", CI_TEXT.split("\njobs:\n", 1)[1], re.MULTILINE)
        self.assertEqual(jobs, ["go-static", "go-test", "go-race", "go-release", "selftest",
                                "docs-budget", "pin-check", "commit-lint", "secrets", "workflow-lint"])
        labels = check.read_ci(CI_TEXT)["ci_only"]
        for label in ("toolchain", "build", "selftest", "docs-budget", "pin-check", "commit-lint",
                      "secrets", "workflow-lint"):
            self.assertIn(label, labels)

    def test_missing_value_fails_closed(self):
        for needle in ('  GOLANGCI_VERSION: "', "      GOTOOLCHAIN: local"):
            with self.subTest(needle):
                broken = CI_TEXT.replace(needle, "  # " + needle.strip(), 1)
                self.assertNotEqual(broken, CI_TEXT)
                with self.assertRaises(ValueError):
                    check.read_ci(broken)

    def test_ci_only_lists_what_the_workflow_runs(self):
        text = CI_TEXT.replace("go test -race", "go test")
        self.assertNotIn("race", check.read_ci(text)["ci_only"])

    def test_scalar(self):
        self.assertEqual(check._scalar(' "1.2.3" # c'), "1.2.3")
        self.assertEqual(check._scalar(" '0'"), "0")
        self.assertEqual(check._scalar(" -mod=readonly # c"), "-mod=readonly")


class VersionTest(unittest.TestCase):
    def test_go_suffix_is_ignored_and_difference_warns(self):
        self.assertIsNone(check.go_version_warning("go1.27.2", "1.27.2"))
        self.assertIsNone(check.go_version_warning("go1.27.2-X:nodwarf5", "1.27.2"))
        self.assertIsNotNone(check.go_version_warning("go1.27.1-X:nodwarf5", "1.27.2"))
        self.assertIsNotNone(check.go_version_warning("devel go1.28-abc", "1.27.2"))

    def test_golangci_must_match_the_pin(self):
        out = "golangci-lint has version 2.14.0 built with go1.27.1-X:nodwarf5 from (unknown)"
        self.assertIsNone(check.golangci_problem(out, "2.14.0"))
        self.assertIsNone(check.golangci_problem(out.replace("2.14.0", "v2.14.0", 1), "2.14.0"))
        self.assertIn("2.14.1", check.golangci_problem(out.replace("2.14.0", "2.14.1", 1), "2.14.0"))
        self.assertIn("unknown version", check.golangci_problem("garbage", "2.14.0"))
        self.assertIsNotNone(check.golangci_problem(out.replace("2.14.0", "2.14.01", 1), "2.14.0"))
        for suffix in ("-rc.1", "-dev", "+dirty", "-0.20261019"):
            self.assertIsNotNone(check.golangci_problem(out.replace("2.14.0", "2.14.0" + suffix, 1), "2.14.0"))


class SelectTest(unittest.TestCase):
    PKGS = [
        {"ImportPath": "m", "Dir": "."},
        {"ImportPath": "m/a", "Dir": "a"},
        {"ImportPath": "m/b", "Dir": "b", "Imports": ["m/a"]},
        {"ImportPath": "m/c", "Dir": "c", "XTestImports": ["m/c", "m/b"]},
        {"ImportPath": "m/x/y", "Dir": "x/y"},
    ]

    def test_transitive_and_test_importers(self):
        selected, _ = check.select_packages(["a/a.go"], self.PKGS)
        self.assertEqual(selected, {"m/a", "m/b", "m/c"})

    def test_root_package_and_nested_testdata(self):
        self.assertEqual(check.select_packages(["main.go"], self.PKGS)[0], {"m"})
        self.assertEqual(check.select_packages(["x/y/testdata/in/z.json"], self.PKGS)[0], {"m/x/y"})

    def test_go_file_outside_packages_selects_everything(self):
        selected, why = check.select_packages(["gone/old.go"], self.PKGS)
        self.assertEqual(len(selected), len(self.PKGS))
        self.assertIn("gone/old.go", why)

    def test_non_go_paths(self):
        self.assertEqual(check.select_packages(["adr/README.md", ".github/CODEOWNERS", "githooks/pre-commit"],
                                               self.PKGS)[0], set())
        # Go tests run tools/ci/seccomp_exec.py.
        self.assertEqual(len(check.select_packages(["tools/ci/seccomp_exec.py"], self.PKGS)[0]), len(self.PKGS))
        self.assertEqual(len(check.select_packages([check.CI_YML], self.PKGS)[0]), len(self.PKGS))
        self.assertEqual(len(check.select_packages(["acceptance/0.toml"], self.PKGS)[0]), len(self.PKGS))


class RunTest(unittest.TestCase):
    def test_timeout_kills_the_process_group(self):
        start = time.monotonic()
        code = "import subprocess, time; subprocess.Popen(['sleep', '60']); time.sleep(60)"
        rc, out = check.run([sys.executable, "-c", code], Path("."), dict(os.environ), timeout=1)
        self.assertIsNone(rc)
        self.assertIn("timed out after 1s", out)
        self.assertLess(time.monotonic() - start, 30)

    def test_timeout_does_not_wait_for_a_detached_descendant(self):
        start = time.monotonic()
        code = ("import subprocess, time; subprocess.Popen(['sleep', '20'], start_new_session=True); "
                "time.sleep(60)")
        rc, out = check.run([sys.executable, "-c", code], Path("."), dict(os.environ), timeout=1)
        self.assertIsNone(rc)
        self.assertIn("timed out after 1s", out)
        # The descendant sleeps 20 s; waiting for it to close the pipe would exceed this.
        self.assertLess(time.monotonic() - start, 15)

    def test_missing_binary_is_not_a_pass(self):
        rc, out = check.run(["/nonexistent/go"], Path("."), dict(os.environ), timeout=5)
        self.assertIsNone(rc)
        self.assertIn("cannot start", out)


class HooksTest(unittest.TestCase):
    def test_githooks_do_not_run_check(self):
        for hook in (ROOT / "githooks").iterdir():
            self.assertNotIn("check.py", hook.read_text(), hook.name)


if __name__ == "__main__":
    unittest.main()
