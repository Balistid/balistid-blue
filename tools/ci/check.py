#!/usr/bin/env python3
"""Local mirror of the Go CI jobs on the packages a change touches. Early feedback only; CI decides.

`check.py fast` diffs the work tree against its merge base with origin/main and selects the Go
packages whose files changed, plus every package that imports them (transitively, or from its tests).
On those it runs gofmt -l, go vet, golangci-lint run --new-from-rev and go test. The environment is the
one of the go-static and go-test jobs in .github/workflows/ci.yml (job env, and the step env of
go-test), plus GOENV=off so no go.env file changes it; every other GO*/CGO_* variable is dropped.
Versions are compared with the pins in ci.yml: golangci-lint must match (FAIL); go is compared without
a distribution suffix such as -X:nodwarf5, and a difference is a WARN. go test runs under RLIMIT_AS
and a timeout and never fuzzes (seed corpora only). The last line is the verdict and names the checks
that only CI runs. Not called from githooks: it builds and runs project code, which a hook must not.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import go_gate

CI_YML = ".github/workflows/ci.yml"
STATIC_JOB, TEST_JOB = "go-static", "go-test"
REQUIRED_JOB_ENV = ("GOFLAGS", "GOWORK", "GOTOOLCHAIN", "CGO_ENABLED")
REQUIRED_PINS = ("GO_VERSION", "GOLANGCI_VERSION")
# Caches only: they change speed, not results.
KEPT_GO_VARS = {"GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "GOLANGCI_LINT_CACHE"}
# A change to one of these can change the result of every package.
WHOLE_MODULE = {"go.mod", "go.sum", "go.work", "go.work.sum", ".golangci.yml", CI_YML}
# Paths no Go build or test reads. Any other path outside a package dir selects the whole module,
# because tests read deploy/, range/ and acceptance/ files.
NO_GO = ("*.md", "tools/ci/*", "githooks/*", ".github/*", "LICENSE", ".gitignore", ".editorconfig",
         ".gitattributes", ".gitleaks.toml", "zizmor.yml")
# (label, text in ci.yml that shows CI runs it); check.py runs none of these.
CI_ONLY = (
    ("race", "test -race"),
    ("tidy", "go mod tidy"),
    ("verify", "go mod verify"),
    ("owned", "go_gate.py owned"),
    ("cgo", "CgoFiles"),
    ("vuln", "govulncheck"),
    ("repro", "go_gate.py same"),
    ("lint-all", "golangci-lint run ./..."),
)
AS_LIMIT = 4 << 30
# Bounds memory: up to TEST_PROCS test binaries run at once, each capped by AS_LIMIT.
TEST_PROCS = 4
TEST_PARALLEL = 2


def _section(lines: list[str], header: str) -> list[str]:
    """Lines nested under the exact line `header` (indentation included), up to its next sibling."""
    if header not in lines:
        return []
    indent = len(header) - len(header.lstrip())
    out = []
    for line in lines[lines.index(header) + 1:]:
        if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip()) <= indent:
            break
        out.append(line)
    return out


def _scalar(raw: str) -> str:
    raw = raw.strip()
    m = re.fullmatch(r"""(["'])(.*?)\1\s*(?:#.*)?""", raw)
    return m[2] if m else raw.split(" #", 1)[0].strip()


def _mapping(lines: list[str], indent: int) -> dict[str, str]:
    out = {}
    for line in lines:
        if len(line) - len(line.lstrip()) == indent:
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):(.*)", line.strip())
            if m:
                out[m[1]] = _scalar(m[2])
    return out


def read_ci(text: str) -> dict:
    """Pins, job env and step env from ci.yml; ValueError when a value check.py needs is missing."""
    lines = text.split("\n")
    pins = _mapping(_section(lines, "env:"), 2)
    missing = [p for p in REQUIRED_PINS if not pins.get(p)]
    jobs = {}
    for job in (STATIC_JOB, TEST_JOB):
        body = _section(lines, f"  {job}:")
        env = _mapping(_section(body, "    env:"), 6)
        missing += [f"{job}.env.{k}" for k in REQUIRED_JOB_ENV if k not in env]
        steps = {}
        for i, line in enumerate(body):
            if line == "        env:":
                steps.update(_mapping(_section(body[i:], line), 10))
        jobs[job] = (env, steps)
    if missing:
        raise ValueError(f"{CI_YML} has no {', '.join(missing)}; update check.py with the workflow")
    return {"pins": pins, "jobs": jobs, "ci_only": [label for label, mark in CI_ONLY if mark in text]}


def ci_env(base: dict[str, str], job_env: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in base.items()
           if not k.startswith(("GO", "CGO_")) or k in KEPT_GO_VARS}
    env.update(job_env)
    env["GOENV"] = "off"
    return env


def go_version_warning(goversion: str, pin: str) -> str | None:
    m = re.fullmatch(r"(go\d+\.\d+(?:\.\d+)?)(?:-X:\S+)?", goversion)
    if m and m[1] == f"go{pin}":
        return None
    return (f"go is {goversion!r}, CI pins go{pin}: results can differ; install go{pin} from "
            f"go.dev/dl and check it against GO_SHA256 in {CI_YML}")


def golangci_problem(version_output: str, pin: str) -> str | None:
    m = re.search(r"has version v?(\d+\.\d+\.\d+)\b", version_output)
    if m and m[1] == pin:
        return None
    found = m[1] if m else f"of unknown version ({version_output.strip()[:80]!r})"
    return (f"golangci-lint {found} is not the CI pin {pin}: install v{pin} (the release tarball "
            f"pinned by GOLANGCI_SHA256 in {CI_YML}, or go install "
            f"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v{pin}) or pass --golangci-lint")


def owner_dir(path: str) -> str:
    """The package dir a file belongs to; testdata belongs to the package above it."""
    parts = path.split("/")[:-1]
    if "testdata" in parts:
        parts = parts[:parts.index("testdata")]
    return "/".join(parts) or "."


def select_packages(changed: list[str], packages: list[dict]) -> tuple[set[str], str]:
    """Import paths to check, and why. Unknown paths widen the set; they never narrow it (R6)."""
    by_dir = {p["Dir"]: p["ImportPath"] for p in packages}
    everything = set(by_dir.values())
    direct = set()
    for path in changed:
        if path in WHOLE_MODULE:
            return everything, f"{path} changed"
        if owner_dir(path) in by_dir:
            direct.add(by_dir[owner_dir(path)])
        elif not any(fnmatch.fnmatchcase(path, pattern) for pattern in NO_GO):
            return everything, f"{path} is outside the Go packages"
    importers = defaultdict(set)
    for p in packages:
        for imp in p.get("Imports") or []:
            importers[imp].add(p["ImportPath"])
    selected, todo = set(direct), list(direct)
    while todo:
        for importer in importers[todo.pop()] - selected:
            selected.add(importer)
            todo.append(importer)
    for p in packages:
        if selected & set((p.get("TestImports") or []) + (p.get("XTestImports") or [])):
            selected.add(p["ImportPath"])
    return selected, f"{len(direct)} changed, {len(selected) - len(direct)} importing them"


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: int,
        limit_as: int | None = None) -> tuple[int | None, str]:
    """Run in its own process group, killed whole on timeout. None means it did not finish."""
    def limit() -> None:
        hard = resource.getrlimit(resource.RLIMIT_AS)[1]
        cap = limit_as if hard == resource.RLIM_INFINITY else min(limit_as, hard)
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=limit if limit_as else None)
    except (OSError, subprocess.SubprocessError) as err:
        return None, f"cannot start {cmd[0]}: {err}"
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
        return None, f"{out}\ntimed out after {timeout}s"
    return proc.returncode, out


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


def changed_paths(repo: Path, base: str) -> list[str]:
    tracked = git(repo, "diff", "--name-only", "--no-renames", "-z", base).split("\0")
    untracked = git(repo, "ls-files", "-z", "--others", "--exclude-standard").split("\0")
    return sorted({p for p in tracked + untracked if p})


def find_golangci(explicit: str | None, env: dict[str, str], gopath: str) -> str | None:
    if explicit:
        return explicit
    on_path = shutil.which("golangci-lint", path=env.get("PATH"))
    if on_path or not gopath:
        return on_path
    return shutil.which("golangci-lint", path=str(Path(gopath) / "bin"))


def fast(args: argparse.Namespace) -> int:
    start = time.monotonic()
    repo = Path(git(args.repo, "rev-parse", "--show-toplevel").strip())
    head = git(repo, "rev-parse", "HEAD").strip()
    dirty = sum(1 for r in git(repo, "status", "--porcelain=v1", "-z", "-uall", "--no-renames")
                .split("\0") if r)
    problems: list[str] = []
    labels: list[str] = []

    def verdict() -> int:
        state = "FAIL" if problems else "PASS"
        for p in problems:
            print(f"FAIL {p}")
        extra = ", ".join(labels) or "nothing"
        print(f"CHECK fast {state} head={head[:12]} dirty={dirty} "
              f"{time.monotonic() - start:.0f}s; CI also: {extra}")
        return 1 if problems else 0

    try:
        ci = read_ci((repo / CI_YML).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        problems.append(f"ci.yml: {err}")
        return verdict()
    labels = ci["ci_only"]
    static_env = ci_env(os.environ, ci["jobs"][STATIC_JOB][0])
    test_env = ci_env(os.environ, {**ci["jobs"][TEST_JOB][0], **ci["jobs"][TEST_JOB][1]})
    dropped = sorted(k for k in os.environ
                     if k.startswith(("GO", "CGO_")) and k not in KEPT_GO_VARS and k not in static_env)
    print("env (static):", " ".join(f"{k}={static_env[k]}" for k in sorted(static_env)
                                    if k.startswith(("GO", "CGO_"))))
    print("env (test):  ", " ".join(f"{k}={test_env[k]}" for k in sorted(test_env)
                                    if k.startswith(("GO", "CGO_", "BALISTID_"))))
    if dropped:
        print("env dropped: ", " ".join(dropped))

    pins = ci["pins"]
    rc, goversion = run(["go", "env", "GOVERSION"], repo, static_env, 60)
    if rc != 0:
        problems.append(f"go: cannot read its version: {goversion.strip()}")
        return verdict()
    goversion = goversion.strip()
    warning = go_version_warning(goversion, pins["GO_VERSION"])
    print(f"WARN {warning}" if warning else
          f"go: {goversion} (pin go{pins['GO_VERSION']}; a distribution suffix is ignored)")
    _, gopath = run(["go", "env", "GOPATH"], repo, static_env, 60)
    golangci = find_golangci(args.golangci_lint, static_env, gopath.strip())
    lint_ok = False
    if not golangci:
        problems.append(f"golangci-lint not found on PATH or in GOPATH/bin: install "
                        f"v{pins['GOLANGCI_VERSION']} or pass --golangci-lint")
    else:
        try:
            digest = hashlib.sha256(Path(golangci).read_bytes()).hexdigest()
        except OSError as err:
            digest = f"unreadable ({err})"
        print(f"golangci-lint: {golangci} sha256={digest} (ci.yml pins the release tarball)")
        _, out = run([golangci, "version"], repo, static_env, 60)
        lint_problem = golangci_problem(out, pins["GOLANGCI_VERSION"])
        problems += [lint_problem] if lint_problem else []
        lint_ok = lint_problem is None

    try:
        base = git(repo, "merge-base", args.base, "HEAD").strip()
    except subprocess.CalledProcessError:
        problems.append(f"no merge base with {args.base}: run git fetch origin")
        return verdict()
    rc, listing = run(["go", "list", "-e", "-json=ImportPath,Dir,Imports,TestImports,XTestImports",
                       "./..."], repo, static_env, args.timeout)
    if rc != 0:
        problems.append(f"go list: {listing.strip()}")
        return verdict()
    try:
        packages = go_gate.go_list_packages(listing)
        for p in packages:
            p["Dir"] = Path(p["Dir"]).resolve().relative_to(repo.resolve()).as_posix()
    except (KeyError, TypeError, ValueError) as err:
        problems.append(f"go list: unusable output ({err})")
        return verdict()
    if args.all:
        selected, why = {p["ImportPath"] for p in packages}, "--all"
    else:
        selected, why = select_packages(changed_paths(repo, base), packages)
        if len(selected) < len(packages):
            labels = ["all-packages", *labels]
    dirs = sorted(p["Dir"] for p in packages if p["ImportPath"] in selected)
    print(f"base: {args.base} merge-base {base[:12]}; packages: {len(dirs)} of {len(packages)} ({why})")
    if not dirs:
        return verdict()
    imports = sorted(selected)
    go_files = sorted(str(f.relative_to(repo)) for d in dirs for f in (repo / d).glob("*.go"))
    # gofmt of the same toolchain as go, as in CI, not whichever comes first on PATH.
    rc, goroot = run(["go", "env", "GOROOT"], repo, static_env, 60)
    if rc != 0 or not goroot.strip():
        problems.append(f"go env GOROOT: {goroot.strip()}")
    else:
        rc, out = run([str(Path(goroot.strip()) / "bin" / "gofmt"), "-l", *go_files],
                      repo, static_env, args.timeout)
        step(problems, "gofmt -l", rc, out, unformatted=bool(out.strip()))
    step(problems, "go vet", *run(["go", "vet", *imports], repo, static_env, args.timeout))
    if lint_ok:
        lint_args = [f"./{d}" if d != "." else "." for d in dirs]
        step(problems, "golangci-lint", *run([golangci, "run", f"--new-from-rev={base}", *lint_args],
                                             repo, static_env, args.timeout))
    step(problems, "go test", *run(
        ["go", "test", f"-timeout={args.timeout}s", f"-p={TEST_PROCS}", f"-parallel={TEST_PARALLEL}",
         *imports], repo, test_env, args.timeout + 60, limit_as=AS_LIMIT))
    return verdict()


def step(problems: list[str], name: str, rc: int | None, out: str, unformatted: bool = False) -> None:
    if rc == 0 and not unformatted:
        print(f"ok   {name}")
        return
    print(f"--- {name} ---\n{out.rstrip()}")
    problems.append(name if rc is not None else f"{name} did not finish")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fast", help="touched packages against origin/main")
    f.add_argument("--repo", type=Path, default=Path("."))
    f.add_argument("--base", default="origin/main")
    f.add_argument("--all", action="store_true", help="check every package, not only touched ones")
    f.add_argument("--golangci-lint", help="path of the golangci-lint binary to use")
    f.add_argument("--timeout", type=int, default=900, help="seconds per step (default 900)")
    return fast(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
