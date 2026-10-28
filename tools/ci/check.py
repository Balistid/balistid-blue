#!/usr/bin/env python3
"""Local mirror of the Go CI jobs on the packages a change touches. Early feedback only; CI decides.

`check.py fast` diffs the work tree against its merge base with origin/main and selects the Go
packages whose files changed, plus every package that imports them (transitively, or from its tests).
On those it runs gofmt -l, go vet, golangci-lint run --new-from-rev and go test. The environment is the
one of the go-static and go-test jobs in .github/workflows/ci.yml (job env, and the step env of
go-test), plus GOENV=off so no go.env file changes it and CI=true as on GitHub (unset, with a note, where unix
sockets are denied, so the socket tests skip in a sandbox); every other GO*/CGO_*
variable is dropped. gofmt also gets every changed .go file, whether or not go list sees its package.
Versions are compared with the pins in ci.yml: golangci-lint must match (FAIL); go is compared without
a distribution suffix such as -X:nodwarf5, and a difference is a WARN. go test runs under RLIMIT_AS
and a timeout, with -short (a test that skips under it runs only in CI) and never fuzzes (seed
corpora only). The last line is the verdict and names the checks
that only CI runs. Not called from githooks: it builds and runs project code, which a hook must not.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import os
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
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
# because tests read deploy/, range/, acceptance/ and tools/ci/ files.
NO_GO = ("*.md", "githooks/*", ".github/*", "LICENSE", ".gitignore", ".editorconfig",
         ".gitattributes", ".gitleaks.toml", "zizmor.yml")
# What status.py reads; a change to one runs its test here, the one selftest module that needs no
# tool missing from a sandbox. The rest of selftest stays CI-only.
STATUS_INPUTS = ("STATUS.md", "adr/*", "acceptance/*", "tools/ci/status.py", "tools/ci/tests/test_status.py")
# (label, text in ci.yml that shows CI runs it); check.py runs none of these. Covers every job.
CI_ONLY = (
    ("toolchain", "go_gate.py toolchain"),
    ("build", "go build ./..."),
    ("race", "test -race"),
    ("tidy", "go mod tidy"),
    ("verify", "go mod verify"),
    ("owned", "go_gate.py owned"),
    ("cgo", "CgoFiles"),
    ("vuln", "govulncheck"),
    ("lint-all", "golangci-lint run ./..."),
    ("repro", "go_gate.py same"),
    ("selftest", "unittest discover"),
    ("docs-budget", "docs_budget.py"),
    ("pin-check", "--config zizmor.yml"),
    ("commit-lint", "commit_lint.py"),
    ("secrets", 'gitleaks" git'),
    ("workflow-lint", 'actionlint" -color'),
)
AS_LIMIT = 4 << 30
# Seconds to read what is left after a timeout; a descendant outside the group may hold the pipe.
DRAIN_SECONDS = 5
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


def ci_env(base: dict[str, str], job_env: dict[str, str], sockets: bool = True) -> dict[str, str]:
    env = {k: v for k, v in base.items()
           if not k.startswith(("GO", "CGO_")) or k in KEPT_GO_VARS}
    env.update(job_env)
    env["GOENV"] = "off"
    # GitHub sets CI=true in every step; tests turn some local skips into failures on it. Where
    # unix sockets are denied (an agent sandbox) CI stays unset, so the socket tests skip here.
    if sockets:
        env["CI"] = "true"
    else:
        env.pop("CI", None)
    return env


def unix_sockets_allowed() -> bool:
    """Whether this process may bind an AF_UNIX socket, which the collector tests need."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.bind(os.path.join(tmp, "probe.sock"))
        except OSError:
            return False
    return True


def go_version_warning(goversion: str, pin: str) -> str | None:
    m = re.fullmatch(r"(go\d+\.\d+(?:\.\d+)?)(?:-X:\S+)?", goversion)
    if m and m[1] == f"go{pin}":
        return None
    return (f"go is {goversion!r}, CI pins go{pin}: results can differ; install go{pin} from "
            f"go.dev/dl and check it against GO_SHA256 in {CI_YML}")


def golangci_problem(version_output: str, pin: str) -> str | None:
    m = re.search(r"has version (\S+)", version_output)
    if m and re.fullmatch(r"v?(\d+\.\d+\.\d+)", m[1]) and m[1].lstrip("v") == pin:
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
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, encoding="utf-8", errors="replace",
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=limit if limit_as else None)
    except (OSError, subprocess.SubprocessError) as err:
        return None, f"cannot start {cmd[0]}: {err}"
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            out, _ = proc.communicate(timeout=DRAIN_SECONDS)
        except subprocess.TimeoutExpired as err:
            partial = err.output or b""
            out = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
            proc.stdout.close()
            proc.wait()
        return None, f"{out}\ntimed out after {timeout}s"
    return proc.returncode, out


def git(repo: Path, *args: str) -> str:
    """Git output as str; surrogateescape keeps any path byte, so a path still names its file."""
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          encoding="utf-8", errors="surrogateescape").stdout


def changed_paths(repo: Path, base: str) -> list[str]:
    tracked = git(repo, "diff", "--name-only", "--no-renames", "-z", base).split("\0")
    untracked = git(repo, "ls-files", "-z", "--others", "--exclude-standard").split("\0")
    return sorted({p for p in tracked + untracked if p})


def absolute(path: str | None) -> str | None:
    """One absolute path, so the file hashed is the file run whatever the cwd of either."""
    return str(Path(path).resolve()) if path else None


def find_golangci(explicit: str | None, env: dict[str, str], gopath: str) -> str | None:
    if explicit:
        return absolute(explicit)
    on_path = shutil.which("golangci-lint", path=env.get("PATH"))
    if on_path or not gopath:
        return absolute(on_path)
    return absolute(shutil.which("golangci-lint", path=str(Path(gopath) / "bin")))


def report(state: dict, reason: str | None = None) -> int:
    for p in state["problems"]:
        print(f"FAIL {p}")
    failed = bool(state["problems"] or reason)
    print(f"CHECK fast {'FAIL' if failed else 'PASS'} head={state['head']} dirty={state['dirty']} "
          f"{time.monotonic() - state['start']:.0f}s{f' reason={reason}' if reason else ''}; "
          f"CI also: {', '.join(state['labels']) or 'nothing'}", flush=True)
    return 1 if failed else 0


def checks(args: argparse.Namespace, state: dict) -> None:
    problems: list[str] = state["problems"]
    repo = Path(git(args.repo, "rev-parse", "--show-toplevel").strip()).resolve()
    state["head"] = git(repo, "rev-parse", "HEAD").strip()[:12]
    state["dirty"] = str(sum(1 for r in git(repo, "status", "--porcelain=v1", "-z", "-uall",
                                            "--no-renames").split("\0") if r))
    try:
        ci = read_ci((repo / CI_YML).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        problems.append(f"ci.yml: {err}")
        return
    state["labels"] = [*ci["ci_only"], "long-tests"]
    sockets = unix_sockets_allowed()
    if not sockets:
        print("sandbox: unix sockets denied, socket tests run only in CI")
        state["labels"] = [*state["labels"], "unix-socket-tests"]
    static_env = ci_env(os.environ, ci["jobs"][STATIC_JOB][0], sockets)
    test_env = ci_env(os.environ, {**ci["jobs"][TEST_JOB][0], **ci["jobs"][TEST_JOB][1]}, sockets)
    dropped = sorted(k for k in os.environ
                     if k.startswith(("GO", "CGO_")) and k not in KEPT_GO_VARS and k not in static_env)
    shown = ("GO", "CGO_", "BALISTID_", "CI")
    print("env (static):", " ".join(f"{k}={v}" for k, v in sorted(static_env.items()) if k.startswith(shown)))
    print("env (test):  ", " ".join(f"{k}={v}" for k, v in sorted(test_env.items()) if k.startswith(shown)))
    if dropped:
        print("env dropped: ", " ".join(dropped))

    pins = ci["pins"]
    go = absolute(shutil.which("go", path=static_env.get("PATH")))
    if not go:
        problems.append(f"go not found on PATH: install go{pins['GO_VERSION']}")
        return
    rc, goversion = run([go, "env", "GOVERSION"], repo, static_env, 60)
    if rc != 0:
        problems.append(f"{go} env GOVERSION (exit {rc}): {goversion.strip()}")
        return
    goversion = goversion.strip()
    warning = go_version_warning(goversion, pins["GO_VERSION"])
    print(f"WARN {warning}" if warning else
          f"go: {go} {goversion} (pin go{pins['GO_VERSION']}; a distribution suffix is ignored)")
    rc, gopath = run([go, "env", "GOPATH"], repo, static_env, 60)
    if rc != 0:
        problems.append(f"{go} env GOPATH (exit {rc}): {gopath.strip()}")
        gopath = ""
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
        rc, out = run([golangci, "version"], repo, static_env, 60)
        lint_problem = (golangci_problem(out, pins["GOLANGCI_VERSION"]) if rc == 0
                        else f"{golangci} version (exit {rc}): {out.strip()[:200]}")
        problems += [lint_problem] if lint_problem else []
        lint_ok = lint_problem is None

    try:
        base = git(repo, "merge-base", args.base, "HEAD").strip()
    except subprocess.CalledProcessError:
        problems.append(f"no merge base with {args.base}: run git fetch origin")
        return
    changed = changed_paths(repo, base)
    if any(fnmatch.fnmatchcase(path, pattern) for path in changed for pattern in STATUS_INPUTS):
        step(problems, "status selftest", *run([sys.executable, "-m", "unittest", "discover", "-s", "tools/ci/tests",
                                                "-p", "test_status.py"], repo, static_env, args.timeout))
    rc, listing = run([go, "list", "-e", "-json=ImportPath,Dir,Imports,TestImports,XTestImports",
                       "./..."], repo, static_env, args.timeout)
    packages: list[dict] = []
    if rc != 0:
        problems.append(f"go list: {listing.strip()}")
    else:
        try:
            packages = go_gate.go_list_packages(listing)
            for p in packages:
                p["Dir"] = Path(p["Dir"]).resolve().relative_to(repo).as_posix()
        except (KeyError, TypeError, ValueError) as err:
            problems.append(f"go list: unusable output ({err})")
            packages = []
    if args.all:
        selected, why = {p["ImportPath"] for p in packages}, "--all"
    else:
        selected, why = select_packages(changed, packages)
        if len(selected) < len(packages):
            state["labels"] = ["all-packages", *state["labels"]]
    dirs = sorted(p["Dir"] for p in packages if p["ImportPath"] in selected)
    print(f"base: {args.base} merge-base {base[:12]}; packages: {len(dirs)} of {len(packages)} ({why})")

    # Changed files count even where go list sees no package (a build constraint excludes them all).
    go_files = {f for f in changed if f.endswith(".go") and (repo / f).is_file()}
    go_files |= {str(f.relative_to(repo)) for d in dirs for f in (repo / d).glob("*.go")}
    if args.all:
        go_files |= {f for f in git(repo, "ls-files", "-z", "--", "*.go").split("\0")
                     if f and (repo / f).is_file()}
    if go_files:
        gofmt(problems, go, sorted(go_files), repo, static_env, args.timeout)
    if not dirs:
        return
    imports = sorted(selected)
    step(problems, "go vet", *run([go, "vet", *imports], repo, static_env, args.timeout))
    if lint_ok:
        lint_args = [f"./{d}" if d != "." else "." for d in dirs]
        step(problems, "golangci-lint", *run([golangci, "run", f"--new-from-rev={base}", *lint_args],
                                             repo, static_env, args.timeout))
    step(problems, "go test", *run(
        [go, "test", "-short", f"-timeout={args.timeout}s", f"-p={TEST_PROCS}", f"-parallel={TEST_PARALLEL}",
         *imports], repo, test_env, args.timeout + 60, limit_as=AS_LIMIT))


def gofmt(problems: list[str], go: str, files: list[str], repo: Path, env: dict[str, str],
          timeout: int) -> None:
    """gofmt of the same toolchain as go, as in CI, not whichever comes first on PATH."""
    rc, goroot = run([go, "env", "GOROOT"], repo, env, 60)
    if rc != 0 or not goroot.strip():
        problems.append(f"{go} env GOROOT (exit {rc}): {goroot.strip()}")
        return
    rc, out = run([str(Path(goroot.strip()) / "bin" / "gofmt"), "-l", *files], repo, env, timeout)
    step(problems, "gofmt -l", rc, out, unformatted=bool(out.strip()))


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
    args = parser.parse_args(argv)
    state = {"start": time.monotonic(), "head": "unknown", "dirty": "unknown", "labels": [],
             "problems": []}
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")
    # The one error boundary: whatever breaks, the last line is still the verdict, and it fails.
    try:
        checks(args, state)
    except Exception as err:
        detail = str(getattr(err, "stderr", None) or "").strip()
        state["problems"].append(f"{type(err).__name__}: {err}{': ' + detail if detail else ''}")
        return report(state, type(err).__name__)
    return report(state)


if __name__ == "__main__":
    sys.exit(main())
