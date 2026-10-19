#!/usr/bin/env python3
"""Checks for the Go CI job that need no Go toolchain to test (ADR 0003).

toolchain: go.mod pins `toolchain go<version>` and the running toolchain reports exactly that
           upstream version (no distribution suffix such as `X:nodwarf5`).
modsum:    a module fetched with `go mod download -json` has the pinned h1 hash.
same:      two release builds are byte-identical.
owned:     every package the range binaries, the runner and the client compile, and the paths that go into the range image,
           is in the main module and code-owned (ADR 0011): an agent change there would run on
           the host or in the evidence image, so it waits for the maintainer. A package from another
           module passes only if that module, at that version and not replaced, is in ALLOWED_MODULES.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def toolchain_problems(go_mod: str, goversion: str, expected: str) -> list[str]:
    problems = []
    lines = go_mod.splitlines()
    if lines.count(f"toolchain go{expected}") != 1 or sum(l.startswith("toolchain") for l in lines) != 1:
        problems.append(f"go.mod must pin exactly one 'toolchain go{expected}'")
    if goversion != f"go{expected}":
        problems.append(f"running toolchain is {goversion!r}, not the pinned upstream go{expected}")
    if not any(re.fullmatch(r"go \d+\.\d+(\.\d+)?", l) for l in lines):
        problems.append("go.mod has no go directive")
    return problems


def modsum_problems(download_json: str, expected_sum: str) -> list[str]:
    try:
        info = json.loads(download_json)
    except json.JSONDecodeError as err:
        return [f"go mod download output is not JSON: {err}"]
    if info.get("Error"):
        return [f"download failed: {info['Error']}"]
    if info.get("Sum") != expected_sum:
        return [f"{info.get('Path')}@{info.get('Version')} has sum {info.get('Sum')!r}, pinned {expected_sum!r}"]
    return []


def same_problems(a: bytes, b: bytes) -> list[str]:
    ha, hb = hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()
    return [] if ha == hb else [f"release builds differ: {ha} != {hb}"]


# The binaries (the range launcher and guest, the runner and the client root installs, ADR 0011) and the
# image inputs of session.go (imageFiles, range/, packaging/); change together with ci.yml.
OWNED_ROOTS = ("cmd/balistid-range", "cmd/balistid-range-guest", "cmd/balistid-runner", "cmd/balistid")
OWNED_PATHS = ("range", "deploy", "packaging")
# The store's whole compiled closure (SQLite without cgo, ADR 0003), exactly as go.mod requires it; a
# module bump moves this list in the same code-owned change. Go checks each module's h1 against go.sum.
ALLOWED_MODULES = frozenset({
    "github.com/dustin/go-humanize@v1.0.1",
    "github.com/google/uuid@v1.6.0",
    "github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec",
    "golang.org/x/sys@v0.48.0",
    "modernc.org/libc@v1.77.1",
    "modernc.org/mathutil@v1.7.1",
    "modernc.org/memory@v1.12.1",
    "modernc.org/sqlite@v1.60.1",
})
MAINTAINER = "@Jvc0n"
# Every line is an anchored plain path owned by the maintainer alone. GitHub lets a later line take
# an owner away (a glob, a child path, an empty or invalid owner, an inline comment); refusing all of
# them keeps "some line matches" equal to "GitHub requires the maintainer".
_CODEOWNERS_LINE = re.compile(r"(/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]*) +" + MAINTAINER)


def codeowners_rules(text: str) -> tuple[list[str], list[str]]:
    rules, problems = [], []
    # GitHub splits on "\n" only; splitlines() would also split on U+2028 and friends, so a line
    # GitHub reads as one comment could hide owner lines here.
    for n, line in enumerate(text.split("\n"), 1):
        if line == "" or line.startswith("#"):
            continue
        m = _CODEOWNERS_LINE.fullmatch(line)
        if not m or any(part in ("", ".", "..") for part in m[1].strip("/").split("/")):
            problems.append(f"CODEOWNERS line {n}: not '/<plain path> {MAINTAINER}': {line!r}")
            continue
        rules.append(m[1].rstrip("/"))
    return rules, problems


def is_owned(path: str, rules: list[str]) -> bool:
    return any(f"/{path}/".startswith(pattern + "/") for pattern in rules)


def go_module(go_mod: str) -> str:
    names = re.findall(r"^module ([A-Za-z0-9./_-]+)$", go_mod, re.MULTILINE)
    return names[0] if len(names) == 1 else ""


def go_list_packages(text: str) -> list[dict]:
    decoder, packages, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            return packages
        pkg, i = decoder.raw_decode(text, i)
        if not isinstance(pkg, dict):
            raise ValueError("go list output holds a value that is not an object")
        packages.append(pkg)


def allowed_module(path: str, module: dict) -> bool:
    """A package of a listed module, at its listed version and not replaced."""
    mod = module.get("Path", "")
    return (module.get("Main") is not True and "Replace" not in module and bool(mod)
            and f"{mod}@{module.get('Version')}" in ALLOWED_MODULES
            and (path == mod or path.startswith(mod + "/")))


def owned_problems(deps_json: str, codeowners: str, go_mod: str) -> list[str]:
    rules, problems = codeowners_rules(codeowners)
    module_path = go_module(go_mod)
    if not module_path:
        return problems + ["go.mod has no single module line"]
    try:
        packages = go_list_packages(deps_json)
    except ValueError as err:
        return problems + [f"go list output is not JSON: {err}"]
    seen = set()
    for pkg in packages:
        path = pkg.get("ImportPath", "")
        if pkg.get("Standard") is True:
            continue
        module = pkg.get("Module") or {}
        if allowed_module(path, module):
            continue
        main_module = module.get("Path") == module_path and module.get("Main") is True
        if not main_module or not path.startswith(module_path + "/"):
            problems.append(f"{path}: package from outside the main module")
            continue
        rel = path[len(module_path) + 1:]
        seen.add(rel)
        if not is_owned(rel, rules):
            problems.append(f"{rel}: compiled into a gated binary but has no code owner")
    problems += [f"{r}: missing from the dependency list" for r in OWNED_ROOTS if r not in seen]
    problems += [f"{p}: goes into the range image but has no code owner"
                 for p in OWNED_PATHS if not is_owned(p, rules)]
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("toolchain")
    t.add_argument("--go-mod", type=Path, required=True)
    t.add_argument("--goversion", required=True)
    t.add_argument("--expect", required=True)
    m = sub.add_parser("modsum")
    m.add_argument("--json", type=Path, required=True)
    m.add_argument("--expect", required=True)
    s = sub.add_parser("same")
    s.add_argument("a", type=Path)
    s.add_argument("b", type=Path)
    o = sub.add_parser("owned")
    o.add_argument("--deps", type=Path, required=True)
    o.add_argument("--codeowners", type=Path, required=True)
    o.add_argument("--go-mod", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.cmd == "toolchain":
        problems = toolchain_problems(args.go_mod.read_text(), args.goversion, args.expect)
    elif args.cmd == "modsum":
        problems = modsum_problems(args.json.read_text(), args.expect)
    elif args.cmd == "owned":
        problems = owned_problems(args.deps.read_text(), args.codeowners.read_text(), args.go_mod.read_text())
    else:
        problems = same_problems(args.a.read_bytes(), args.b.read_bytes())
    for p in problems:
        print(f"go-gate: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
