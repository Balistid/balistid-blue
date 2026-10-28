#!/usr/bin/env python3
"""Checks for the Go CI job that need no Go toolchain to test (ADR 0003).

toolchain: go.mod pins `toolchain go<version>` and the running toolchain reports exactly that
           upstream version (no distribution suffix such as `X:nodwarf5`).
modsum:    a module fetched with `go mod download -json` has the pinned h1 hash.
same:      two release builds are byte-identical.
owned:     every package the range binaries, the runner and the client compile, and the paths that go into the range image,
           is in the main module and code-owned (ADR 0011): an agent change there would run on
           the host or in the evidence image, so it waits for the maintainer. A package from another
           module passes only if that module, at that version and not replaced, is in ALLOWED_MODULES with
           an allowed licence whose file has the pinned SHA-256.
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
OWNED_ROOTS = ("cmd/balistid-range", "cmd/balistid-range-guest", "cmd/balistid-runner", "cmd/balistid",
               "cmd/balistid-collector", "cmd/balistid-ledger")
OWNED_PATHS = ("range", "deploy", "packaging")
# Every module a gated binary compiles, at its exact version and not replaced, with the licence its file
# states and that file's SHA-256 (R14, ENGINEERING.md 7): a bump or a relicence moves this table in the same
# code-owned change. Go checks each module's h1 against go.sum.
ALLOWED_MODULES: dict[str, tuple[str, str, str]] = {
    "github.com/cenkalti/backoff/v5@v5.0.3":
        ("LICENSE", "MIT", "5c0476add4c38b55d0ed5ac11b85e00c38f26e1caee20dfe3ab58190103d1fbc"),
    "github.com/cespare/xxhash/v2@v2.3.0":
        ("LICENSE.txt", "MIT", "f566a9f97bacdaf00d9f21dd991e81dc11201c4e016c86b470799429a1c9a79c"),
    "github.com/dustin/go-humanize@v1.0.1":
        ("LICENSE", "MIT", "a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71"),
    "github.com/go-logr/logr@v1.4.3":
        ("LICENSE", "Apache-2.0", "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1"),
    "github.com/go-logr/stdr@v1.2.2":
        ("LICENSE", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"),
    "github.com/google/uuid@v1.6.0":
        ("LICENSE", "BSD-3-Clause", "0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d"),
    "github.com/hashicorp/golang-lru/v2@v2.0.7":
        ("LICENSE", "MPL-2.0", "6c7088eb877b5d7e6e0e9d27e822ea25fcda2e83f9eba59bb5f1418a656796e0"),
    "github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec":
        ("LICENSE", "BSD-3-Clause", "dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d"),
    "github.com/transparency-dev/formats@v0.0.0-20251017110053-404c0d5b696c":
        ("LICENSE", "Apache-2.0", "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"),
    "github.com/transparency-dev/merkle@v0.0.2":
        ("LICENSE", "Apache-2.0", "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"),
    "github.com/transparency-dev/tessera@v1.0.4":
        ("LICENSE", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"),
    "go.opentelemetry.io/auto/sdk@v1.2.1":
        ("LICENSE", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"),
    "go.opentelemetry.io/otel@v1.41.0":
        ("LICENSE", "Apache-2.0 AND BSD-3-Clause", "1ae07514be1d7bb33f0698f8d91fb51b8b9fe1463157ec1c72081a49b9bc6f40"),
    "go.opentelemetry.io/otel/metric@v1.41.0":
        ("LICENSE", "Apache-2.0 AND BSD-3-Clause", "1ae07514be1d7bb33f0698f8d91fb51b8b9fe1463157ec1c72081a49b9bc6f40"),
    "go.opentelemetry.io/otel/trace@v1.41.0":
        ("LICENSE", "Apache-2.0 AND BSD-3-Clause", "1ae07514be1d7bb33f0698f8d91fb51b8b9fe1463157ec1c72081a49b9bc6f40"),
    "golang.org/x/crypto@v0.52.0":
        ("LICENSE", "BSD-3-Clause", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"),
    "golang.org/x/exp@v0.0.0-20240325151524-a685a6edb6d8":
        ("LICENSE", "BSD-3-Clause", "2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067"),
    "golang.org/x/mod@v0.41.0":
        ("LICENSE", "BSD-3-Clause", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"),
    "golang.org/x/sync@v0.23.0":
        ("LICENSE", "BSD-3-Clause", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"),
    "golang.org/x/sys@v0.48.0":
        ("LICENSE", "BSD-3-Clause", "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"),
    "k8s.io/klog/v2@v2.130.1":
        ("LICENSE", "Apache-2.0", "73ba74dfaa520b49a401b5d21459a8523a146f3b7518a833eea5efa85130bf68"),
    "modernc.org/libc@v1.77.1":
        ("LICENSE", "BSD-3-Clause", "95ff867eb55a56935fa7492406cfa953fb7c13ca73f4c0a86ae05756b4605600"),
    "modernc.org/mathutil@v1.7.1":
        ("LICENSE", "BSD-3-Clause", "bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5"),
    "modernc.org/memory@v1.12.1":
        ("LICENSE", "BSD-3-Clause", "59895e669f48f168b6b858358f6005779cdf40a265f7828813061b56af67b496"),
    "modernc.org/sqlite@v1.60.1":
        ("LICENSE", "BSD-3-Clause", "c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822"),
}
LICENCES = frozenset({"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Apache-2.0 AND BSD-3-Clause"})
# The one exception (ADR 0026): Tessera's dependency, linked unmodified; depguard keeps our code from importing it.
LICENCE_EXCEPTION = ("github.com/hashicorp/golang-lru/v2@v2.0.7", "MPL-2.0")
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


def licence_problems(key: str, module_dir: str) -> list[str]:
    """A listed module's licence is allowed and its file in the module directory is the one pinned."""
    name, spdx, want = ALLOWED_MODULES[key]
    if spdx not in LICENCES and (key, spdx) != LICENCE_EXCEPTION:
        return [f"{key}: licence {spdx} is not allowed (ENGINEERING.md 7)"]
    if not module_dir:
        return [f"{key}: no module directory to read its licence from"]
    try:
        got = hashlib.sha256((Path(module_dir) / name).read_bytes()).hexdigest()
    except OSError as err:
        return [f"{key}: licence file: {err}"]
    return [] if got == want else [f"{key}: {name} has sha256 {got}, pinned {want}"]


def owned_problems(deps_json: str, codeowners: str, go_mod: str) -> list[str]:
    rules, problems = codeowners_rules(codeowners)
    module_path = go_module(go_mod)
    if not module_path:
        return problems + ["go.mod has no single module line"]
    try:
        packages = go_list_packages(deps_json)
    except ValueError as err:
        return problems + [f"go list output is not JSON: {err}"]
    seen, licensed = set(), set()
    for pkg in packages:
        path = pkg.get("ImportPath", "")
        if pkg.get("Standard") is True:
            continue
        module = pkg.get("Module") or {}
        if allowed_module(path, module):
            key = f"{module['Path']}@{module.get('Version')}"
            if key not in licensed:
                licensed.add(key)
                problems += licence_problems(key, module.get("Dir", ""))
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
