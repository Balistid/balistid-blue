#!/usr/bin/env python3
"""Checks for the Go CI job that need no Go toolchain to test (ADR 0003).

toolchain: go.mod pins `toolchain go<version>` and the running toolchain reports exactly that
           upstream version (no distribution suffix such as `X:nodwarf5`).
modsum:    a module fetched with `go mod download -json` has the pinned h1 hash.
same:      two release builds are byte-identical.
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
    args = parser.parse_args(argv)
    if args.cmd == "toolchain":
        problems = toolchain_problems(args.go_mod.read_text(), args.goversion, args.expect)
    elif args.cmd == "modsum":
        problems = modsum_problems(args.json.read_text(), args.expect)
    else:
        problems = same_problems(args.a.read_bytes(), args.b.read_bytes())
    for p in problems:
        print(f"go-gate: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
