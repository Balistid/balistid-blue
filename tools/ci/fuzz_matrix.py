#!/usr/bin/env python3
"""Print the nightly fuzz matrix as a GitHub output line, from the fuzz functions in the tracked test files.

Every `func FuzzXxx(*testing.F)` in a tracked `*_test.go` is one row (ADR 0041): an hour each for code that reads
input on the host or the Pi, ten minutes for the range guest's own (fuzz_hours, ADR 0016). It reads source and
runs no project code, so no package can change another's rows. A declaration it cannot read, a package path it
cannot use, a duplicate or an empty list is an error; a row that is not a real target fails its job, which must
show the fuzzer running.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

# Code that only the range guest runs on its own output; everything else reads input on the host or the Pi.
GUEST_ONLY = {"./cmd/balistid-range-guest", "./internal/rangeguest"}
GUEST_MINUTES, HOST_MINUTES = 10, 60
# Every top-level func whose name starts with Fuzz; go test takes it when Fuzz ends the name or is followed by a
# character that is not lower case, and then it must read as one *testing.F parameter, or the scan stops.
DECL = re.compile(r"^func[ \t]+(Fuzz\w*)", re.M)
SIGNATURE = re.compile(r"\(\s*(?:\w+\s+)?\*testing\.F\s*,?\s*\)\s*\{")
PKG = re.compile(r"\./[a-z0-9/_-]+")


def ignored(directory: PurePosixPath) -> bool:
    """Directories the go tool skips in ./...: testdata, vendor, and names starting with _ or a dot."""
    return any(p in ("testdata", "vendor") or p.startswith(("_", ".")) for p in directory.parts)


def rows(files: dict[str, str]) -> list[dict[str, str | int]]:
    """files maps each tracked *_test.go path, relative to the repository root, to its text."""
    found = set()
    for path, text in files.items():
        directory = PurePosixPath(path).parent
        if ignored(directory):
            continue
        pkg = "./" + directory.as_posix()
        for decl in DECL.finditer(text):
            name = decl.group(1)
            if len(name) > 4 and name[4].islower():
                continue
            if not SIGNATURE.match(text, decl.end()):
                raise ValueError(f"{path}: {name} is not written as func {name}(f *testing.F) {{, which the scan reads")
            if not PKG.fullmatch(pkg):
                raise ValueError(f"not a package path the matrix can use: {pkg!r}")
            if (pkg, name) in found:
                raise ValueError(f"listed twice: {pkg} {name}")
            found.add((pkg, name))
    if not found:
        raise ValueError("no fuzz target found")
    return [{"pkg": pkg, "target": name, "minutes": GUEST_MINUTES if pkg in GUEST_ONLY else HOST_MINUTES}
            for pkg, name in sorted(found)]


def tracked_tests() -> dict[str, str]:
    out = subprocess.run(["git", "ls-files", "-z", "--", "*_test.go"], check=True, capture_output=True).stdout
    paths = [p for p in out.decode("utf-8").split("\0") if p]
    return {p: Path(p).read_text(encoding="utf-8") for p in paths}


def main() -> int:
    try:
        matrix = rows(tracked_tests())
    except (ValueError, OSError, subprocess.CalledProcessError) as err:
        print(f"fuzz-matrix: {err}", file=sys.stderr)
        return 1
    print("matrix=" + json.dumps(matrix, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
