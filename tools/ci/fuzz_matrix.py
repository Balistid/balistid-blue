#!/usr/bin/env python3
"""Print the nightly fuzz matrix as a GitHub output line, from `go test -list '^Fuzz' -json ./...` on stdin.

Every fuzz function the compiler lists is one row (ADR 0041): an hour each for code that reads input on the host
or the Pi, ten minutes for the range guest's own (fuzz_hours, ADR 0016). A failed build, a name that is not a
plain identifier or an empty list is an error: a fuzz run that cannot tell its targets must not pass.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable

MODULE = "github.com/Balistid/balistid-blue/"
# Code that only the range guest runs on its own output; everything else reads input on the host or the Pi.
GUEST_ONLY = {"./cmd/balistid-range-guest", "./internal/rangeguest"}
GUEST_MINUTES, HOST_MINUTES = 10, 60
TARGET = re.compile(r"Fuzz[A-Za-z0-9_]*")
PKG = re.compile(r"\./[a-z0-9/_-]+")
# `go test -json` events of a listing that built; build-fail, fail and anything new stop the run.
LISTING = {"start", "output", "pass", "skip"}


def rows(events: Iterable[str]) -> list[dict[str, str | int]]:
    found = set()
    for line in events:
        event = json.loads(line)
        action, package = event.get("Action"), event.get("Package", "")
        if action not in LISTING:
            raise ValueError(f"go test reported {action!r} for {package!r}")
        name = event.get("Output", "").removesuffix("\n")
        if action != "output" or not name.startswith("Fuzz"):
            continue
        pkg = "./" + package.removeprefix(MODULE)
        if not package.startswith(MODULE) or not PKG.fullmatch(pkg) or not TARGET.fullmatch(name):
            raise ValueError(f"not a fuzz target of this module: {package!r} {name!r}")
        if (pkg, name) in found:
            raise ValueError(f"listed twice: {pkg} {name}")
        found.add((pkg, name))
    if not found:
        raise ValueError("no fuzz target listed")
    return [{"pkg": pkg, "target": name, "minutes": GUEST_MINUTES if pkg in GUEST_ONLY else HOST_MINUTES}
            for pkg, name in sorted(found)]


def main() -> int:
    try:
        matrix = rows(sys.stdin)
    except (ValueError, json.JSONDecodeError) as err:
        print(f"fuzz-matrix: {err}", file=sys.stderr)
        return 1
    print("matrix=" + json.dumps(matrix, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
