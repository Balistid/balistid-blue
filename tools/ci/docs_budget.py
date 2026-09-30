#!/usr/bin/env python3
"""Fail when the repo carries documentation outside the allowlist or over its line cap.

Rule R12 (ENGINEERING.md): running code first, documents about it second. Every
prose file must match an allowlisted path and stay under that path's line cap.
Changing the allowlist requires an ADR (adr/0001-repo-governance.md).
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path

PROSE_SUFFIXES = (".md", ".markdown", ".rst", ".adoc", ".txt")

# (glob relative to repo root, max lines). First match wins.
ALLOWLIST: tuple[tuple[str, int], ...] = (
    ("README.md", 120),
    ("SECURITY.md", 60),
    ("THREAT_MODEL.md", 80),
    ("ENGINEERING.md", 160),
    ("CLAUDE.md", 80),
    ("AGENTS.md", 60),
    ("STATUS.md", 40),
    ("adr/[0-9][0-9][0-9][0-9]-*.md", 60),
    (".github/pull_request_template.md", 40),
)


def tracked_files(repo: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--cached"],
        check=True,
        capture_output=True,
    ).stdout
    return [p for p in out.decode().split("\0") if p]


def cap_for(path: str) -> int | None:
    for pattern, cap in ALLOWLIST:
        if fnmatch.fnmatchcase(path, pattern):
            return cap
    return None


def check(repo: Path) -> list[str]:
    violations = []
    for path in tracked_files(repo):
        if not path.lower().endswith(PROSE_SUFFIXES):
            continue
        cap = cap_for(path)
        if cap is None:
            violations.append(f"{path}: not in docs allowlist")
            continue
        with open(repo / path, encoding="utf-8") as fh:
            lines = sum(1 for _ in fh)
        if lines > cap:
            violations.append(f"{path}: {lines} lines > cap {cap}")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    violations = check(args.repo)
    for v in violations:
        print(f"docs-budget: {v}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
