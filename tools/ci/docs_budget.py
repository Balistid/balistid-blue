#!/usr/bin/env python3
"""Fail on any tracked path outside the repository layout allowlist, and on prose over its caps.

Rule R12 (ENGINEERING.md): running code first, documents about it second. The allowlist is closed:
a path that matches no entry fails, whatever its suffix. Prose files also have line and byte caps.
Symlinks are rejected. Changing either list requires an ADR (adr/0001-repo-governance.md);
code directories are added by the ADR that picks the implementation language.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path

# Prose: (pattern, max lines). Byte cap is lines * BYTES_PER_LINE.
DOCS: tuple[tuple[str, int], ...] = (
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
BYTES_PER_LINE = 120

# Everything else that may be tracked.
LAYOUT: tuple[str, ...] = (
    "LICENSE",
    ".gitignore",
    ".editorconfig",
    ".gitattributes",
    ".gitleaks.toml",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/workflows/*.yml",
    "githooks/pre-commit",
    "githooks/commit-msg",
    "tools/ci/*.py",
    "tools/ci/tests/*.py",
    "acceptance/[0-9].toml",
)

SYMLINK_MODE = "120000"


def matches(path: str, pattern: str) -> bool:
    """Match segment by segment so that '*' never crosses a '/'."""
    parts, pats = path.split("/"), pattern.split("/")
    return len(parts) == len(pats) and all(fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pats))


def tracked_entries(repo: Path) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--stage"],
        check=True,
        capture_output=True,
    ).stdout
    entries = []
    for record in out.decode().split("\0"):
        if record:
            meta, path = record.split("\t", 1)
            entries.append((meta.split()[0], path))
    return entries


def doc_cap(path: str) -> int | None:
    for pattern, cap in DOCS:
        if matches(path, pattern):
            return cap
    return None


def check(repo: Path) -> list[str]:
    violations = []
    for mode, path in tracked_entries(repo):
        if mode == SYMLINK_MODE:
            violations.append(f"{path}: symlinks are not allowed")
            continue
        cap = doc_cap(path)
        if cap is None:
            if not any(matches(path, pattern) for pattern in LAYOUT):
                violations.append(f"{path}: not in repository layout allowlist")
            continue
        data = (repo / path).read_bytes()
        lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
        if lines > cap:
            violations.append(f"{path}: {lines} lines > cap {cap}")
        if len(data) > cap * BYTES_PER_LINE:
            violations.append(f"{path}: {len(data)} bytes > cap {cap * BYTES_PER_LINE}")
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
