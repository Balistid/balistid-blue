#!/usr/bin/env python3
"""Fail on any tracked path outside the repository layout allowlist, and on prose over its caps.

Rule R12 (ENGINEERING.md): running code first, documents about it second. The allowlist is closed:
a path that matches no entry fails, whatever its suffix. Prose files also have line and byte caps.
Only regular files are allowed (no symlinks, no submodules). Every path segment follows a strict
grammar (lowercase, at most one extension from a short list) unless it is one of a few exact names;
the gitleaks default path allowlist matches only names outside that grammar, so no tracked file can
hide from the secret scan by its name. Sizes are measured on the committed blob, not the
checked-out file (which .gitattributes filters could change). Changing either list requires an ADR (adr/0001-repo-governance.md);
code directories are added by the ADR that picks the implementation language.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
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
    "zizmor.yml",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/workflows/*.yml",
    ".github/ISSUE_TEMPLATE/*.yml",
    "githooks/pre-commit",
    "githooks/commit-msg",
    "tools/ci/*.py",
    "tools/ci/tests/*.py",
    "acceptance/[0-9].toml",
)

REGULAR_MODES = {"100644", "100755"}
# Exact names allowed outside the grammar (uppercase or a leading dot or two dots).
EXACT_SEGMENTS = {
    "LICENSE", "README.md", "SECURITY.md", "THREAT_MODEL.md", "ENGINEERING.md", "CLAUDE.md",
    "AGENTS.md", "STATUS.md", ".gitignore", ".editorconfig", ".gitattributes", ".gitleaks.toml",
    ".github", "CODEOWNERS", "ISSUE_TEMPLATE",
}
DIR_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
FILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(?:\.(?:md|py|yml|toml))?$")


def grammar_violation(path: str) -> str | None:
    *dirs, name = path.split("/")
    for seg in dirs:
        if seg not in EXACT_SEGMENTS and not DIR_RE.match(seg):
            return f"directory name {seg!r} breaks the name grammar"
    if name not in EXACT_SEGMENTS and not FILE_RE.match(name):
        return f"file name {name!r} breaks the name grammar"
    return None


def matches(path: str, pattern: str) -> bool:
    """Match segment by segment so that '*' never crosses a '/'."""
    parts, pats = path.split("/"), pattern.split("/")
    return len(parts) == len(pats) and all(fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pats))


def tracked_entries(repo: Path) -> list[tuple[str, str, str]]:
    """Return (mode, blob sha, path) for every index entry."""
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--stage"],
        check=True,
        capture_output=True,
    ).stdout
    entries = []
    for record in out.decode().split("\0"):
        if record:
            meta, path = record.split("\t", 1)
            mode, sha, _stage = meta.split()
            entries.append((mode, sha, path))
    return entries


def blob(repo: Path, sha: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), "cat-file", "blob", sha],
        check=True,
        capture_output=True,
    ).stdout


def doc_cap(path: str) -> int | None:
    for pattern, cap in DOCS:
        if matches(path, pattern):
            return cap
    return None


def check(repo: Path) -> list[str]:
    violations = []
    for mode, sha, path in tracked_entries(repo):
        if mode not in REGULAR_MODES:
            violations.append(f"{path}: mode {mode} is not a regular file")
            continue
        problem = grammar_violation(path)
        if problem:
            violations.append(f"{path}: {problem}")
            continue
        cap = doc_cap(path)
        if cap is None:
            if not any(matches(path, pattern) for pattern in LAYOUT):
                violations.append(f"{path}: not in repository layout allowlist")
            continue
        data = blob(repo, sha)
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
