#!/usr/bin/env python3
"""Fail when a GitHub Actions `uses:` reference is not pinned to a full commit SHA (R14).

Deliberately strict and line-based: every line that mentions `uses` must be exactly
`[- ]uses: <ref>[  # comment]`, where <ref> is a local action (`./path`),
`owner/repo[/path]@<40 hex>`, or `docker://image@sha256:<64 hex>`. Flow style, quoted keys and any
other spelling fail, so YAML syntax variants cannot smuggle in a mutable tag or branch.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MENTION_RE = re.compile(r"uses", re.IGNORECASE)
LINE_RE = re.compile(r"^\s*(?:-\s+)?uses: (\S+)(?:\s+#.*)?\s*$")
PINNED_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
LOCAL_RE = re.compile(r"^\./[A-Za-z0-9_./-]+$")
DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def check_file(path: Path) -> list[str]:
    violations = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not MENTION_RE.search(line):
            continue
        match = LINE_RE.match(line)
        ref = match.group(1) if match else None
        if ref and (PINNED_RE.match(ref) or LOCAL_RE.match(ref) or DOCKER_RE.match(ref)):
            continue
        violations.append(f"{path}:{lineno}: unpinned or non-canonical 'uses' line: {line.strip()!r}")
    return violations


def workflow_files(repo: Path) -> list[Path]:
    files = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml", "**/action.yml", "**/action.yaml"):
        files.extend(p for p in repo.glob(pattern) if ".git" not in p.relative_to(repo).parts)
    return sorted(set(files))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    files = workflow_files(args.repo)
    if not files:
        print("pin-check: no workflow files found", file=sys.stderr)
        return 1
    violations = [v for f in files for v in check_file(f)]
    for v in violations:
        print(f"pin-check: {v}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
