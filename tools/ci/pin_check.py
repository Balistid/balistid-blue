#!/usr/bin/env python3
"""Fail when a GitHub Actions `uses:` reference is not pinned to a full commit SHA (R14).

Allowed: local actions (`./path`), `owner/repo[/path]@<40 hex>`, and
`docker://image@sha256:<64 hex>`. Tags and branches are mutable and rejected.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"#\s]+)")
PINNED_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
DOCKER_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def check_file(path: Path) -> list[str]:
    violations = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = USES_RE.match(line)
        if not match:
            continue
        ref = match.group(1)
        if ref.startswith("./") or PINNED_RE.match(ref) or DOCKER_RE.match(ref):
            continue
        violations.append(f"{path}:{lineno}: unpinned action reference {ref!r}")
    return violations


def workflow_files(repo: Path) -> list[Path]:
    files = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml", "**/action.yml", "**/action.yaml"):
        files.extend(repo.glob(pattern))
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
