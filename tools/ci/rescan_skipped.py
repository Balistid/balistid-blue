#!/usr/bin/env python3
"""Copy every committed file that gitleaks would skip into a directory gitleaks will scan.

The pinned gitleaks skips some paths by default (go.mod, go.sum, its own config), and the
secrets job scans history in git mode, so a secret committed to such a file and removed later
would reach `main` unseen. For every commit in the range, this writes each such blob to
`<out>/<n>.txt`, a name no default allowlist matches, and prints which commit and path each file
came from. The secrets job then runs `gitleaks dir` on that directory with the default config.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docs_budget  # noqa: E402


def skipped(path: str) -> bool:
    return path == ".gitleaks.toml" or any(p.search(path) for p in docs_budget.GITLEAKS_SKIPPED)


def extract(repo: Path, rev_range: str, out: Path) -> list[tuple[str, str, Path]]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for commit in docs_budget.commits_in(repo, rev_range):
        for mode, sha, path in docs_budget.tracked_entries(repo, commit):
            if mode in docs_budget.REGULAR_MODES and skipped(path):
                target = out / f"{len(written)}.txt"
                target.write_bytes(docs_budget.blob(repo, sha))
                written.append((commit, path, target))
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--range", dest="rev_range", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists() and any(args.out.iterdir()):
        print(f"rescan: {args.out} is not empty", file=sys.stderr)
        return 1
    for commit, path, target in extract(args.repo, args.rev_range, args.out):
        print(f"{target.name}\t{commit[:12]}\t{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
