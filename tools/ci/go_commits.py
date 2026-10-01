#!/usr/bin/env python3
"""Print, as a JSON list, the commits in a range that the per-commit Go job must build and test.

Commits before go.mod first appears are skipped, unless they already contain Go files. Once go.mod
exists (in the range's base or any earlier commit), a commit without it fails: deleting go.mod must
not switch the gate off. CI runs one fresh runner per listed commit.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def has_go_mod(repo: Path, rev: str) -> bool:
    return git(repo, "cat-file", "-e", f"{rev}:go.mod").returncode == 0


def has_go_files(repo: Path, rev: str) -> bool:
    out = git(repo, "ls-tree", "-r", "--name-only", rev)
    if out.returncode != 0:
        raise ValueError(f"cannot list {rev}")
    return any(p.endswith(".go") for p in out.stdout.splitlines())


def go_commits(repo: Path, rev_range: str) -> list[str]:
    listed = git(repo, "rev-list", "--reverse", rev_range)
    commits = listed.stdout.split()
    if listed.returncode != 0 or not commits:
        raise ValueError(f"range {rev_range!r} has no commits")
    base = rev_range.split("..", 1)[0] if ".." in rev_range else None
    seen = base is not None and has_go_mod(repo, base)
    selected = []
    for commit in commits:
        if has_go_mod(repo, commit):
            seen = True
            selected.append(commit)
        elif seen:
            raise ValueError(f"{commit}: go.mod removed after it existed")
        elif has_go_files(repo, commit):
            raise ValueError(f"{commit}: Go files without go.mod")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--range", dest="rev_range", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(go_commits(args.repo, args.rev_range), separators=(",", ":")))
    except ValueError as err:
        print(f"go-commits: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
