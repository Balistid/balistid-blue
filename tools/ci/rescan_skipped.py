#!/usr/bin/env python3
"""Copy every committed file that gitleaks would skip into a directory gitleaks will scan.

The pinned gitleaks skips some paths by default (go.mod, go.sum, its own config), and the
secrets job scans history in git mode, so a secret committed to such a file and removed later
would reach `main` unseen. For every commit in the range, this writes each such blob to
`rescan/<n>.txt`, a name no default allowlist matches, prints which commit and path each file
came from, and runs `gitleaks dir` on it with the repository config.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
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


def scan(gitleaks: str, config: Path, workdir: Path) -> int:
    """Run gitleaks on <workdir>/rescan exactly as CI does; nonzero means a leak or an error."""
    (workdir / "no-ignore").mkdir(exist_ok=True)
    return subprocess.run(
        [gitleaks, "dir", "--config", str(config.resolve()), "--redact", "--no-banner",
         "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(workdir / "no-ignore"), "rescan"],
        cwd=workdir, timeout=300,
    ).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--range", dest="rev_range", required=True)
    parser.add_argument("--gitleaks", required=True, help="pinned gitleaks binary")
    parser.add_argument("--config", type=Path, required=True, help="gitleaks config of the repository")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for commit, path, target in extract(args.repo, args.rev_range, workdir / "rescan"):
            print(f"{target.name}\t{commit[:12]}\t{path}")
        return scan(args.gitleaks, args.config, workdir)


if __name__ == "__main__":
    sys.exit(main())
