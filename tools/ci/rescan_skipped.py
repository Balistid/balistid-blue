#!/usr/bin/env python3
"""Copy every committed file that gitleaks would skip into a directory gitleaks will scan.

The pinned gitleaks skips some paths by default (go.mod, go.sum, its own config), and the
secrets job scans history in git mode, so a secret committed to such a file and removed later
would reach `main` unseen. For every commit in the range, this writes each such blob to
`rescan/<n>.txt`, a name no default allowlist matches, prints which commit and path each file
came from, and runs `gitleaks dir` on it with the repository config.

A window's text files hold the runner's escape (rangevm.Printable), where gitleaks reads
`\\x22api_key\\x22:\\x22...` as no key; each is decoded first, and one the escape cannot have
written fails. With --history it runs the git-mode scan of the whole history instead, which
fails on an error or on a scan of no commits as well as on a leak.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docs_budget  # noqa: E402

ESCAPED = re.compile(rb'(?:[\x20\x21\x23-\x5b\x5d-\x7e]|\\x[0-9a-f]{2})*')
NEEDS_ESCAPE = re.compile(rb'[^\x20\x21\x23-\x5b\x5d-\x7e]')
# gitleaks dir skips a file whose first bytes a file-type sniffer reads as a program or an archive (ELF, zip, PDF,
# tar's "ustar" at 257). A decoded window may start with any bytes, so its copy starts with 64 KiB of plain text.
SNIFF_PAD = (b"." * 127 + b"\n") * 512
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def skipped(path: str) -> bool:
    return path == ".gitleaks.toml" or any(p.search(path) for p in docs_budget.GITLEAKS_SKIPPED)


def window_text(path: str) -> bool:
    return path.endswith(".txt") and docs_budget.WINDOW_FILE.fullmatch(path) is not None


def unescape(data: bytes) -> bytes:
    """Decode the runner's escape; bytes it cannot have written, or would have written otherwise, are an error."""
    if not ESCAPED.fullmatch(data):
        raise ValueError("not the runner's escape")
    decoded = re.sub(rb"\\x([0-9a-f]{2})", lambda m: bytes.fromhex(m[1].decode()), data)
    if NEEDS_ESCAPE.sub(lambda m: b"\\x%02x" % m[0][0], decoded) != data:
        raise ValueError("an escape the runner would not write")
    return decoded


def extract(repo: Path, rev_range: str, out: Path) -> list[tuple[str, str, Path]]:
    out.mkdir(parents=True, exist_ok=True)
    written, decoded = [], set()
    for commit in docs_budget.commits_in(repo, rev_range):
        for mode, sha, path in docs_budget.tracked_entries(repo, commit):
            if mode not in docs_budget.REGULAR_MODES:
                continue
            if skipped(path):
                data = docs_budget.blob(repo, sha)
            elif window_text(path) and sha not in decoded:
                decoded.add(sha)  # the same blob decodes the same in every commit that holds it
                try:
                    data = SNIFF_PAD + unescape(docs_budget.blob(repo, sha))
                except ValueError as err:
                    raise SystemExit(f"rescan: {commit[:12]} {path}: {err}") from err
            else:
                continue
            target = out / f"{len(written)}.txt"
            target.write_bytes(data)
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


def history_problems(returncode: int, log: str) -> list[str]:
    """What makes a git-mode scan fail besides a leak: gitleaks exits 0 when git itself fails, logging an ERR
    line and "0 commits scanned"."""
    lines = ANSI.sub("", log).splitlines()
    problems = [f"gitleaks exited {returncode}"] if returncode else []
    problems += [f"gitleaks logged an error: {line.strip()}" for line in lines if " ERR " in line]
    counts = [m[1] for line in lines if (m := re.search(r"\b(\d+) commits scanned", line))]
    if len(counts) != 1:
        problems.append(f"gitleaks logged {len(counts)} counts of commits scanned, not one")
    elif int(counts[0]) == 0:
        problems.append("gitleaks scanned 0 commits of a history that has some")
    return problems


def history(gitleaks: str, config: Path, repo: Path, env: dict[str, str] | None = None) -> int:
    """Scan every commit in git mode as CI does, inline allow comments and any committed ignore file ignored."""
    docs_budget.commits_in(repo, "HEAD")  # a history with no commits fails here
    with tempfile.TemporaryDirectory() as no_ignore:
        proc = subprocess.run(
            [gitleaks, "git", "--config", str(config.resolve()), "--redact", "--no-banner",
             "--ignore-gitleaks-allow", "--gitleaks-ignore-path", no_ignore, str(repo)],
            capture_output=True, text=True, errors="replace", env=env, timeout=300,
        )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    problems = history_problems(proc.returncode, proc.stdout + proc.stderr)
    for problem in problems:
        print(f"secrets: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--range", dest="rev_range")
    parser.add_argument("--history", action="store_true", help="scan the whole history in git mode")
    parser.add_argument("--gitleaks", required=True, help="pinned gitleaks binary")
    parser.add_argument("--config", type=Path, required=True, help="gitleaks config of the repository")
    args = parser.parse_args(argv)
    if args.history == bool(args.rev_range):
        parser.error("give exactly one of --range and --history")
    if args.history:
        return history(args.gitleaks, args.config, args.repo)
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for commit, path, target in extract(args.repo, args.rev_range, workdir / "rescan"):
            print(f"{target.name}\t{commit[:12]}\t{path}")
        return scan(args.gitleaks, args.config, workdir)


if __name__ == "__main__":
    sys.exit(main())
