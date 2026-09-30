#!/usr/bin/env python3
"""Check commit messages against ENGINEERING.md rules.

- Subject follows Conventional Commits and fits in 72 characters.
- Body, if any, is separated from the subject by a blank line.
- Exactly one provenance trailer `Agent: alex` or `Agent: <claude|codex>/<model>` (R11).
- No advertising trailers (Co-Authored-By, "Generated with", robot emoji).

Modes: --message-file (commit-msg hook) or --range BASE..HEAD (CI).
Dependabot commits are exempt from the Agent trailer only; every other rule applies.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

TYPES = "feat|fix|docs|refactor|test|ci|build|chore|perf|revert|security"
SUBJECT_RE = re.compile(rf"^({TYPES})(\([a-z0-9-]+\))?!?: \S.*$")
SUBJECT_MAX = 72
AGENT_RE = re.compile(r"^Agent: (alex|(claude|codex)/[a-z0-9][a-z0-9.-]*)$")
AGENT_LINE_RE = re.compile(r"^agent:", re.IGNORECASE)
FORBIDDEN_RE = re.compile(r"co-authored-by|generated with|\U0001F916", re.IGNORECASE)
DEPENDABOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"


def strip_comments(message: str) -> str:
    lines = [ln for ln in message.splitlines() if not ln.startswith("#")]
    return "\n".join(lines).strip("\n")


def lint(message: str, *, require_agent: bool = True) -> list[str]:
    errors = []
    lines = message.splitlines()
    if not lines or not lines[0].strip():
        return ["empty commit message"]
    subject = lines[0]
    if not SUBJECT_RE.match(subject):
        errors.append(f"subject is not Conventional Commits ({TYPES}): {subject!r}")
    if len(subject) > SUBJECT_MAX:
        errors.append(f"subject longer than {SUBJECT_MAX} characters")
    if len(lines) > 1 and lines[1].strip():
        errors.append("second line must be blank")
    if FORBIDDEN_RE.search(message):
        errors.append("advertising trailer found (Co-Authored-By / Generated with / robot emoji)")
    agent_lines = [ln for ln in lines if AGENT_LINE_RE.match(ln)]
    if require_agent:
        if len(agent_lines) != 1:
            errors.append(f"expected exactly one 'Agent:' trailer, found {len(agent_lines)}")
        elif not AGENT_RE.match(agent_lines[0]):
            errors.append(f"malformed trailer {agent_lines[0]!r}; use 'Agent: alex' or 'Agent: claude/<model>'")
    return errors


def commits_in_range(repo: Path, rev_range: str) -> list[tuple[str, str, str]]:
    fmt = "%H%x1f%ae%x1f%B%x1e"
    out = subprocess.run(
        ["git", "-C", str(repo), "log", "--no-merges", f"--format={fmt}", rev_range],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    commits = []
    for record in out.split("\x1e"):
        record = record.strip("\n")
        if record:
            sha, email, body = record.split("\x1f", 2)
            commits.append((sha, email, body.strip("\n")))
    return commits


def merges_in_range(repo: Path, rev_range: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--merges", rev_range],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.split()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--message-file", type=Path)
    group.add_argument("--range", dest="rev_range")
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args(argv)

    failures = 0
    if args.message_file:
        errors = lint(strip_comments(args.message_file.read_text(encoding="utf-8")))
        for e in errors:
            print(f"commit-lint: {e}", file=sys.stderr)
        return 1 if errors else 0

    for sha in merges_in_range(args.repo, args.rev_range):
        print(f"commit-lint: {sha[:12]}: merge commits are not allowed (linear history)", file=sys.stderr)
        failures += 1
    commits = commits_in_range(args.repo, args.rev_range)
    if not commits and failures == 0:
        print(f"commit-lint: no commits in range {args.rev_range}", file=sys.stderr)
        return 1
    for sha, email, body in commits:
        for e in lint(body, require_agent=email != DEPENDABOT_EMAIL):
            print(f"commit-lint: {sha[:12]}: {e}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
