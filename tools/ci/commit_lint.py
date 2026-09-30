#!/usr/bin/env python3
"""Check commit messages against ENGINEERING.md rules.

- Subject follows Conventional Commits and fits in 72 characters.
- Body, if any, is separated from the subject by a blank line.
- Exactly one `Agent:` line in the whole message, and it sits in the final trailer block as parsed
  by `git interpret-trailers` (R11): `Agent: alex` or `Agent: <claude|codex>/<model>`.
- No advertising trailers (Co-Authored-By, "Generated with", robot emoji).
- In range mode: no merge commits (linear history).

Modes: --message-file (commit-msg hook) or --range REV-RANGE (CI).
--dependabot-pr exempts commits authored by Dependabot from the Agent trailer only. CI sets it only
when GitHub reports the pull request author as dependabot[bot]; the author email alone is not trusted.
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
AGENT_LINE_RE = re.compile(r"^\s*agent\s*:", re.IGNORECASE)
FORBIDDEN_RE = re.compile(r"co-authored-by|generated with|\U0001F916", re.IGNORECASE)
SCISSORS = "# ------------------------ >8 ------------------------"
DEPENDABOT_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"


def strip_comments(message: str) -> str:
    kept = []
    for line in message.splitlines():
        if line == SCISSORS:
            break
        if not line.startswith("#"):
            kept.append(line)
    return "\n".join(kept).strip("\n")


def parsed_trailers(message: str) -> list[str]:
    out = subprocess.run(
        ["git", "interpret-trailers", "--parse", "--no-divider"],
        input=message + "\n",
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [ln for ln in out.splitlines() if ln]


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
    if require_agent:
        agent_lines = [ln for ln in lines if AGENT_LINE_RE.match(ln)]
        trailer_agents = [t for t in parsed_trailers(message) if AGENT_LINE_RE.match(t)]
        if len(agent_lines) != 1:
            errors.append(f"expected exactly one 'Agent:' line, found {len(agent_lines)}")
        elif not AGENT_RE.match(agent_lines[0]):
            errors.append(f"malformed trailer {agent_lines[0]!r}; use 'Agent: alex' or 'Agent: claude/<model>'")
        elif len(trailer_agents) != 1:
            errors.append("'Agent:' must be in the final trailer block (last paragraph)")
    return errors


def read_commit(repo: Path, sha: str) -> tuple[int, str, str]:
    """Return (parent count, author email, message) from the raw commit object."""
    raw = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "commit", sha],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    header, _, message = raw.partition("\n\n")
    parents, email = 0, ""
    for line in header.splitlines():
        if line.startswith("parent "):
            parents += 1
        elif line.startswith("author "):
            match = re.search(r"<([^>]*)>", line)
            email = match.group(1) if match else ""
    return parents, email, message.strip("\n")


def shas_in_range(repo: Path, rev_range: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--reverse", rev_range],
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
    parser.add_argument("--dependabot-pr", action="store_true")
    args = parser.parse_args(argv)

    if args.message_file:
        errors = lint(strip_comments(args.message_file.read_text(encoding="utf-8")))
        for e in errors:
            print(f"commit-lint: {e}", file=sys.stderr)
        return 1 if errors else 0

    shas = shas_in_range(args.repo, args.rev_range)
    if not shas:
        print(f"commit-lint: no commits in range {args.rev_range}", file=sys.stderr)
        return 1
    failures = 0
    for sha in shas:
        parents, email, message = read_commit(args.repo, sha)
        errors = []
        if parents > 1:
            errors.append("merge commits are not allowed (linear history)")
        exempt = args.dependabot_pr and email == DEPENDABOT_EMAIL
        errors.extend(lint(message, require_agent=not exempt))
        for e in errors:
            print(f"commit-lint: {sha[:12]}: {e}", file=sys.stderr)
        failures += len(errors)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
