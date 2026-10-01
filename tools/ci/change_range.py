#!/usr/bin/env python3
"""Print the git revision range a CI run must check, from the GitHub event in the environment.

pull_request: base..head of the pull request.
push:         before..after; a new branch (before is all zeros) checks all history up to after.
Anything else, or a missing value, is an error: a gate that cannot tell what changed must not pass.
"""

from __future__ import annotations

import os
import re
import sys

SHA = re.compile(r"[0-9a-f]{40}")
ZERO = "0" * 40


def change_range(event: str, pr_base: str, pr_head: str, push_before: str, push_after: str) -> str:
    if event == "pull_request":
        shas = (pr_base, pr_head)
    elif event == "push":
        shas = (push_before, push_after)
    else:
        raise ValueError(f"unsupported event {event!r}")
    for sha in shas:
        if not SHA.fullmatch(sha):
            raise ValueError(f"not a full commit sha: {sha!r}")
    if shas[1] == ZERO:
        raise ValueError("head or after is all zeros")
    if event == "push" and push_before == ZERO:
        return push_after
    if shas[0] == ZERO:
        raise ValueError("pull request base is all zeros")
    return f"{shas[0]}..{shas[1]}"


def main() -> int:
    env = os.environ
    try:
        print(change_range(env.get("EVENT", ""), env.get("PR_BASE", ""), env.get("PR_HEAD", ""),
                           env.get("PUSH_BEFORE", ""), env.get("PUSH_AFTER", "")))
    except ValueError as err:
        print(f"change-range: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
