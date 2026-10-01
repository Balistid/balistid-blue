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
    # Go and deployment layout (ADR 0003).
    "go.mod",
    "go.sum",
    ".golangci.yml",
    "cmd/*/*.go",
    "internal/*/*.go",
    "internal/*/*/*.go",
    "cmd/*/testdata/*.json",
    "cmd/*/testdata/*.jsonl",
    "internal/*/testdata/*.json",
    "internal/*/testdata/*.jsonl",
    "internal/*/*/testdata/*.json",
    "internal/*/*/testdata/*.jsonl",
    "packaging/*/PKGBUILD",
    "deploy/audit/*.rules",
    "deploy/auditd/auditd.conf",
    "deploy/laurel/config.toml",
    "deploy/systemd/*.service",
    "deploy/systemd/*.timer",
)

REGULAR_MODES = {"100644", "100755"}
# Exact names allowed outside the grammar (uppercase or a leading dot or two dots).
EXACT_SEGMENTS = {
    "LICENSE", "README.md", "SECURITY.md", "THREAT_MODEL.md", "ENGINEERING.md", "CLAUDE.md",
    "AGENTS.md", "STATUS.md", ".gitignore", ".editorconfig", ".gitattributes", ".gitleaks.toml",
    ".github", "CODEOWNERS", "ISSUE_TEMPLATE", "PKGBUILD", ".golangci.yml",
}
DIR_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
FILE_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]*(?:\.(?:md|py|yml|toml|go|mod|sum|json|jsonl|rules|conf|service|timer))?$"
)

# Path patterns that the default config of the pinned gitleaks (v8.30.1, config/gitleaks.toml)
# exempts from scanning, minus those the name grammar already blocks (dot or uppercase segments,
# dotted directory names) and with every vendor/ path folded into one pattern. A tracked path matching one is refused, except go.mod and go.sum at the
# root, whose whole content must instead match a strict grammar (CONTENT_GRAMMAR), so nothing can
# hide in them. Update this list together with GITLEAKS_VERSION in ci.yml.
GITLEAKS_SKIPPED = tuple(re.compile(p) for p in (
    r"gitleaks\.toml",
    r"(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
    r"(?i)\.(?:eot|[ot]tf|woff2?)$",
    r"(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
    r"go\.(?:mod|sum|work(?:\.sum)?)$",
    r"(?:^|/)vendor/",
    r"(?:^|/)gradlew(?:\.bat)?$",
    r"(?:^|/)gradle\.lockfile$",
    r"(?:^|/)mvnw(?:\.cmd)?$",
    r"(?:^|/)node_modules(?:/.*)?$",
    r"(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$",
    r"(?:^|/)bower_components(?:/.*)?$",
    r"(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js",
    r"(?:^|/)javascript\.json$",
    r"(?:^|/)(?:Pipfile|poetry)\.lock$",
    r"(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
    r"(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$",
    r"\.gem$",
    r"verification-metadata\.xml",
    r"Database.refactorlog",
))
_MOD_PATH = r"[A-Za-z0-9.~_+/-]+"
_MOD_VER = r"v[0-9A-Za-z.+-]+"
CONTENT_GRAMMAR = {
    "go.sum": re.compile(rf"^{_MOD_PATH} {_MOD_VER}(?:/go\.mod)? h1:[A-Za-z0-9+/]{{43}}=$"),
    "go.mod": re.compile(
        rf"^(?:module {_MOD_PATH}|go \d+\.\d+(?:\.\d+)?|toolchain go\d+\.\d+\.\d+"
        rf"|require {_MOD_PATH} {_MOD_VER}(?: // indirect)?|require \(|\t{_MOD_PATH} {_MOD_VER}"
        rf"(?: // indirect)?|\)|)$"
    ),
}


def content_violation(path: str, data: bytes) -> str | None:
    """Check files that gitleaks skips line by line against their only legal shape."""
    grammar = CONTENT_GRAMMAR[path]
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return "content is not ASCII"
    if path == "go.sum" and text == "":
        return None
    if text.endswith("\n"):
        text = text[:-1]
    for number, line in enumerate(text.split("\n"), 1):
        if not grammar.match(line):
            return f"line {number} breaks the {path} grammar"
    return None


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


def tracked_entries(repo: Path, rev: str | None = None) -> list[tuple[str, str, str]]:
    """Return (mode, object sha, path) for every index entry, or every entry of a commit's tree."""
    cmd = ["ls-files", "-z", "--stage"] if rev is None else ["ls-tree", "-r", "-z", "--full-tree", rev]
    out = subprocess.run(["git", "-C", str(repo), *cmd], check=True, capture_output=True).stdout
    entries = []
    for record in out.decode().split("\0"):
        if record:
            meta, path = record.split("\t", 1)
            fields = meta.split()
            # ls-files prints mode, sha, stage; ls-tree prints mode, type, sha.
            mode, sha = (fields[0], fields[1]) if rev is None else (fields[0], fields[2])
            entries.append((mode, sha, path))
    return entries


def commits_in(repo: Path, rev_range: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--reverse", rev_range],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if not out:
        raise SystemExit(f"docs-budget: range {rev_range!r} has no commits")
    return out


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


def check(repo: Path, rev: str | None = None) -> list[str]:
    violations = []
    for mode, sha, path in tracked_entries(repo, rev):
        if mode not in REGULAR_MODES:
            violations.append(f"{path}: mode {mode} is not a regular file")
            continue
        problem = grammar_violation(path)
        if problem:
            violations.append(f"{path}: {problem}")
            continue
        if path.endswith(".go") and "testdata" in path.split("/"):
            violations.append(f"{path}: Go code under testdata is never built, vetted or linted")
            continue
        # .gitleaks.toml is skipped by gitleaks itself; that risk is accepted in ADR 0001 (code-owned).
        if path != ".gitleaks.toml" and any(p.search(path) for p in GITLEAKS_SKIPPED):
            if path not in CONTENT_GRAMMAR:
                violations.append(f"{path}: gitleaks would skip this path")
                continue
            problem = content_violation(path, blob(repo, sha))
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
    parser.add_argument("--range", dest="rev_range",
                        help="check the tree of every commit in this range, not the index")
    args = parser.parse_args(argv)
    if args.rev_range:
        violations = [f"{c[:12]}: {v}" for c in commits_in(args.repo, args.rev_range)
                      for v in check(args.repo, c)]
    else:
        violations = check(args.repo)
    for v in violations:
        print(f"docs-budget: {v}", file=sys.stderr)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
