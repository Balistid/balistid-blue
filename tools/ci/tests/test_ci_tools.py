"""Tests for tools/ci. Each rule has a passing case and at least one case that must fail."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import change_range  # noqa: E402
import commit_lint  # noqa: E402
import docs_budget  # noqa: E402
import go_gate  # noqa: E402
import rescan_skipped  # noqa: E402

GOOD_MSG = "feat(core): add event store\n\nBody text.\n\nAgent: claude/opus-5.5"
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "1+t@users.noreply.github.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "1+t@users.noreply.github.com",
}


def git(repo: Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env or GIT_ENV,
    ).stdout


def new_repo(tmp: str) -> Path:
    repo = Path(tmp)
    git(repo, "init", "-q", "-b", "main")
    return repo


def commit(repo: Path, message: str, filename: str = "f", env: dict | None = None) -> None:
    path = repo / filename
    path.write_text(path.read_text() + "x" if path.exists() else "x")
    git(repo, "add", filename)
    git(repo, "commit", "-q", "--no-verify", "-m", message, env=env)


class CommitLintMessageTest(unittest.TestCase):
    def test_valid_message_passes(self):
        self.assertEqual(commit_lint.lint(GOOD_MSG), [])

    def test_maintainer_trailer_passes(self):
        self.assertEqual(commit_lint.lint("fix: typo\n\nAgent: jvc0n"), [])

    def test_maintainer_by_name_fails(self):
        # ADR 0063: the maintainer signs by handle; the old trailer no longer passes.
        self.assertTrue(commit_lint.lint("fix: typo\n\nAgent: " + "al" + "ex"))

    def test_missing_agent_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nbody"))

    def test_two_agent_trailers_fail(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\nAgent: claude/opus-5.5"))

    def test_malformed_agent_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: Claude Opus"))

    def test_lowercase_agent_key_counts_and_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nagent: jvc0n"))

    def test_co_authored_by_fails(self):
        msg = GOOD_MSG + "\nCo-Authored-By: Claude <noreply@anthropic.com>"
        self.assertTrue(commit_lint.lint(msg))

    def test_generated_with_fails(self):
        self.assertTrue(commit_lint.lint(GOOD_MSG + "\nGenerated with Claude Code"))

    def test_robot_emoji_fails(self):
        self.assertTrue(commit_lint.lint(GOOD_MSG + "\n\U0001F916"))

    def test_non_conventional_subject_fails(self):
        self.assertTrue(commit_lint.lint("Add stuff\n\nAgent: jvc0n"))

    def test_long_subject_fails(self):
        self.assertTrue(commit_lint.lint("feat: " + "a" * 80 + "\n\nAgent: jvc0n"))

    def test_missing_blank_line_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\nbody\n\nAgent: jvc0n"))

    def test_empty_fails(self):
        self.assertTrue(commit_lint.lint(""))

    def test_agent_outside_trailer_block_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\n\nTrailing paragraph."))

    def test_agent_value_is_checked_as_git_parses_it(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\n really claude/opus wrote it"))

    def test_line_separator_characters_fail(self):
        self.assertTrue(commit_lint.lint("feat: x\x0b\x0bfree text\n\nAgent: jvc0n"))
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\u2028claude/opus-5.5 actually"))

    def test_agent_must_be_last_line(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\n# trailing comment line"))
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: jvc0n\nConflicts:\n\tfile"))

    def test_scissors_block_is_ignored(self):
        msg = GOOD_MSG + "\n" + commit_lint.SCISSORS + "\n+Co-Authored-By: someone\n"
        self.assertEqual(commit_lint.lint(commit_lint.strip_comments(msg)), [])

    def test_hook_strips_tool_attribution_and_passes(self):
        msg = ("feat(core): add event store\n\nBody text.\n\nAgent: claude/opus-5.5\n"
               "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n"
               "\U0001F916 Generated with [Claude Code](https://claude.com/claude-code)\n")
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write(msg)
        try:
            self.assertEqual(commit_lint.main(["--strip-attribution", "--message-file", fh.name]), 0)
            cleaned = Path(fh.name).read_text()
            self.assertNotIn("Co-Authored-By", cleaned)
            self.assertTrue(cleaned.rstrip("\n").endswith("Agent: claude/opus-5.5"))
        finally:
            os.unlink(fh.name)

    def test_without_strip_flag_attribution_still_fails(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write(GOOD_MSG + "\nCo-Authored-By: x <x@y>\n")
        try:
            self.assertEqual(commit_lint.main(["--message-file", fh.name]), 1)
        finally:
            os.unlink(fh.name)

    def test_hook_mode_strips_comments(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write(GOOD_MSG + "\n# Please enter the commit message\n")
        try:
            self.assertEqual(commit_lint.main(["--message-file", fh.name]), 0)
        finally:
            os.unlink(fh.name)


class CommitLintRangeTest(unittest.TestCase):
    def test_range_passes_and_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: jvc0n")
            base = git(repo, "rev-parse", "HEAD").strip()
            commit(repo, GOOD_MSG)
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 0)
            commit(repo, "feat: sneaky\n\nAgent: jvc0n\nCo-Authored-By: x <x@y>")
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    def test_empty_range_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, GOOD_MSG)
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", "HEAD..HEAD"]), 1)

    def test_merge_commit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: jvc0n")
            base = git(repo, "rev-parse", "HEAD").strip()
            git(repo, "checkout", "-q", "-b", "side")
            commit(repo, GOOD_MSG, filename="g")
            git(repo, "checkout", "-q", "main")
            commit(repo, GOOD_MSG, filename="h")
            git(repo, "merge", "-q", "--no-ff", "--no-edit", "-m", "chore: merge\n\nAgent: jvc0n", "side")
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    def test_dependabot_exempt_from_agent_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: jvc0n")
            base = git(repo, "rev-parse", "HEAD").strip()
            bot = {**GIT_ENV, "GIT_AUTHOR_EMAIL": commit_lint.DEPENDABOT_EMAIL}
            commit(repo, "ci: bump actions/checkout from 1 to 2", env=bot)
            rng = ["--repo", tmp, "--range", f"{base}..HEAD"]
            self.assertEqual(commit_lint.main(rng + ["--dependabot-pr"]), 0)
            # A spoofed author email without GitHub's PR-author signal is not exempt.
            self.assertEqual(commit_lint.main(rng), 1)
            commit(repo, "Bump something", env=bot)
            self.assertEqual(commit_lint.main(rng + ["--dependabot-pr"]), 1)

    def test_personal_address_fails_without_being_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: jvc0n")
            base = git(repo, "rev-parse", "HEAD").strip()
            rng = ["--repo", tmp, "--range", f"{base}..HEAD"]
            for key in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
                with self.subTest(key=key):
                    commit(repo, GOOD_MSG, env={**GIT_ENV, key: "someone@mail.example"})
                    err = io.StringIO()
                    with contextlib.redirect_stderr(err):
                        self.assertEqual(commit_lint.main(rng), 1)
                    self.assertIn("not a GitHub noreply address", err.getvalue())
                    self.assertNotIn("mail.example", err.getvalue())
                    git(repo, "reset", "-q", "--hard", base)
            commit(repo, GOOD_MSG, env={**GIT_ENV, "GIT_COMMITTER_EMAIL": "noreply@github.com"})
            self.assertEqual(commit_lint.main(rng), 0)

    def test_record_separator_in_message_cannot_split_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: jvc0n")
            base = git(repo, "rev-parse", "HEAD").strip()
            evil = ("feat: x\n\nAgent: jvc0n\x1e\x1f" + commit_lint.DEPENDABOT_EMAIL
                    + "\x1fchore: y\n\nAgent: claude/opus-5.5")
            commit(repo, evil)
            rng = ["--repo", tmp, "--range", f"{base}..HEAD", "--dependabot-pr"]
            self.assertEqual(commit_lint.main(rng), 1)


def map_readme(paths) -> str:
    """A README whose repository map names exactly the components of paths."""
    rows = "".join(f"| `{c}` | x |\n" for c in sorted(docs_budget.components(set(paths))))
    return "# x\n\n## Repository map\n\n| Path | Purpose |\n|---|---|\n" + rows


class DocsBudgetTest(unittest.TestCase):
    def _repo_with(self, files: dict[str, str | bytes]) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory()
        repo = new_repo(tmp.name)
        files = dict(files)
        files.setdefault("README.md", map_readme(files))
        for name, content in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
            git(repo, "add", name)
        return tmp

    def test_allowlisted_paths_pass(self):
        files = {"adr/0001-x.md": "b\n", "tools/ci/x.py": "c\n", "LICENSE": "d\n"}
        with self._repo_with(files) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)

    def test_unknown_paths_fail_whatever_suffix(self):
        for name in ("NOTES", "docs/PLAN.org", "docs/plan.mdx", "docs/plan.html", "src/x.py"):
            with self.subTest(name=name), self._repo_with({name: "x\n"}) as tmp:
                self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_a_mutation_directive_fails(self):
        for directive in ("// mutator-disable-func", "// mutator-disable-next-line", "//mutator-disable-regexp x"):
            with self.subTest(directive=directive):
                with self._repo_with({"internal/detect/x.go": f"package detect\n\n{directive}\nfunc f() {{}}\n"}) as tmp:
                    self.assertEqual(docs_budget.main(["--repo", tmp]), 1)
        with self._repo_with({"internal/detect/x.go": "package detect\n\nfunc f() {}\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)

    def test_lab_data_paths(self):
        window = "lab/windows/20261116t163124z-ba1549c1-dev-1-tech-a"
        files = {"lab/pairs/dev-1.json": "{}\n", "lab/rules/dev-1/opus-1.json": "{}\n",
                 f"{window}/result.json": "{}\n", f"{window}/job-laurel.txt": "x", f"{window}/job-out.txt": "x",
                 f"{window}/serial.txt": "x", f"{window}/serial-1.txt": "x", f"{window}/serial-12.txt": "x",
                 "lab/results/2026-11-20.json": "{}\n", "lab/agent-errors.jsonl": "{}\n"}
        with self._repo_with(files) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)
        for name in ("lab/windows/20261116T163124Z-ba1549c1-x/result.json", "lab/windows/a-1/result.json",
                     "lab/windows/20261116t163124z-ba1549c1/result.json",
                     "lab/windows/20261116t163124z-ba1549c-x/job-out.txt",
                     "lab/windows/20261116t163124z-ba1549c1-" + "a" * 65 + "/serial.txt",
                     "lab/windows/20261116t163124z-ba1549c1--x/serial.txt",
                     f"{window}/serial-0.txt", f"{window}/serial-01.txt", f"{window}/serial-.txt",
                     f"{window}/other.txt", f"{window}/result.txt", f"{window}/job-laurel.json",
                     f"{window}/serial.txt-x", f"{window}/result.json-x", f"{window}/job-laurel.txt.bak",
                     "lab/pairs/dev-1.toml", "lab/job-laurel.txt", "lab/serial.txt", f"{window}/x/job-laurel.txt",
                     "tools/ci/job-laurel.txt", "lab/rules/dev-1/x/opus-1.json", "cmd/job-laurel.txt/main.go",
                     "lab/windows/job-laurel.txt/result.json", f"{window}/serial.txt/result.json",
                     "lab/rules/serial.txt/opus-1.json", "lab/pairs/serial.txt", "lab/results/job-out.txt",
                     "cmd/LICENSE/main.go", "internal/CODEOWNERS/x.go"):
            with self.subTest(name=name), self._repo_with({name: "x\n"}) as tmp:
                self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_lab_blobs_are_printable_ascii_and_lf(self):
        window = "lab/windows/20261116t163124z-ba1549c1-dev-1-tech-a"
        self.assert_budget({f"{window}/job-out.txt": bytes(range(0x20, 0x7f)) + b"\n\n"}, 0)
        for content in (b"x\x00y", b"\x7fELF\x02\x01\x01\x00", b"\x89PNG\r\n\x1a\n", b"\x1f\x8b\x08\x00",
                        "café\n".encode(), b"x\xffy", b"x\ry", b"x\ty", b"x\x1b[2Jy"):
            for name in (f"{window}/job-out.txt", f"{window}/result.json", "lab/pairs/dev-1.json",
                         "lab/agent-errors.jsonl"):
                with self.subTest(name=name, content=content):
                    self.assert_budget({name: content}, 1)

    def test_binary_lab_blob_in_an_intermediate_commit_fails_the_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / "README.md").write_text(map_readme(["lab/pairs/dev-1.json"]))
            (repo / "lab/pairs").mkdir(parents=True)
            (repo / "lab/pairs/dev-1.json").write_text("{}\n")
            git(repo, "add", ".")
            git(repo, "commit", "-q", "--no-verify", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()
            for content in (b"{}\x00\n", b"{}\n"):
                (repo / "lab/pairs/dev-1.json").write_bytes(content)
                git(repo, "commit", "-q", "--no-verify", "-am", "x")
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)
            self.assertEqual(docs_budget.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    # ADR 0079 point 9: every blob under lab/ together, not one file.
    def test_lab_holds_at_most_16_mib(self):
        half = 8 << 20
        for extra, expected in ((0, 0), (1, 1)):
            with self.subTest(extra=extra):
                self.assert_budget({"lab/rules/dev-1/opus-1.json": b"x" * half,
                                    "lab/pairs/dev-1.json": b"x" * (half - 1 + extra) + b"\n",
                                    "tools/ci/big.py": "#" + "x" * half + "\n"}, expected)

    def assert_budget(self, files: dict[str, str | bytes], expected: int) -> None:
        with self._repo_with(files) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), expected)

    def test_star_does_not_cross_directories(self):
        with self._repo_with({"tools/ci/deep/x.py": "c\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_byte_cap_fails_single_long_line(self):
        with self._repo_with({"STATUS.md": "x" * 200_000 + "\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_blob_size_is_measured_not_checkout(self):
        # UTF-16 in the working tree is smaller than the UTF-8 blob for this character.
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / ".gitattributes").write_text("STATUS.md working-tree-encoding=UTF-16LE\n")
            (repo / "STATUS.md").write_bytes(("\u20ac" * 1700).encode("utf-16-le"))
            (repo / "README.md").write_text(map_readme([]))
            git(repo, "add", ".gitattributes", "STATUS.md", "README.md")
            self.assertLess((repo / "STATUS.md").stat().st_size, 4800)
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_names_that_gitleaks_would_skip_fail(self):
        for name in ("tools/ci/gitleaks.toml.py", "tools/ci/tests/test_verification-metadata.xml.py",
                     "tools/ci/Upper.py", "adr/0003-gitleaks.toml.md", "adr/0003-Database-refactorlog.md",
                     "adr/0003-verification-metadata.xml.md", ".github/workflows/gitleaks.toml.yml"):
            with self.subTest(name=name), self._repo_with({name: "x\n"}) as tmp:
                self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_submodule_entry_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / "README.md").write_text(map_readme(["tools/ci/tests/test_sub.py"]))
            git(repo, "add", "README.md")
            git(repo, "update-index", "--add", "--cacheinfo",
                "160000," + "a" * 40 + ",tools/ci/tests/test_sub.py")
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_symlink_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            os.symlink("LICENSE", repo / "README.md")
            git(repo, "add", "README.md")
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_unlisted_doc_fails(self):
        with self._repo_with({"README.md": "a\n", "docs/PLAN.md": "b\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_unlisted_txt_fails(self):
        with self._repo_with({"NOTES.txt": "b\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_bad_adr_name_fails(self):
        with self._repo_with({"adr/notes.md": "b\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_over_cap_fails(self):
        with self._repo_with({"STATUS.md": "x\n" * 41}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)


REPO_ROOT = Path(__file__).resolve().parents[3]
GO_MOD = "module github.com/example/balistid\n\ngo 1.27\n\ntoolchain go1.27.1\n"
GO_SUM_LINE = "golang.org/x/sys v0.20.0/go.mod h1:" + "A" * 43 + "="


class RepositoryMapTest(unittest.TestCase):
    _repo_with = DocsBudgetTest._repo_with
    files = {"adr/0001-x.md": "b\n", "tools/ci/x.py": "c\n", "cmd/balistid/main.go": "package main\n"}

    def budget(self, readme: str) -> int:
        with self._repo_with({**self.files, "README.md": readme}) as tmp:
            return docs_budget.main(["--repo", tmp])

    def test_complete_map_passes(self):
        self.assertEqual(self.budget(map_readme(self.files)), 0)

    def test_missing_row_fails(self):
        self.assertEqual(self.budget(map_readme(self.files).replace("| `cmd/balistid/` | x |\n", "")), 1)

    def test_row_for_untracked_path_fails(self):
        self.assertEqual(self.budget(map_readme(self.files) + "| `cmd/gone/` | x |\n"), 1)

    def test_mention_outside_the_table_or_first_column_does_not_count(self):
        readme = map_readme(self.files).replace("| `cmd/balistid/` | x |\n", "| x | `cmd/balistid/` |\n")
        self.assertEqual(self.budget(readme + "\nSee `cmd/balistid/`.\n"), 1)

    def test_missing_readme_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / "LICENSE").write_text("x\n")
            git(repo, "add", "LICENSE")
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_components(self):
        paths = {"LICENSE", "cmd/x.go", "tools/ci/tests/t.py", ".github/workflows/c.yml", "internal/a/b/x.go"}
        self.assertEqual(docs_budget.components(paths), {"cmd/", "tools/ci/", ".github/", "internal/a/"})

    def test_row_for_missing_file_fails(self):
        self.assertEqual(self.budget(map_readme(self.files) + "| `GONE.md` | x |\n"), 1)

    def test_each_commit_of_a_range_needs_its_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / "README.md").write_text(map_readme(["LICENSE"]))
            (repo / "LICENSE").write_text("x\n")
            git(repo, "add", "README.md", "LICENSE")
            git(repo, "commit", "-q", "--no-verify", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()
            (repo / "cmd/balistid").mkdir(parents=True)
            (repo / "cmd/balistid/main.go").write_text("package main\n")
            git(repo, "add", "cmd/balistid/main.go")
            git(repo, "commit", "-q", "--no-verify", "-m", "code without its row")
            (repo / "README.md").write_text(map_readme(["LICENSE", "cmd/balistid/main.go"]))
            git(repo, "commit", "-q", "--no-verify", "-am", "row")
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)
            self.assertEqual(docs_budget.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    def test_map_under_another_heading_does_not_count(self):
        self.assertEqual(self.budget(map_readme(self.files).replace("## Repository map", "## Map")), 1)


# The collector's socket unit as deployed (ADR 0016): its sha256 is pinned in docs_budget (ADR 0003).
SOCKET_UNIT = (Path(__file__).resolve().parents[3] / "deploy/collector/balistid-collector.socket").read_text()


class GoLayoutTest(unittest.TestCase):
    """ADR 0003: the Go and deployment layout, and the files gitleaks would skip."""

    _repo_with = DocsBudgetTest._repo_with

    def assert_budget(self, files: dict[str, str], expected: int) -> None:
        with self._repo_with(files) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), expected, files)

    def test_go_and_deploy_paths_pass(self):
        self.assert_budget({
            "go.mod": GO_MOD + "\nrequire (\n\tgolang.org/x/sys v0.20.0 // indirect\n)\n",
            "go.sum": GO_SUM_LINE + "\n",
            ".golangci.yml": "version: \"2\"\n",
            "cmd/balistid/main.go": "package main\n",
            "internal/store/shard.go": "package store\n",
            "internal/store/seal/seal_test.go": "package seal\n",
            "internal/store/testdata/leaf.json": "{}\n",
            "internal/store/seal/testdata/vectors.jsonl": "{}\n",
            "cmd/balistid/testdata/args.json": "{}\n",
            "packaging/laurel/PKGBUILD": "pkgname=laurel\n",
            "deploy/audit/balistid.rules": "-e 2\n",
            "deploy/auditd/auditd.conf": "q_depth = 2000\n",
            "deploy/laurel/config.toml": "[auditlog]\n",
            "deploy/auditd/laurel-plugin.conf": "active = yes\n",
            "deploy/sysctl/balistid.conf": "kernel.io_uring_disabled = 2\n",
            "deploy/systemd/balistid-collector.service": "[Service]\n",
            "deploy/systemd/balistid-verify.timer": "[Timer]\n",
            "deploy/runner/sysusers.conf": "g x -\n",
            "deploy/runner/tmpfiles.conf": "d /x 0755 root root -\n",
            "deploy/runner/balistid-runner-build.service": "[Service]\n",
            "deploy/runner/balistid-runner-tick.service": "[Service]\n",
            "deploy/runner/balistid-runner-tick.timer": "[Timer]\n",
            "deploy/install/allowed_signers": "maintainer@balistid.dev\n",
            "deploy/collector/sysusers.conf": "u x -\n",
            "deploy/collector/tmpfiles.conf": "d /x 0700 x x -\n",
            "deploy/collector/balistid-collector.service": "[Service]\n",
            "deploy/collector/balistid-collector.socket": SOCKET_UNIT,
            "range/mkosi.conf": "[Distribution]\n",
            "range/balistid-range-guest.service": "[Unit]\n",
        }, 0)

    def test_paths_outside_the_go_layout_fail(self):
        for name in ("cmd/balistid/deep/x.go", "internal/a/b/c/x.go", "cmd/x.go", "internal/x.go",
                     "internal/a/go.mod", "go.work", "testdata/x.json", "internal/a/x.json",
                     "internal/a/testdata/deep/x.json", "packaging/PKGBUILD",
                     "packaging/laurel/build.sh", "deploy/audit/balistid.conf",
                     "deploy/systemd/balistid.socket", "deploy/systemd/sub/x.service",
                     "deploy/auditd/other.conf", "src/main.go", "range/mkosi.postinst",
                     "range/mkosi.extra/etc/x.conf", "range/other.conf", "range/sub/x.service",
                     "range/mkosi.conf.d/x.conf", "range/x.timer", "range/x.service",
                     "deploy/sysctl/other.conf", "deploy/auditd/other-plugin.conf",
                     "deploy/runner/other.conf", "deploy/runner/balistid-runner.service",
                     "deploy/runner/balistid-runner-tick.socket", "deploy/runner/sub/tmpfiles.conf",
                     "deploy/install/other", "deploy/install/allowed_signers.pub",
                     "deploy/collector/other.socket", "deploy/collector/other.conf",
                     "deploy/collector/sub/balistid-collector.socket"):
            with self.subTest(name=name):
                self.assert_budget({name: "x\n"}, 1)

    def test_testdata_names_gitleaks_skips_fail(self):
        for name in ("internal/a/testdata/package-lock.json", "internal/a/testdata/javascript.json",
                     "cmd/x/testdata/npm-shrinkwrap.json"):
            with self.subTest(name=name):
                self.assert_budget({name: "{}\n"}, 1)

    def test_go_mod_outside_its_grammar_fails(self):
        for extra in ("replace golang.org/x/sys => ../sys", "// ghp_" + "a" * 36,
                      "exclude golang.org/x/sys v0.1.0", "godebug default=go1.21",
                      "tool golang.org/x/tools/cmd/stringer", "require x v1 // note",
                      "module github.com/example/balistid // c"):
            with self.subTest(extra=extra):
                self.assert_budget({"go.mod": GO_MOD + extra + "\n"}, 1)

    def test_go_sum_outside_its_grammar_fails(self):
        for line in ("token=" + "a" * 40, GO_SUM_LINE + " extra", GO_SUM_LINE.replace("h1:", "h2:"),
                     GO_SUM_LINE[:-2] + "=", "# comment"):
            with self.subTest(line=line):
                self.assert_budget({"go.sum": GO_SUM_LINE + "\n" + line + "\n"}, 1)

    def test_socket_unit_other_than_pinned_fails(self):
        path = "deploy/collector/balistid-collector.socket"
        self.assert_budget({path: SOCKET_UNIT}, 0)
        for content in (SOCKET_UNIT + "\n", SOCKET_UNIT + "Description=api key AbCd\n", SOCKET_UNIT[:-1],
                        SOCKET_UNIT.replace("0660", "0666"), ""):
            with self.subTest(content=content[-30:]):
                self.assert_budget({path: content}, 1)

    def test_line_outside_the_allowlist_in_a_root_installed_file_fails(self):
        for name in ("deploy/collector/tmpfiles.conf", "deploy/runner/balistid-runner-tick.service",
                     "deploy/audit/balistid.rules", "range/mkosi.conf", "packaging/laurel/PKGBUILD"):
            too_long = "# " + "x" * (299 if name.startswith("range/") else 199)
            for line in ("# x\x00User=root", "# x\rUser=root", "# x\x1bUser=root", "# c\u2028NoNewPrivileges=yes",
                         "# c\x85NoNewPrivileges=yes", "NoNewPrivileges=yes\u00a0", "\ufeff[Service]", too_long,
                         "-k balistid-exec\tx"):
                with self.subTest(name=name, line=line[:12]):
                    self.assert_budget({name: line + "\n"}, 1)
        self.assert_budget({"deploy/collector/tmpfiles.conf": "# x dirs " + "x" * 190 + "\n"}, 0)

    # Only the range image's files get 300 bytes a line; the installed ones keep 200 (docs_budget.line_cap).
    def test_range_lines_may_run_to_300_bytes_installed_ones_to_200(self):
        self.assert_budget({"range/balistid-collector-range.conf": "# " + "x" * 298 + "\n"}, 0)
        for name in ("deploy/collector/balistid-collector.service", "packaging/laurel/PKGBUILD"):
            with self.subTest(name=name):
                self.assert_budget({name: "# " + "x" * 199 + "\n"}, 1)

    def test_non_ascii_go_mod_fails(self):
        self.assert_budget({"go.mod": GO_MOD + "​\n"}, 1)

    # range/witness is under range/ (root-installed): its go.mod and go.sum take the root's grammar
    # instead of the printable-line rule, so a tab passes and anything outside the grammar fails.
    def test_range_witness_module_takes_the_root_grammar(self):
        tabbed = GO_MOD + "\nrequire (\n\tgolang.org/x/sys v0.20.0 // indirect\n)\n"
        self.assert_budget({"range/witness/go.mod": tabbed, "range/witness/go.sum": GO_SUM_LINE + "\n"}, 0)
        self.assert_budget({"range/witness/go.mod": GO_MOD + "replace x => ../x\n"}, 1)
        self.assert_budget({"range/witness/go.sum": GO_SUM_LINE + "\n# comment\n"}, 1)
        self.assert_budget({"range/witness/go.work": "go 1.27\n"}, 1)



class GoLayoutMoreTest(unittest.TestCase):
    _repo_with = DocsBudgetTest._repo_with
    assert_budget = GoLayoutTest.assert_budget

    def test_every_testdata_pattern_admits_its_files(self):
        for name in ("cmd/balistid/testdata/a.jsonl", "internal/store/testdata/a.jsonl",
                     "internal/store/seal/testdata/a.json", "internal/store/seal/testdata/b.jsonl"):
            with self.subTest(name=name):
                self.assert_budget({name: "{}\n"}, 0)

    def test_go_under_testdata_fails(self):
        for name in ("internal/buildinfo/testdata/bad.go", "cmd/balistid/testdata/x.go"):
            with self.subTest(name=name):
                self.assert_budget({name: "package x\n"}, 1)

    def test_go_paths_gitleaks_skips_fail(self):
        for name in ("internal/vendor/ruby/x.go", "internal/node_modules/x.go", "internal/env/lib/x.go",
                     "internal/bower_components/x.go"):
            with self.subTest(name=name):
                self.assert_budget({name: "package x\n"}, 1)

    def test_empty_go_sum_passes(self):
        self.assert_budget({"go.mod": GO_MOD, "go.sum": ""}, 0)


def history_with_secret_in_go_mod(tmp: str) -> tuple[Path, str]:
    """main: a clean go.mod; then commit A adds a token line, commit B removes it again."""
    repo = new_repo(tmp)
    (repo / "go.mod").write_text(GO_MOD)
    (repo / "README.md").write_text(map_readme(["go.mod"]))
    git(repo, "add", "go.mod", "README.md")
    git(repo, "commit", "-q", "--no-verify", "-m", "base")
    base = git(repo, "rev-parse", "HEAD").strip()
    (repo / "go.mod").write_text(GO_MOD + "// ghp_" + "a" * 36 + "\n")
    git(repo, "commit", "-q", "--no-verify", "-am", "a")
    (repo / "go.mod").write_text(GO_MOD)
    git(repo, "commit", "-q", "--no-verify", "-am", "b")
    return repo, base


class RangeTest(unittest.TestCase):
    def test_secret_in_an_intermediate_commit_fails_the_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, base = history_with_secret_in_go_mod(tmp)
            self.assertEqual(docs_budget.main(["--repo", str(repo)]), 0)
            self.assertEqual(docs_budget.main(["--repo", str(repo), "--range", f"{base}..HEAD"]), 1)

    def test_clean_range_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, base = history_with_secret_in_go_mod(tmp)
            self.assertEqual(docs_budget.main(["--repo", str(repo), "--range", "HEAD~1..HEAD"]), 0)

    def test_empty_range_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _base = history_with_secret_in_go_mod(tmp)
            with self.assertRaises(SystemExit):
                docs_budget.main(["--repo", str(repo), "--range", "HEAD..HEAD"])


class RescanTest(unittest.TestCase):
    def test_every_commit_of_a_skipped_file_is_copied_under_a_neutral_name(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            repo, base = history_with_secret_in_go_mod(tmp)
            written = rescan_skipped.extract(repo, f"{base}..HEAD", Path(out) / "r")
            self.assertEqual([p for _c, p, _t in written], ["go.mod", "go.mod"])
            self.assertTrue(any(b"ghp_" in t.read_bytes() for _c, _p, t in written))
            for _c, _p, target in written:
                self.assertRegex(target.name, r"^\d+\.txt$")
                self.assertFalse(rescan_skipped.skipped(target.name))

    def test_files_gitleaks_scans_are_not_copied(self):
        self.assertFalse(rescan_skipped.skipped("cmd/balistid/main.go"))
        self.assertTrue(rescan_skipped.skipped(".gitleaks.toml"))
        self.assertTrue(rescan_skipped.skipped("go.sum"))



class GoGateTest(unittest.TestCase):
    MOD = "module m\n\ngo 1.27\n\ntoolchain go1.27.1\n"

    def test_pinned_toolchain_passes(self):
        self.assertEqual(go_gate.toolchain_problems(self.MOD, "go1.27.1", "1.27.1"), [])

    def test_toolchain_mismatches_fail(self):
        cases = [(self.MOD.replace("go1.27.1", "go1.27.9"), "go1.27.1"),
                 (self.MOD + "toolchain go1.27.1\n", "go1.27.1"),
                 (self.MOD + "toolchain go1.27.9\n", "go1.27.1"),
                 (self.MOD, "go1.27.1 X:nodwarf5"),
                 (self.MOD, "go1.27.2"),
                 (self.MOD.replace("go 1.27\n", ""), "go1.27.1"),
                 (self.MOD.replace("toolchain go1.27.1\n", ""), "go1.27.1")]
        for mod, version in cases:
            with self.subTest(mod=mod, version=version):
                self.assertTrue(go_gate.toolchain_problems(mod, version, "1.27.1"))

    def test_module_sum(self):
        good = '{"Path": "golang.org/x/vuln", "Version": "v1.8.0", "Sum": "h1:abc="}'
        self.assertEqual(go_gate.modsum_problems(good, "h1:abc="), [])
        for bad in (good.replace("abc", "abd"), '{"Error": "not found"}', "not json", "{}",
                    '{"Sum": "h1:abc=", "Error": "checksum mismatch"}'):
            with self.subTest(bad=bad):
                self.assertTrue(go_gate.modsum_problems(bad, "h1:abc="))

    def test_builds_must_match(self):
        self.assertEqual(go_gate.same_problems(b"x", b"x"), [])
        self.assertTrue(go_gate.same_problems(b"x", b"y"))


class OwnedDepsTest(unittest.TestCase):
    M = "example.com/balistid"
    OWNERS = ("# owned\n\n/range/ @Jvc0n\n/deploy/ @Jvc0n\n/packaging/ @Jvc0n\n/cmd/balistid-range/ @Jvc0n\n"
              "/cmd/balistid-range-guest/ @Jvc0n\n/cmd/balistid-runner/ @Jvc0n\n/cmd/balistid/ @Jvc0n\n"
              "/cmd/balistid-collector/ @Jvc0n\n/cmd/balistid-ledger/ @Jvc0n\n/cmd/balistid-relay/ @Jvc0n\n"
              "/cmd/balistid-pi/ @Jvc0n\n/cmd/balistid-auditstat/ @Jvc0n\n/cmd/balistid-install/ @Jvc0n\n"
              "/cmd/balistid-judge/ @Jvc0n\n/cmd/balistid-lab/ @Jvc0n\n/internal/rangevm/ @Jvc0n\n")
    MOD = "module example.com/balistid\n\ngo 1.27\n\ntoolchain go1.27.1\n"

    def pkg(self, rel, **extra):
        return {"ImportPath": f"{self.M}/{rel}", "Module": {"Path": self.M, "Main": True}, **extra}

    def deps(self, *extra):
        pkgs = [{"ImportPath": "os", "Standard": True}, self.pkg("internal/rangevm"),
                self.pkg("cmd/balistid-range"), self.pkg("cmd/balistid-range-guest"),
                self.pkg("cmd/balistid-runner"), self.pkg("cmd/balistid"), self.pkg("cmd/balistid-collector"),
                self.pkg("cmd/balistid-ledger"), self.pkg("cmd/balistid-relay"), self.pkg("cmd/balistid-pi"),
                self.pkg("cmd/balistid-auditstat"), self.pkg("cmd/balistid-install"),
                self.pkg("cmd/balistid-judge"), self.pkg("cmd/balistid-lab"), *extra]
        return "\n".join(json.dumps(p, indent=1) for p in pkgs)

    def problems(self, deps=None, owners=None, mod=None):
        return go_gate.owned_problems(self.deps() if deps is None else deps,
                                      self.OWNERS if owners is None else owners,
                                      self.MOD if mod is None else mod)

    def test_owned_tree_passes(self):
        self.assertEqual(self.problems(), [])

    def test_unowned_package_fails(self):
        self.assertTrue(self.problems(deps=self.deps(self.pkg("internal/util"))))

    def test_subpackage_of_owned_dir_passes(self):
        self.assertEqual(self.problems(deps=self.deps(self.pkg("internal/rangevm/sub"))), [])

    def test_foreign_or_lookalike_packages_fail(self):
        cases = [{"ImportPath": "example.com/x", "Module": {"Path": "example.com/x"}},
                 {"ImportPath": f"{self.M}-evil/x", "Module": {"Path": self.M, "Main": True}},
                 {"ImportPath": f"{self.M}/internal/rangevm/v", "Module": {"Path": self.M}},
                 {"ImportPath": "os"}]
        for pkg in cases:
            with self.subTest(pkg=pkg):
                self.assertTrue(self.problems(deps=self.deps(pkg)))

    def test_missing_root_or_bad_input_fails(self):
        for deps in ("", "[]", "not json", json.dumps(self.pkg("internal/rangevm"))):
            with self.subTest(deps=deps):
                self.assertTrue(self.problems(deps=deps))

    def test_module_comes_from_go_mod(self):
        for mod in ("", "go 1.27\n", self.MOD.replace("example.com/balistid", "example.com/other"),
                    self.MOD + "module example.com/balistid\n"):
            with self.subTest(mod=mod):
                self.assertTrue(self.problems(mod=mod))

    def test_unowned_image_path_fails(self):
        for path in go_gate.OWNED_PATHS:
            with self.subTest(path=path):
                self.assertTrue(self.problems(owners=self.OWNERS.replace(f"/{path}/ @Jvc0n\n", "")))

    def test_lines_that_could_take_an_owner_away_fail(self):
        for line in ("/internal/", "/internal/rangevm/session.go", "/range/mkosi.conf  ",
                     "/internal/rangevm/ #@Jvc0n", "/internal/rangevm/\u00a0@Jvc0n", "/internal/rangevm/\t@Jvc0n",
                     "/internal/rangevm/ @agent-bot", "/internal/rangevm/ @Jvc0n @agent-bot",
                     "/internal/rangevm/ @Jvc0n # note", " /internal/rangevm/ @Jvc0n"):
            with self.subTest(line=line):
                self.assertTrue(self.problems(owners=self.OWNERS + line + "\n"))

    def test_owner_line_hidden_in_a_comment_fails(self):
        for sep in ("\u2028", "\u0085", "\r", "\f"):
            with self.subTest(sep=sep):
                owners = self.OWNERS.replace("/range/ @Jvc0n\n", "") + f"# x{sep}/range/ @Jvc0n\n"
                self.assertTrue(self.problems(owners=owners))

    def test_patterns_it_cannot_evaluate_fail(self):
        for line in ("* @Jvc0n", "*.go @Jvc0n", "internal/ @Jvc0n", "/internal/**/x @Jvc0n",
                     "/a/../range/ @Jvc0n", "/ @Jvc0n"):
            with self.subTest(line=line):
                self.assertTrue(self.problems(owners=self.OWNERS + line + "\n"))

    def setUp(self):
        # The listed module's licence file lives in a temporary module directory, pinned by its hash.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.licence = Path(tmp.name) / "LICENSE"
        self.licence.write_bytes(b"BSD licence\n")
        pin = ("LICENSE", "BSD-3-Clause", hashlib.sha256(b"BSD licence\n").hexdigest())
        patcher = mock.patch.dict(go_gate.ALLOWED_MODULES, {"modernc.org/sqlite@v1.60.1": pin})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.SQLITE = {"Path": "modernc.org/sqlite", "Version": "v1.60.1", "Dir": tmp.name}

    def test_listed_module_at_its_version_passes(self):
        deps = self.deps({"ImportPath": "modernc.org/sqlite", "Module": self.SQLITE},
                         {"ImportPath": "modernc.org/sqlite/lib", "Module": self.SQLITE})
        self.assertEqual(self.problems(deps=deps), [])

    def test_module_off_the_list_fails(self):
        listed = {"ImportPath": "modernc.org/sqlite", "Module": self.SQLITE}
        self.assertEqual(self.problems(deps=self.deps(listed)), [])  # the variants below differ in one thing
        cases = [{"ImportPath": "modernc.org/sqlite", "Module": {**self.SQLITE, "Version": "v1.60.2"}},
                 {"ImportPath": "modernc.org/sqlite", "Module": {"Path": "modernc.org/sqlite"}},
                 {"ImportPath": "example.com/x", "Module": {"Path": "example.com/x", "Version": "v1.0.0"}},
                 {"ImportPath": "modernc.org/sqlite",
                  "Module": {**self.SQLITE, "Replace": {"Path": "example.com/fork", "Version": "v1.0.0"}}},
                 {"ImportPath": "modernc.org/sqlite", "Module": {**self.SQLITE, "Main": True}},
                 {"ImportPath": "modernc.org/sqlite-evil/x", "Module": self.SQLITE},
                 {"ImportPath": "example.com/x", "Module": self.SQLITE},
                 {"ImportPath": "modernc.org/sqlite"}]
        for pkg in cases:
            with self.subTest(pkg=pkg):
                self.assertTrue(self.problems(deps=self.deps(pkg)))

    def test_allowed_modules_are_what_go_mod_requires(self):
        root = Path(__file__).resolve().parents[3]
        go_mod = (root / "go.mod").read_text()
        required = {f"{m}@{v}" for m, v in re.findall(r"^\s*(?:require )?(\S+) (v\S+)", go_mod, re.M)}
        self.assertEqual(set(go_gate.ALLOWED_MODULES) - required, set())

    def test_changed_or_missing_licence_file_fails(self):
        sqlite = {"ImportPath": "modernc.org/sqlite", "Module": self.SQLITE}
        self.assertEqual(self.problems(deps=self.deps(sqlite)), [])
        self.licence.write_bytes(b"GPL licence\n")
        self.assertTrue(self.problems(deps=self.deps(sqlite)))
        self.licence.unlink()
        self.assertTrue(self.problems(deps=self.deps(sqlite)))
        nodir = {"ImportPath": "modernc.org/sqlite", "Module": {"Path": "modernc.org/sqlite", "Version": "v1.60.1"}}
        self.assertTrue(self.problems(deps=self.deps(nodir)))

    def test_licence_off_the_list_fails(self):
        sqlite = {"ImportPath": "modernc.org/sqlite", "Module": self.SQLITE}
        digest = hashlib.sha256(self.licence.read_bytes()).hexdigest()
        lru = "github.com/hashicorp/golang-lru/v2"
        cases = {"modernc.org/sqlite@v1.60.1": ("modernc.org/sqlite", "v1.60.1", "GPL-3.0-only"),
                 "modernc.org/sqlite@v1.60.1 ": ("modernc.org/sqlite", "v1.60.1", "MPL-2.0"),
                 f"{lru}@v2.0.8": (lru, "v2.0.8", "MPL-2.0")}
        for name, (path, version, spdx) in cases.items():
            with self.subTest(case=name), mock.patch.dict(go_gate.ALLOWED_MODULES,
                                                         {f"{path}@{version}": ("LICENSE", spdx, digest)}):
                pkg = {"ImportPath": path, "Module": {**self.SQLITE, "Path": path, "Version": version}}
                self.assertTrue(self.problems(deps=self.deps(pkg)))
        self.assertEqual(self.problems(deps=self.deps(sqlite)), [])

    def test_every_pinned_licence_is_allowed(self):
        for key, (_, spdx, digest) in go_gate.ALLOWED_MODULES.items():
            with self.subTest(module=key):
                self.assertTrue(spdx in go_gate.LICENCES or (key, spdx) == go_gate.LICENCE_EXCEPTION)
                self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_our_code_cannot_import_the_mpl_module(self):
        root = Path(__file__).resolve().parents[3]
        self.assertIn("pkg: github.com/hashicorp/golang-lru", (root / ".golangci.yml").read_text())

    # The binaries root installs are in the gate, and CI lists exactly the gate's roots (ADR 0011).
    def test_gate_roots_match_ci(self):
        root = Path(__file__).resolve().parents[3]
        self.assertTrue({"cmd/balistid-runner", "cmd/balistid", "cmd/balistid-collector", "cmd/balistid-install",
                         "cmd/balistid-lab"} <= set(go_gate.OWNED_ROOTS))
        ci = (root / ".github/workflows/ci.yml").read_text()
        listed = [line for line in ci.splitlines() if "go list -deps -json" in line]
        self.assertEqual(len(listed), 1)
        args = sorted(a.removeprefix("./") for a in listed[0].split() if a.startswith("./cmd/"))
        self.assertEqual(args, sorted(go_gate.OWNED_ROOTS))

    def test_real_codeowners_is_evaluable(self):
        root = Path(__file__).resolve().parents[3]
        rules, problems = go_gate.codeowners_rules((root / ".github/CODEOWNERS").read_text())
        self.assertEqual(problems, [])
        for path in (*go_gate.OWNED_ROOTS, *go_gate.OWNED_PATHS):
            with self.subTest(path=path):
                self.assertTrue(go_gate.is_owned(path, rules))


class VulnScanTest(unittest.TestCase):
    def test_govulncheck_scans_every_witness_program(self):
        root = Path(__file__).resolve().parents[3]
        programs = re.findall(r'"range/witness", "([^"]+)"', (root / "internal/rangevm/session.go").read_text())
        scan = re.search(r'govulncheck@[^"]+" -C range/witness \\\n\s*([^\n]+)',
                         (root / ".github/workflows/ci.yml").read_text())
        self.assertTrue(programs)
        self.assertIsNotNone(scan)
        self.assertEqual(sorted(scan.group(1).split()), sorted(programs))


A_SHA, B_SHA, ZERO_SHA = "a" * 40, "b" * 40, "0" * 40


class ChangeRangeTest(unittest.TestCase):
    def test_pull_request_and_push_ranges(self):
        self.assertEqual(change_range.change_range("pull_request", A_SHA, B_SHA, "", ""), f"{A_SHA}..{B_SHA}")
        self.assertEqual(change_range.change_range("push", "", "", A_SHA, B_SHA), f"{A_SHA}..{B_SHA}")
        self.assertEqual(change_range.change_range("push", "", "", ZERO_SHA, B_SHA), B_SHA)

    def test_merge_group_range_is_the_groups_own(self):
        self.assertEqual(change_range.change_range("merge_group", "", "", "", "", A_SHA, B_SHA), f"{A_SHA}..{B_SHA}")
        for args in (("merge_group", A_SHA, B_SHA, A_SHA, B_SHA, "", ""),
                     ("merge_group", "", "", "", "", ZERO_SHA, B_SHA),
                     ("merge_group", "", "", "", "", A_SHA, ZERO_SHA),
                     ("merge_group", "", "", "", "", A_SHA[:7], B_SHA),
                     ("pull_request", "", "", "", "", A_SHA, B_SHA)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                change_range.change_range(*args)

    def test_unknown_or_missing_values_fail(self):
        for args in (("workflow_dispatch", A_SHA, B_SHA, A_SHA, B_SHA),
                     ("pull_request", "", B_SHA, "", ""), ("pull_request", A_SHA, "main", "", ""),
                     ("pull_request", ZERO_SHA, B_SHA, "", ""), ("push", "", "", A_SHA, ""),
                     ("push", "", "", A_SHA[:7], B_SHA), ("push", "", "", A_SHA, B_SHA + "\n"),
                     ("push", "", "", A_SHA, ZERO_SHA), ("pull_request", A_SHA, ZERO_SHA, "", "")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                change_range.change_range(*args)


def random_github_token() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


class RescanDetectionTest(unittest.TestCase):
    """The pinned gitleaks must find a token that only ever lived in an intermediate go.mod."""

    def gitleaks(self) -> str:
        path = os.environ.get("GITLEAKS", "")
        if not path or not os.access(path, os.X_OK):
            raise AssertionError("set GITLEAKS to the pinned gitleaks binary; this test does not skip")
        return path

    def scan(self, go_mod_line: str) -> int:
        """Build the history, then run the rescan exactly as the secrets job does."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / "go.mod").write_text(GO_MOD)
            git(repo, "add", "go.mod")
            git(repo, "commit", "-q", "--no-verify", "-m", "base")
            (repo / "go.mod").write_text(GO_MOD + go_mod_line + "\n")
            git(repo, "commit", "-q", "--no-verify", "-am", "a")
            (repo / "go.mod").write_text(GO_MOD)
            git(repo, "commit", "-q", "--no-verify", "-am", "b")
            return rescan_skipped.main(["--repo", str(repo), "--range", "HEAD",
                                        "--gitleaks", self.gitleaks(),
                                        "--config", str(REPO_ROOT / ".gitleaks.toml")])

    def test_token_in_an_intermediate_go_mod_is_found(self):
        self.assertNotEqual(self.scan("// " + random_github_token()), 0)

    def test_repository_rules_apply(self):
        # Fails if the rescan drops --config: host-home-path is a repository rule, not a default one.
        self.assertNotEqual(self.scan("// /home/" + "alice"), 0)

    def test_inline_allow_comments_are_ignored(self):
        # Fails if the rescan drops --ignore-gitleaks-allow.
        self.assertNotEqual(self.scan("// " + random_github_token() + " // gitleaks:allow"), 0)

    def test_clean_history_passes(self):
        self.assertEqual(self.scan(""), 0)

class GitleaksWindowTest(unittest.TestCase):
    """A window's result.json passes the secret scan only through its content_key line (ADR 0077)."""

    gitleaks = RescanDetectionTest.gitleaks

    def leaks(self, files: dict[str, str]) -> int:
        """Commit files and scan the history as the secrets job does (gitleaks git, repository paths)."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            for name, text in files.items():
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).write_text(text)
                git(repo, "add", name)
            git(repo, "commit", "-q", "--no-verify", "-m", "x")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return rescan_skipped.history(self.gitleaks(), REPO_ROOT / ".gitleaks.toml", repo)

    def test_content_key_path_is_the_layouts_window_id(self):
        config = tomllib.loads((REPO_ROOT / ".gitleaks.toml").read_text())
        paths = [p for a in config["allowlists"] if any("content_key" in r for r in a.get("regexes", []))
                 for p in a.get("paths", [])]
        self.assertEqual(paths, [rf"^lab/windows/{docs_budget.WINDOW_ID}/result\.json$"])

    def test_content_key_of_a_window_passes(self):
        key = secrets.token_hex(32)
        result = f'{{\n  "content_key": "{key}",\n  "program_sha256": "{secrets.token_hex(32)}"\n}}\n'
        self.assertEqual(self.leaks({"lab/windows/20261116t163124z-ba1549c1-x/result.json": result}), 0)
        base62 = random_github_token()[4:] + random_github_token()[4:32]
        for name, text in (("tools/ci/x.json", result), ("vendor/x/lab/windows/a-1/result.json", result),
                           ("lab/windows/a-1/result.json", result),
                           ("lab/windows/20261116t163124z-ba1549c1-x/job-out.txt", result),
                           ("lab/windows/20261116t163124z-ba1549c1-x/sub/result.json", result),
                           ("lab/windows/20261116t163124z-ba1549c1-x/result.json",
                            result.replace('"content_key"', '"api_key"')),
                           ("lab/windows/20261116t163124z-ba1549c1-x/result.json", result.replace(key, base62))):
            with self.subTest(name=name, text=text[:30]):
                self.assertNotEqual(self.leaks({name: text}), 0)


def printable(data: bytes) -> bytes:
    """The runner's escape, rangevm.Printable at 2c09799, byte by byte."""
    return b"".join(bytes([c]) if 0x20 <= c <= 0x7e and c not in b'\\"' else b"\\x%02x" % c for c in data)


WINDOW = "lab/windows/20261117t164346z-4e1197c7-hard-exec-1"


class WindowRescanTest(unittest.TestCase):
    """Every window text file in every commit is decoded and scanned with the repository rules (ADR 0079 point 3)."""

    gitleaks = RescanDetectionTest.gitleaks

    def api_key_record(self) -> bytes:
        """A Laurel-shaped line with a key generic-api-key finds as it stands; escaped, it finds none. A random key
        can hold one of the rule's stopwords, so the first of a few that the plain scan finds is taken."""
        for _ in range(20):
            key = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                          for _ in range(32))
            record = b'{"ID":"1794933833.971:186","EXECVE":{"api_key":"' + key.encode() + b'"}}\n'
            if subprocess.run([self.gitleaks(), "stdin", "--no-banner", "--config", str(REPO_ROOT / ".gitleaks.toml")],
                              input=record, capture_output=True, timeout=60).returncode == 1:
                return record
        raise AssertionError("gitleaks found none of 20 random keys in a plain record")

    def history(self, *trees: dict[str, bytes]) -> Path:
        """One commit per tree, each tree replacing the window's files."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        repo = new_repo(tmp.name)
        for tree in trees:
            git(repo, "rm", "-rq", "--ignore-unmatch", "lab")
            for name, data in tree.items():
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).write_bytes(data)
                git(repo, "add", name)
            git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-m", "x")
        return repo

    def rescan(self, repo: Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return rescan_skipped.main(["--repo", str(repo), "--range", "HEAD", "--gitleaks", self.gitleaks(),
                                        "--config", str(REPO_ROOT / ".gitleaks.toml")])

    def test_key_in_an_escaped_record_is_found_in_every_window_text_file(self):
        clean = printable(b'{"ID":"1794933833.971:186","SYSCALL":{"comm":"systemd-run","key":"balistid-exec"}}\n')
        for leaf in ("job-laurel.txt", "job-out.txt", "serial.txt", "serial-2.txt"):
            with self.subTest(leaf=leaf):
                self.assertEqual(self.rescan(self.history({f"{WINDOW}/{leaf}": clean})), 0)
                repo = self.history({f"{WINDOW}/{leaf}": clean + printable(self.api_key_record())},
                                    {f"{WINDOW}/{leaf}": clean})
                self.assertNotEqual(self.rescan(repo), 0)

    def test_a_go_sum_line_passes_only_in_go_sum(self):
        for _ in range(20):  # a random hash can miss the rule's entropy; take one the rule reads as a key
            line = ("github.com/example/token v1.1.0 h1:" + base64.b64encode(secrets.token_bytes(32)).decode()).encode() + b"\n"
            if self.rescan(self.history({f"{WINDOW}/serial.txt": printable(line)})) != 0:
                break
        else:
            raise AssertionError("generic-api-key read none of 20 go.sum lines as a key")
        self.assertEqual(self.rescan(self.history({"go.sum": line})), 0)

    def test_one_blob_as_a_result_and_as_text_is_checked_as_each(self):
        """A blob that decodes as a result.json still has the text escape checked where it is a .txt file."""
        blob = json.dumps({"reason": "ok"}).encode() + b"\n"  # a JSON string's quotes are no escape the runner writes
        repo = self.history({f"{WINDOW}/result.json": blob}, {f"{WINDOW}/result.json": blob, f"{WINDOW}/serial.txt": blob})
        with self.assertRaises(SystemExit):
            self.rescan(repo)

    def test_key_after_a_file_type_signature_is_found(self):
        for magic in (b"\x7fELF\x02\x01\x01\x00", b"PK\x03\x04", b"\x1f\x8b\x08", b"%PDF-1.4\n",
                      b"a" * 257 + b"ustar\x0000", b"SQLite format 3\x00"):
            with self.subTest(magic=magic[-8:]):
                repo = self.history({f"{WINDOW}/job-out.txt": printable(magic + b"\n" + self.api_key_record())})
                self.assertNotEqual(self.rescan(repo), 0)

    def test_what_the_escape_cannot_have_written_fails(self):
        good = printable(b'"a\\b\n\x00\xff')
        self.assertEqual(rescan_skipped.unescape(good), b'"a\\b\n\x00\xff')
        for data in (b'"', b"\\", b"a\\", b"\\x4", b"\\x4g", b"\\X22", b"\\x2A", b"\\x41", b"\\x5C", b"a\nb",
                     b"a\tb", b"\x80", "é".encode()):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    rescan_skipped.unescape(data)
                repo = self.history({f"{WINDOW}/serial-1.txt": data}, {f"{WINDOW}/serial-1.txt": good})
                with self.assertRaises(SystemExit):
                    self.rescan(repo)

    def test_only_window_files_are_decoded(self):
        self.assertTrue(rescan_skipped.window_text(f"{WINDOW}/serial-3.txt"))
        self.assertTrue(rescan_skipped.window_result(f"{WINDOW}/result.json"))
        for path in (f"{WINDOW}/result.json", "lab/serial.txt", "tools/ci/job-out.txt", f"{WINDOW}/x/job-out.txt"):
            with self.subTest(path=path):
                self.assertFalse(rescan_skipped.window_text(path))
        for path in ("lab/result.json", f"{WINDOW}/x/result.json", "lab/results/2026-11-20.json"):
            with self.subTest(path=path):
                self.assertFalse(rescan_skipped.window_result(path))

    def test_key_in_a_results_escaped_reason_is_found(self):
        """The runner escapes a result's reasons too (rangerun WriteResult); JSON then doubles each backslash."""
        reason = printable(self.api_key_record().rstrip(b"\n")).decode()
        clean = json.dumps({"id": "x", "reason": "the job ran", "runs": [{"reason": "ok"}]}).encode() + b"\n"
        bad = json.dumps({"id": "x", "reason": "the job ran", "runs": [{"reason": reason}]}).encode() + b"\n"
        self.assertEqual(self.rescan(self.history({f"{WINDOW}/result.json": clean})), 0)
        self.assertNotEqual(self.rescan(self.history({f"{WINDOW}/result.json": bad}, {f"{WINDOW}/result.json": clean})), 0)
        for data in (b"not json", json.dumps({"reason": "\\x4"}).encode(), b'{"reason":"x","reason":"ok"}\n'):
            with self.subTest(data=data):
                with self.assertRaises(SystemExit):
                    self.rescan(self.history({f"{WINDOW}/result.json": data}))


class HistoryScanTest(unittest.TestCase):
    """The git-mode scan of the whole history fails closed (ci.yml, secrets job)."""

    gitleaks = RescanDetectionTest.gitleaks

    def test_exit_code_error_line_or_no_commits_fail(self):
        ok = "\x1b[90m10:17AM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1m3 commits scanned.\x1b[0m\n"
        self.assertEqual(rescan_skipped.history_problems(0, ok), [])
        err = "\x1b[90m10:17AM\x1b[0m \x1b[31mERR\x1b[0m \x1b[1mfailed to scan\x1b[0m\n"
        for code, log in ((1, ok), (0, ok + err), (0, ok.replace("3 commits", "0 commits")), (0, ""),
                          (0, ok + ok), (0, ok.replace("3 commits", "3 commit"))):
            with self.subTest(code=code, log=log):
                self.assertTrue(rescan_skipped.history_problems(code, log))

    def test_a_gitleaksignore_fails_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, GOOD_MSG)
            (repo / ".gitleaksignore").write_text("x\n")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rescan_skipped.history(self.gitleaks(), REPO_ROOT / ".gitleaks.toml", repo), 1)

    def test_git_that_fails_fails_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as bindir:
            repo = new_repo(tmp)
            commit(repo, GOOD_MSG)
            fake = Path(bindir) / "git"
            fake.write_text("#!/bin/sh\nexit 128\n")
            fake.chmod(0o755)
            env = {**os.environ, "PATH": bindir + os.pathsep + os.environ["PATH"]}
            config = REPO_ROOT / ".gitleaks.toml"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rescan_skipped.history(self.gitleaks(), config, repo), 0)
                self.assertEqual(rescan_skipped.history(self.gitleaks(), config, repo, env=env), 1)


if __name__ == "__main__":
    unittest.main()
