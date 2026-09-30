"""Tests for tools/ci. Each rule has a passing case and at least one case that must fail."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import commit_lint  # noqa: E402
import docs_budget  # noqa: E402
import pin_check  # noqa: E402

GOOD_MSG = "feat(core): add event store\n\nBody text.\n\nAgent: claude/opus-5.5"
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
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

    def test_alex_trailer_passes(self):
        self.assertEqual(commit_lint.lint("fix: typo\n\nAgent: alex"), [])

    def test_missing_agent_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nbody"))

    def test_two_agent_trailers_fail(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\nAgent: claude/opus-5.5"))

    def test_malformed_agent_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: Claude Opus"))

    def test_lowercase_agent_key_counts_and_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nagent: alex"))

    def test_co_authored_by_fails(self):
        msg = GOOD_MSG + "\nCo-Authored-By: Claude <noreply@anthropic.com>"
        self.assertTrue(commit_lint.lint(msg))

    def test_generated_with_fails(self):
        self.assertTrue(commit_lint.lint(GOOD_MSG + "\nGenerated with Claude Code"))

    def test_robot_emoji_fails(self):
        self.assertTrue(commit_lint.lint(GOOD_MSG + "\n\U0001F916"))

    def test_non_conventional_subject_fails(self):
        self.assertTrue(commit_lint.lint("Add stuff\n\nAgent: alex"))

    def test_long_subject_fails(self):
        self.assertTrue(commit_lint.lint("feat: " + "a" * 80 + "\n\nAgent: alex"))

    def test_missing_blank_line_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\nbody\n\nAgent: alex"))

    def test_empty_fails(self):
        self.assertTrue(commit_lint.lint(""))

    def test_agent_outside_trailer_block_fails(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\n\nTrailing paragraph."))

    def test_scissors_block_is_ignored(self):
        msg = GOOD_MSG + "\n" + commit_lint.SCISSORS + "\n+Co-Authored-By: someone\n"
        self.assertEqual(commit_lint.lint(commit_lint.strip_comments(msg)), [])

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
            commit(repo, "chore: base\n\nAgent: alex")
            base = git(repo, "rev-parse", "HEAD").strip()
            commit(repo, GOOD_MSG)
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 0)
            commit(repo, "feat: sneaky\n\nAgent: alex\nCo-Authored-By: x <x@y>")
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    def test_empty_range_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, GOOD_MSG)
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", "HEAD..HEAD"]), 1)

    def test_merge_commit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: alex")
            base = git(repo, "rev-parse", "HEAD").strip()
            git(repo, "checkout", "-q", "-b", "side")
            commit(repo, GOOD_MSG, filename="g")
            git(repo, "checkout", "-q", "main")
            commit(repo, GOOD_MSG, filename="h")
            git(repo, "merge", "-q", "--no-ff", "--no-edit", "-m", "chore: merge\n\nAgent: alex", "side")
            self.assertEqual(commit_lint.main(["--repo", tmp, "--range", f"{base}..HEAD"]), 1)

    def test_dependabot_exempt_from_agent_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: alex")
            base = git(repo, "rev-parse", "HEAD").strip()
            bot = {**GIT_ENV, "GIT_AUTHOR_EMAIL": commit_lint.DEPENDABOT_EMAIL}
            commit(repo, "ci: bump actions/checkout from 1 to 2", env=bot)
            rng = ["--repo", tmp, "--range", f"{base}..HEAD"]
            self.assertEqual(commit_lint.main(rng + ["--dependabot-pr"]), 0)
            # A spoofed author email without GitHub's PR-author signal is not exempt.
            self.assertEqual(commit_lint.main(rng), 1)
            commit(repo, "Bump something", env=bot)
            self.assertEqual(commit_lint.main(rng + ["--dependabot-pr"]), 1)

    def test_record_separator_in_message_cannot_split_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            commit(repo, "chore: base\n\nAgent: alex")
            base = git(repo, "rev-parse", "HEAD").strip()
            evil = ("feat: x\n\nAgent: alex\x1e\x1f" + commit_lint.DEPENDABOT_EMAIL
                    + "\x1fchore: y\n\nAgent: claude/opus-5.5")
            commit(repo, evil)
            rng = ["--repo", tmp, "--range", f"{base}..HEAD", "--dependabot-pr"]
            self.assertEqual(commit_lint.main(rng), 1)


class DocsBudgetTest(unittest.TestCase):
    def _repo_with(self, files: dict[str, str]) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory()
        repo = new_repo(tmp.name)
        for name, content in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            git(repo, "add", name)
        return tmp

    def test_allowlisted_paths_pass(self):
        files = {"README.md": "a\n", "adr/0001-x.md": "b\n", "tools/ci/x.py": "c\n", "LICENSE": "d\n"}
        with self._repo_with(files) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 0)

    def test_unknown_paths_fail_whatever_suffix(self):
        for name in ("NOTES", "docs/PLAN.org", "docs/plan.mdx", "docs/plan.html", "src/x.py"):
            with self.subTest(name=name), self._repo_with({name: "x\n"}) as tmp:
                self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_star_does_not_cross_directories(self):
        with self._repo_with({"tools/ci/deep/x.py": "c\n"}) as tmp:
            self.assertEqual(docs_budget.main(["--repo", tmp]), 1)

    def test_byte_cap_fails_single_long_line(self):
        with self._repo_with({"STATUS.md": "x" * 200_000 + "\n"}) as tmp:
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


class PinCheckTest(unittest.TestCase):
    def _check(self, uses: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp, ".github/workflows")
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: {uses}\n")
            return pin_check.main(["--repo", tmp])

    def test_sha_pinned_passes(self):
        self.assertEqual(self._check("actions/checkout@" + "a" * 40), 0)

    def test_local_action_passes(self):
        self.assertEqual(self._check("./.github/actions/x"), 0)

    def test_tag_fails(self):
        self.assertEqual(self._check("actions/checkout@v5"), 1)

    def test_branch_fails(self):
        self.assertEqual(self._check("actions/checkout@main"), 1)

    def test_short_sha_fails(self):
        self.assertEqual(self._check("actions/checkout@abc1234"), 1)

    def test_docker_tag_fails(self):
        self.assertEqual(self._check("docker://alpine:3"), 1)

    def test_yaml_spelling_variants_fail(self):
        for line in ("- {uses: actions/checkout@v4}", "- uses : actions/checkout@v4",
                     "- 'uses': actions/checkout@v4", '- "uses": actions/checkout@main',
                     "- uses: 'actions/checkout@" + "a" * 40 + "'"):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as tmp:
                wf = Path(tmp, ".github/workflows")
                wf.mkdir(parents=True)
                (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      {line}\n")
                self.assertEqual(pin_check.main(["--repo", tmp]), 1)

    def test_flow_style_reusable_workflow_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp, ".github/workflows")
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text("jobs: {a: {uses: org/repo/.github/workflows/x.yml@main}}\n")
            self.assertEqual(pin_check.main(["--repo", tmp]), 1)

    def test_no_workflows_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(pin_check.main(["--repo", tmp]), 1)


if __name__ == "__main__":
    unittest.main()
