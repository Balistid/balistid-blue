"""Tests for tools/ci. Each rule has a passing case and at least one case that must fail."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

    def test_agent_value_is_checked_as_git_parses_it(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\n really claude/opus wrote it"))

    def test_line_separator_characters_fail(self):
        self.assertTrue(commit_lint.lint("feat: x\x0b\x0bfree text\n\nAgent: alex"))
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\u2028claude/opus-5.5 actually"))

    def test_agent_must_be_last_line(self):
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\n# trailing comment line"))
        self.assertTrue(commit_lint.lint("feat: x\n\nAgent: alex\nConflicts:\n\tfile"))

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

    def test_blob_size_is_measured_not_checkout(self):
        # UTF-16 in the working tree is smaller than the UTF-8 blob for this character.
        with tempfile.TemporaryDirectory() as tmp:
            repo = new_repo(tmp)
            (repo / ".gitattributes").write_text("STATUS.md working-tree-encoding=UTF-16LE\n")
            (repo / "STATUS.md").write_bytes(("\u20ac" * 1700).encode("utf-16-le"))
            git(repo, "add", ".gitattributes", "STATUS.md")
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
GO_MOD = "module github.com/example/kordon\n\ngo 1.27\n\ntoolchain go1.27.1\n"
GO_SUM_LINE = "golang.org/x/sys v0.20.0/go.mod h1:" + "A" * 43 + "="


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
            "cmd/kordon/main.go": "package main\n",
            "internal/store/shard.go": "package store\n",
            "internal/store/seal/seal_test.go": "package seal\n",
            "internal/store/testdata/leaf.json": "{}\n",
            "internal/store/seal/testdata/vectors.jsonl": "{}\n",
            "cmd/kordon/testdata/args.json": "{}\n",
            "packaging/laurel/PKGBUILD": "pkgname=laurel\n",
            "deploy/audit/kordon.rules": "-e 2\n",
            "deploy/auditd/auditd.conf": "q_depth = 2000\n",
            "deploy/laurel/config.toml": "[auditlog]\n",
            "deploy/systemd/kordon-collector.service": "[Service]\n",
            "deploy/systemd/kordon-verify.timer": "[Timer]\n",
            "range/mkosi.conf": "[Distribution]\n",
            "range/kordon-range-guest.service": "[Unit]\n",
        }, 0)

    def test_paths_outside_the_go_layout_fail(self):
        for name in ("cmd/kordon/deep/x.go", "internal/a/b/c/x.go", "cmd/x.go", "internal/x.go",
                     "internal/a/go.mod", "go.work", "testdata/x.json", "internal/a/x.json",
                     "internal/a/testdata/deep/x.json", "packaging/PKGBUILD",
                     "packaging/laurel/build.sh", "deploy/audit/kordon.conf",
                     "deploy/systemd/kordon.socket", "deploy/systemd/sub/x.service",
                     "deploy/auditd/other.conf", "src/main.go", "range/mkosi.postinst",
                     "range/mkosi.extra/etc/x.conf", "range/other.conf", "range/sub/x.service",
                     "range/mkosi.conf.d/x.conf", "range/x.timer"):
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
                      "module github.com/example/kordon // c"):
            with self.subTest(extra=extra):
                self.assert_budget({"go.mod": GO_MOD + extra + "\n"}, 1)

    def test_go_sum_outside_its_grammar_fails(self):
        for line in ("token=" + "a" * 40, GO_SUM_LINE + " extra", GO_SUM_LINE.replace("h1:", "h2:"),
                     GO_SUM_LINE[:-2] + "=", "# comment"):
            with self.subTest(line=line):
                self.assert_budget({"go.sum": GO_SUM_LINE + "\n" + line + "\n"}, 1)

    def test_non_ascii_go_mod_fails(self):
        self.assert_budget({"go.mod": GO_MOD + "​\n"}, 1)



class GoLayoutMoreTest(unittest.TestCase):
    _repo_with = DocsBudgetTest._repo_with
    assert_budget = GoLayoutTest.assert_budget

    def test_every_testdata_pattern_admits_its_files(self):
        for name in ("cmd/kordon/testdata/a.jsonl", "internal/store/testdata/a.jsonl",
                     "internal/store/seal/testdata/a.json", "internal/store/seal/testdata/b.jsonl"):
            with self.subTest(name=name):
                self.assert_budget({name: "{}\n"}, 0)

    def test_go_under_testdata_fails(self):
        for name in ("internal/buildinfo/testdata/bad.go", "cmd/kordon/testdata/x.go"):
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
    git(repo, "add", "go.mod")
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
        self.assertFalse(rescan_skipped.skipped("cmd/kordon/main.go"))
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


A_SHA, B_SHA, ZERO_SHA = "a" * 40, "b" * 40, "0" * 40


class ChangeRangeTest(unittest.TestCase):
    def test_pull_request_and_push_ranges(self):
        self.assertEqual(change_range.change_range("pull_request", A_SHA, B_SHA, "", ""), f"{A_SHA}..{B_SHA}")
        self.assertEqual(change_range.change_range("push", "", "", A_SHA, B_SHA), f"{A_SHA}..{B_SHA}")
        self.assertEqual(change_range.change_range("push", "", "", ZERO_SHA, B_SHA), B_SHA)

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

if __name__ == "__main__":
    unittest.main()
