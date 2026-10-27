"""Tests for tools/ci/status.py: it reads this repository, warns on stale state and prints no input raw."""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import status  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
TODAY = dt.date(2026, 10, 9)
NOWHERE = Path("/nonexistent/balistid-status-test")
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}
STATUS = """# Status

Updated: {updated} by t

## Where we are

| Part | Does | State |
|---|---|---|
| Runner | VM | runner installed at {installed}; PR 13 open |
| Store | cap \\| reserve | not started |
## Next step

1. First step
   continues here.
2. Second step.
## Open decisions (maintainer)

- Pick a name.
"""
ADR = "# {num} — {title}\n\n- Status: {status}\n- Date: {date}\n- Decided-by: t\n"
ON_MERGE = "proposed (accepted when merged with the maintainer's approval)"
ACCEPTANCE = '[meta]\nfloor = 0\nstatus = "approved"\n\n[[metric]]\nid = "m1"\nadr = "0001"\nunit = "s"\n'
EV1, EV2, AG1 = "20261009T100000Z-aaaaaaaa", "20261009T110000Z-bbbbbbbb", "20261009T120000Z-cccccccc-job"
PASS = {"schema_version": 1, "verdict": "PASS", "runner_commit": "abc1234" + "0" * 33}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env=GIT_ENV).stdout.strip()


class Fixture(unittest.TestCase):
    """A small repository on main with one evidence result and an empty review queue."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.repo, self.results, self.done = root / "repo", root / "results", root / "done"
        for d in (self.repo / "adr", self.repo / "acceptance", self.results / "evidence",
                  self.results / "agent", self.done):
            d.mkdir(parents=True)
        self.done.chmod(0o700)  # whatever the umask
        git(self.repo, "init", "-q", "-b", "main")
        self.write_status("2026-10-09", "abc1234")
        self.adr("0001", "First", "accepted", "2026-09-01")
        self.adr("0002", "Second", ON_MERGE, "2026-09-01")
        self.adr("0003", "Third", "proposed", "2026-10-08")
        self.write("acceptance/0.toml", ACCEPTANCE)
        self.commit()
        self.result("evidence", EV1, PASS)

    def write(self, rel: str, text: str) -> None:
        (self.repo / rel).write_text(text, encoding="utf-8")

    def adr(self, num: str, title: str, state: str, date: str) -> None:
        self.write(f"adr/{num}-{title.lower()}.md", ADR.format(num=num, title=title, status=state, date=date))

    def write_status(self, updated: str, installed: str) -> None:
        self.write("STATUS.md", STATUS.format(updated=updated, installed=installed))

    def commit(self, msg: str = "c") -> str:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", msg)
        return git(self.repo, "rev-parse", "HEAD")

    def result(self, label: str, name: str, body: object) -> None:
        d = self.results / label / name
        d.mkdir()
        (d / "result.json").write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")

    def render(self, today: dt.date = TODAY) -> str:
        return status.render(self.repo, self.results, self.done, False, True, False, today)

    def warns(self, today: dt.date = TODAY) -> str:
        return self.render(today).split("Waiting on the maintainer")[0]


class RepositoryTest(unittest.TestCase):
    def test_this_repository_renders(self) -> None:
        # The gate: a STATUS.md, ADR or acceptance change the tool cannot read fails here.
        st = status.parse_status((REPO / "STATUS.md").read_text(encoding="utf-8"))
        self.assertTrue(st["next"], "next steps are read")
        # While the range runner is installed its row names the commit; a rewording would silently stop
        # the check against the runner's results.
        self.assertTrue(st["installed"], "the runner row names the installed commit")
        out = status.render(REPO, NOWHERE, NOWHERE, False, True, False, TODAY)
        for adr in sorted((REPO / "adr").glob("[0-9][0-9][0-9][0-9]-*.md"))[1:]:
            self.assertIn(f"  {adr.name[:4]}  ", out)
        self.assertIn("Floor 0 parts", out)
        self.assertRegex(out, r"Acceptance floor 0: \d+ metrics")


class StatusTest(Fixture):
    def test_fresh_state_has_no_warnings(self) -> None:
        out = self.render()
        self.assertIn("Warnings (0)", out)
        self.assertIn("0001  accepted", out)
        self.assertIn("0002  accepted", out)  # merged with approval
        self.assertIn("0003  proposed", out)
        self.assertIn("accept ADR 0003: Third", out)
        self.assertIn("decide: Pick a name.", out)
        self.assertIn("1. First step continues here.", out)
        self.assertIn("ADR 0001: 1  m1", out)
        st = status.parse_status((self.repo / "STATUS.md").read_text())
        self.assertEqual(st["parts"][1], ("Store", "cap | reserve", "not started"))  # escaped pipe

    def test_status_edited_off_main_is_unmerged(self) -> None:
        # An uncommitted edit, or one on a branch, does not accept anything.
        self.adr("0003", "Third", "accepted", "2026-10-08")
        self.adr("0004", "Fourth", ON_MERGE, "2026-09-01")
        out = self.render()
        self.assertIn("0003  unmerged", out)
        self.assertIn("0004  unmerged", out)
        self.assertIn("merge ADR 0004: Fourth", out)
        self.assertIn("ADR 0004 unmerged for 38 days", out)
        self.adr("0001", "First", "superseded by 0004", "2026-09-01")
        self.assertIn("0001  unmerged", self.render())  # superseded only once main says so
        git(self.repo, "switch", "-q", "-c", "feature")
        self.commit()
        self.assertIn("0004  unmerged", self.render())
        git(self.repo, "branch", "-q", "-m", "main", "old")  # no main branch: nothing counts as merged
        self.assertIn("0002  unmerged", self.render())

    def test_old_or_future_status_warns(self) -> None:
        self.assertIn("updated 4 days ago", self.warns(TODAY + dt.timedelta(days=4)))
        self.assertNotIn("days ago", self.warns(TODAY + dt.timedelta(days=3)))
        self.assertIn("after today", self.warns(TODAY - dt.timedelta(days=1)))

    def test_status_behind_head_warns(self) -> None:
        for i in range(status.STALE_COMMITS):
            self.commit(f"c{i}")
        self.assertNotIn("commits behind", self.warns())
        self.commit("one more")
        self.assertIn(f"STATUS.md is {status.STALE_COMMITS + 1} commits behind HEAD", self.warns())

    def test_an_adr_shows_which_later_adrs_amend_it(self) -> None:
        self.write("adr/0003-third.md", ADR.format(num="0003", title="Third", status="proposed", date="2026-10-08")
                   + "\n## Consequences\n\n- Amends ADR 0001 point 2 and\n  0002 points 1 and 3, and ADR 0099 point 1.\n"
                   + "- The range holds 2000/s on 0.5 cores; ADR 0001 stays as it is.\n")
        adrs = {a["num"]: a for a in status.parse_adrs(self.repo)}
        self.assertEqual([adrs[n]["amended_by"] for n in ("0001", "0002", "0003")], [["0003"], ["0003"], []])
        out = self.render()
        self.assertIn("First  (amended by 0003)", out)
        self.assertNotIn("Third  (amended", out)

    def test_old_proposed_adr_warns(self) -> None:
        out = self.warns(dt.date(2026, 10, 23))
        self.assertIn("ADR 0003 proposed for 15 days", out)
        self.assertNotIn("ADR 0002", out)

    def test_runner_commit_other_than_status_warns(self) -> None:
        self.result("evidence", EV2, {**PASS, "runner_commit": "def5678" + "0" * 33})
        self.assertIn("runner installed at abc1234; latest evidence ran def5678", self.warns())
        # A newer agent result does not hide the latest evidence run.
        self.result("agent", AG1, PASS)
        self.assertIn("latest evidence ran def5678", self.warns())
        # The claim is read whatever its case.
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text().replace("runner installed at abc1234",
                                                                              "Runner Installed at DEF5678"))
        self.assertNotIn("latest evidence ran", self.warns())
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text().replace("DEF5678", "ABC1234"))
        self.assertIn("runner installed at abc1234; latest evidence ran def5678", self.warns())

    def test_failed_evidence_warns(self) -> None:
        self.result("evidence", EV2, {**PASS, "verdict": "FAIL"})
        self.assertIn(f"latest evidence run {EV2} is FAIL", self.warns())

    def test_unreadable_sources_warn(self) -> None:
        out = status.render(self.repo, NOWHERE, NOWHERE, False, False, False, TODAY)
        self.assertEqual(out.count("cannot check:"), 2)
        self.assertIn("not readable", out)

    def test_open_pull_requests_over_the_limit_warn(self) -> None:
        prs = [{"number": n, "title": "t", "wait": "CI running"} for n in range(status.MAX_OPEN_PRS + 1)]
        facts, res = {"status_behind": 0}, {"latest": [], "evidence": None}
        st = status.parse_status((self.repo / "STATUS.md").read_text())
        self.assertIn("3 open pull requests", " ".join(status.warnings(st, [], facts, res, [], prs, TODAY)))
        self.assertFalse(status.warnings(st, [], facts, res, [], prs[:2], TODAY))
        self.assertIn("cannot check: gh failed", " ".join(status.warnings(st, [], facts, res, [], "gh failed", TODAY)))
        self.assertFalse(status.warnings(st, [], facts, res, [], status.NOT_ASKED, TODAY))


class RunnerResultTest(Fixture):
    def test_bad_results_are_unreadable_not_fatal(self) -> None:
        self.result("evidence", EV2, "[" * 200000 + "]" * 200000)  # deeper than Python's recursion limit
        self.assertIn(f"latest evidence run {EV2} is UNREADABLE", self.warns())
        # Valid JSON padded past the cap would parse after truncation: refused for its size alone.
        for body in ({**PASS, "schema_version": 2}, ["not", "an", "object"], json.dumps(PASS) + " " * status.MAX_JSON):
            (self.results / "evidence" / EV2 / "result.json").write_text(
                body if isinstance(body, str) else json.dumps(body))
            self.assertIn("is UNREADABLE", self.warns())

    def test_only_runner_names_count(self) -> None:
        # A directory the runner never names cannot sort first and hide a newer failed run.
        self.result("evidence", "2099-later", {**PASS, "runner_commit": "abc1234"})
        self.result("evidence", EV2, {**PASS, "verdict": "FAIL"})
        self.assertIn(f"latest evidence run {EV2} is FAIL", self.warns())
        self.assertNotIn("2099-later", self.render())


class UnreadableTest(Fixture):
    def broken(self, old: str, new: str) -> str:
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text().replace(old, new))
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(status.main(["--repo", str(self.repo), "--results", str(NOWHERE)]), 1)
        return err.getvalue()

    def test_status_drift_fails(self) -> None:
        cases = {
            ("## Where we are", "## Where"): "no '## Where we are' section",
            ("| Runner | VM |", "| Runner | VM | x |"): "parts row without 3 cells",
            ("## Open decisions (maintainer)", "## Decisions"): "no '## Open decisions (maintainer)' section",
            ("## Next step", "## Next"): "no '## Next step' section",
            ("| Store | cap \\| reserve | not started |", "| Store | cap \\| reserve | not started |\nprose"):
                "parts row without 3 cells",
            ("|---|---|---|", "|---|---|"): "no parts table",
            ("| Part | Does | State |", "| Part | Does | State | More |"): "header needs 3 cells",
            ("| Store |", "|---|---|---|\n| Store |"): "parts row without 3 cells",
            ("Updated: 2026-10-09", "Updated: 9.10.2026"): "no 'Updated: YYYY-MM-DD' line",
        }
        for (old, new), want in cases.items():
            with self.subTest(old=old):
                self.write_status("2026-10-09", "abc1234")
                self.assertIn(want, self.broken(old, new))

    def test_table_rows_with_or_without_outer_pipes(self) -> None:
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text()
                   .replace("| Runner | VM | runner installed at abc1234; PR 13 open |",
                            "Runner | VM | runner installed at abc1234; PR 13 open")
                   .replace("| Store | cap \\| reserve | not started |", "| Store | cap \\| reserve | not started"))
        st = status.parse_status((self.repo / "STATUS.md").read_text())
        self.assertEqual(st["parts"], [("Runner", "VM", "runner installed at abc1234; PR 13 open"),
                                       ("Store", "cap | reserve", "not started")])

    def test_prose_around_the_table_is_not_a_row(self) -> None:
        text = (self.repo / "STATUS.md").read_text()
        text = text.replace("| Part | Does | State |", "Columns: a | b | c.\nPipe it: status.py | less\n\n"
                            "| Part | Does | State |")
        text = text.replace("| Store | cap \\| reserve | not started |",
                            "| Store | cap \\| reserve | not started |\n\nAfter the table | with a pipe.")
        self.write("STATUS.md", text)
        st = status.parse_status(text)
        self.assertEqual([p[0] for p in st["parts"]], ["Runner", "Store"])
        short = status.parse_status(text.replace("|---|---|---|", "|-|:-:|-|"))  # any GFM delimiter
        self.assertEqual(short["parts"], st["parts"])

    def test_prose_next_step_is_shown(self) -> None:
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text()
                   .replace("1. First step\n   continues here.\n2. Second step.", "None right now."))
        self.assertIn("1. None right now.", self.render())

    def test_unknown_adr_status_fails(self) -> None:
        for bad in ("rejected", "Proposed", "draft", "withdrawn", "proposed (draft)"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "unknown ADR status"):
                status.adr_state(bad, True)

    def test_adr_without_status_fails(self) -> None:
        self.write("adr/0004-bad.md", "# 0004 — Bad\n\n- Date: 2026-10-09\n")
        with self.assertRaisesRegex(ValueError, "0004-bad.md"):
            status.parse_adrs(self.repo)

    def test_metric_without_adr_fails(self) -> None:
        self.write("acceptance/0.toml", '[[metric]]\nid = "m1"\nunit = "s"\n')
        with self.assertRaisesRegex(ValueError, "needs id, adr and unit"):
            status.parse_acceptance(self.repo / "acceptance" / "0.toml")


class HostileInputTest(Fixture):
    ESC = "\x1b]0;owned\x07\x1b[2J"

    def test_clean_removes_control_and_format_characters(self) -> None:
        self.assertEqual(status.clean("a\x1b[31mb‮c\u0007d\x9be"), "a?[31mb?c?d?e")
        self.assertEqual(status.clean("x" * 10, 5), "xxxx…")

    def test_no_input_reaches_the_terminal_raw(self) -> None:
        self.write("STATUS.md", (self.repo / "STATUS.md").read_text().replace("Pick a name.", "Pick" + self.ESC))
        self.adr("0003", "Third", "proposed", "2026-10-08")
        self.write("adr/0003-third.md", ADR.format(num="0003", title="T" + self.ESC, status="proposed",
                                                  date="2026-10-08"))
        self.result("evidence", EV2, {**PASS, "verdict": "PASS" + self.ESC, "runner_commit": self.ESC,
                                      "reason": self.ESC})
        self.result("agent", AG1, ["not", "an", "object"])
        sha = self.commit()
        (self.done / "r1.request.json").write_text(json.dumps({"commit": sha}))
        (self.done / "r1.md").write_text("Verdict: GO" + self.ESC + "\n")
        out = self.render()
        self.assertIn("GO?]0;owned", out)  # the review was read
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("UNREADABLE", out)


class ReviewQueueTest(Fixture):
    def test_review_commit_is_checked_before_git_sees_it(self) -> None:
        sha = self.commit()
        cases = (("a", sha), ("b", "--output=" + str(self.repo / "x")), ("c", "f" * 40), ("d", 7), ("e", "HEAD"))
        for name, commit in cases:
            (self.done / f"{name}.request.json").write_text(json.dumps({"commit": commit}))
            (self.done / f"{name}.md").write_text(f"Verdict: V{name}\n")
        (self.done / "f.request.json").write_text("[" * 200000)
        (self.done / "f.md").write_text("Verdict: Vf\n")
        # b and e: not a full sha (git would resolve HEAD); c: not in this repository; d: not a string;
        # f: request too deep to parse.
        self.assertEqual([r["verdict"] for r in status.reviews(self.done, self.repo)], ["Va"])
        self.assertFalse((self.repo / "x").exists())

    def test_queue_others_can_write_is_not_trusted(self) -> None:
        sha = self.commit()
        (self.done / "a.request.json").write_text(json.dumps({"commit": sha}))
        (self.done / "a.md").write_text("Verdict: GO\n")
        self.assertEqual(len(status.reviews(self.done, self.repo)), 1)
        for mode in (0o770, 0o707):
            self.done.chmod(mode)
            self.assertIn("not trusted", status.reviews(self.done, self.repo))
        self.done.chmod(0o700)
        link = self.done.with_name("link")
        link.symlink_to(self.done)
        self.assertIn("not trusted", status.reviews(link, self.repo))
        self.assertIn("not readable", status.reviews(NOWHERE, self.repo))


class PullRequestWaitTest(unittest.TestCase):
    def wait(self, checks: list[dict], **pr) -> str:
        return status.pr_wait({"statusCheckRollup": checks, **pr})

    def test_waits(self) -> None:
        ok = [{"conclusion": "SUCCESS"}, {"conclusion": "SKIPPED"}]
        self.assertEqual(self.wait([]), "CI not started")
        for bad in ("FAILURE", "STARTUP_FAILURE", "STALE", "ACTION_REQUIRED"):
            self.assertEqual(self.wait(ok + [{"conclusion": bad}]), "CI failing (agent fixes)")
        self.assertEqual(self.wait(ok + [{"state": "PENDING"}]), "CI running")
        self.assertEqual(self.wait(ok + [{"conclusion": "", "state": ""}]), "CI running")
        self.assertEqual(self.wait(ok, isDraft=True), "draft (agent)")
        self.assertEqual(self.wait(ok, reviewDecision="CHANGES_REQUESTED"), "changes requested (agent)")
        for merge_state in ("BEHIND", "DIRTY"):
            self.assertEqual(self.wait(ok, mergeStateStatus=merge_state), "rebase (agent)")
        self.assertEqual(self.wait(ok, reviewDecision="REVIEW_REQUIRED"), "maintainer review")
        self.assertEqual(self.wait(ok, reviewDecision="APPROVED"), "maintainer merge")
        self.assertEqual(self.wait(ok, reviewDecision=""), "maintainer merge")


if __name__ == "__main__":
    unittest.main()
