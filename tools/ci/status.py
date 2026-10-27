#!/usr/bin/env python3
"""Show where the project stands: floor parts, ADRs, acceptance, what waits on the maintainer.

Read from the repository and, when present, the installed runner's results, the review queue and
(with --prs) GitHub. It warns where the written state disagrees with git or the runner, and when a
source cannot be read, so a stale STATUS.md shows up instead of being believed. It is a view, not a
control: an agent at the maintainer's uid can change every source it reads, refs included.
Read-only: it writes nothing and runs only git and, with --prs, gh. Every string read from a file,
a result or GitHub goes through clean() when it is read, so no input can drive the terminal. The
tests run it on this repository, and every section it reads must be found, so a change to STATUS.md,
an ADR or acceptance/ that it can no longer read fails CI. To redraw: watch -n 10 python3 tools/ci/status.py
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STALE_DAYS = 3  # STATUS.md older than this is a warning
STALE_COMMITS = 10  # and so are this many commits since STATUS.md last changed
PROPOSED_DAYS = 14  # an ADR waiting longer than this is a warning
MAX_OPEN_PRS = 2  # agreed with the maintainer 2026-10-09
SHOWN = 5  # results and reviews listed
MAX_JSON = 1 << 20  # the runner's own reader stops here too (internal/rangerun)
SHA = re.compile(r"[0-9a-f]{40}")
RESULT_NAME = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}(-[a-z0-9][a-z0-9-]{0,63})?")  # rangerun resultName
INSTALLED = re.compile(r"installed at ([0-9a-f]{7,40})\b", re.I)
PIPE = re.compile(r"(?<!\\)\|")
DELIMITER = re.compile(r"\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*){2}\|?")


def clean(text: object, limit: int = 160) -> str:
    """One printable line: control and format characters become '?', long text is cut."""
    s = "".join("?" if unicodedata.category(c)[0] == "C" else c for c in str(text).replace("\n", " "))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def section(text: str, heading: str) -> list[str]:
    """Lines under a '## heading' up to the next heading; a missing heading is an error."""
    out, inside, found = [], False, False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line[3:].strip() == heading
            found = found or inside
        elif inside:
            out.append(line)
    if not found:
        raise ValueError(f"STATUS.md: no '## {heading}' section")
    return out


def cells(row: str) -> list[str]:
    """A table row's cells; the outer pipes are optional and an escaped pipe belongs to its cell."""
    row = row.strip()
    row = row[1:] if row.startswith("|") else row
    row = row[:-1] if row.endswith("|") and not row.endswith("\\|") else row
    return [clean(c.strip().replace("\\|", "|"), 90) for c in PIPE.split(row)]


def table(lines: list[str]) -> list[list[str]]:
    """The first three-column table in lines: header, then rows up to the first blank line.

    It is found by its delimiter row (|---|---|---|), so prose around it, pipes included, is never
    read as a row; inside it, a line that is not a row of three cells is an error."""
    at = next((i for i, ln in enumerate(lines) if DELIMITER.fullmatch(ln.strip())), None)
    if not at:
        raise ValueError("STATUS.md: no parts table (header and |---|---|---| row) under 'Where we are'")
    rows = [cells(lines[at - 1])]
    for line in lines[at + 1:]:
        if not line.strip():
            break
        row = cells(line)
        if len(row) != 3 or DELIMITER.fullmatch(line.strip()):
            raise ValueError(f"STATUS.md: parts row without 3 cells: {clean(line, 60)}")
        rows.append(row)
    if len(rows[0]) != 3:
        raise ValueError("STATUS.md: the parts table header needs 3 cells")
    return rows


def parse_status(text: str) -> dict:
    updated = re.search(r"^Updated: (\d{4}-\d{2}-\d{2})\b", text, re.M)
    if not updated:
        raise ValueError("STATUS.md: no 'Updated: YYYY-MM-DD' line")
    parts = [tuple(row) for row in table(section(text, "Where we are"))[1:]]
    if not parts:
        raise ValueError("STATUS.md: no parts table under 'Where we are'")
    decisions = [clean(ln[2:]) for ln in section(text, "Open decisions (maintainer)") if ln.startswith("- ")]
    steps: list[str] = []
    lines = section(text, "Next step")
    for line in lines:
        item = re.match(r"\d+\. (.*)", line)
        if item:
            steps.append(item.group(1).strip())
        elif steps and line.startswith("   "):
            steps[-1] += " " + line.strip()
    if not steps:  # prose such as "None right now." is shown as it is
        steps = [ln.strip() for ln in lines if ln.strip()]
    return {"updated": dt.date.fromisoformat(updated.group(1)), "parts": parts, "decisions": decisions,
            "next": [clean(s, 220) for s in steps],
            "installed": sorted({m.lower() for _, _, s in parts for m in INSTALLED.findall(s)})}


def adr_fields(text: str, name: str) -> tuple[str, str, str, dt.date]:
    title = re.match(r"# (\d{4}) — (.+)", text)
    status = re.search(r"^- Status: (.+)$", text, re.M)
    date = re.search(r"^- Date: (\d{4}-\d{2}-\d{2})\b", text, re.M)
    if not (title and status and date):
        raise ValueError(f"{name}: needs '# NNNN — title', '- Status:' and '- Date:' lines")
    return title.group(1), clean(title.group(2), 100), status.group(1).strip(), dt.date.fromisoformat(date.group(1))


def adr_state(status: str, merged: bool) -> str:
    """merged: main holds this ADR with this same Status line. Only what is on main counts."""
    if status == "proposed":
        return "proposed"
    if status.startswith("superseded"):
        return "superseded" if merged else "unmerged"
    if status.startswith("accepted") or status.startswith("proposed (accepted when merged"):
        return "accepted" if merged else "unmerged"
    raise ValueError(f"unknown ADR status {clean(status, 60)!r}")


def adr_amends(text: str, own: str) -> list[str]:
    """The ADR numbers an "Amends ..." sentence names: ADRs cite each other as four digits from 0."""
    flat = " ".join(text.split())
    clauses = re.findall(r"\b[Aa]mends\b(.*?)(?:\.\s|\.$|$)", flat)
    return sorted({n for c in clauses for n in re.findall(r"\b0\d{3}\b", c)} - {own})


def main_ref(repo: Path) -> str | None:
    """The main branch to compare with: the remote's if fetched, else the local one."""
    for ref in ("refs/remotes/origin/main", "refs/heads/main"):
        if subprocess.run(["git", "-C", str(repo), "rev-parse", "-q", "--verify", ref],
                          capture_output=True).returncode == 0:
            return ref
    return None


def parse_adrs(repo: Path) -> list[dict]:
    ref = main_ref(repo)
    out = []
    for p in sorted((repo / "adr").glob("[0-9][0-9][0-9][0-9]-*.md")):
        if p.name.startswith("0000-"):
            continue
        text = p.read_text(encoding="utf-8")
        num, title, status, date = adr_fields(text, p.name)
        on_main = ref and subprocess.run(["git", "-C", str(repo), "show", f"{ref}:adr/{p.name}"],
                                         capture_output=True, text=True)
        main_status = on_main and on_main.returncode == 0 and re.search(r"^- Status: (.+)$", on_main.stdout, re.M)
        merged = bool(main_status) and main_status.group(1).strip() == status
        out.append({"num": num, "title": title, "state": adr_state(status, merged), "date": date,
                    "amends": adr_amends(text, num)})
    for a in out:
        a["amended_by"] = [b["num"] for b in out if a["num"] in b["amends"]]
    return out


def parse_acceptance(path: Path) -> dict:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    metrics = data.get("metric")
    if not metrics or any(not {"id", "adr", "unit"} <= m.keys() for m in metrics):
        raise ValueError(f"{path.name}: every [[metric]] needs id, adr and unit")
    meta = data.get("meta", {})
    return {"floor": clean(meta.get("floor", "?"), 4), "status": clean(meta.get("status", "?"), 20),
            "metrics": [(clean(m["adr"], 6), clean(m["id"], 40)) for m in metrics]}


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    return p.stdout.strip()


def git_facts(repo: Path) -> dict:
    last = git(repo, "log", "-1", "--format=%H", "--", "STATUS.md")
    behind = int(git(repo, "rev-list", "--count", f"{last}..HEAD")) if last else None
    return {"head": clean(git(repo, "log", "-1", "--format=%h %cs %s"), 100), "status_behind": behind}


def read_json(path: Path) -> object:
    """A JSON value from a file of at most MAX_JSON bytes, or None."""
    try:
        with path.open("rb") as f:
            raw = f.read(MAX_JSON + 1)
        return json.loads(raw) if len(raw) <= MAX_JSON else None
    except (OSError, ValueError, RecursionError):
        return None


def read_result(d: Path) -> dict:
    r = read_json(d / "result.json")
    if not isinstance(r, dict) or r.get("schema_version") != 1:
        r = {"verdict": "UNREADABLE"}
    return {"id": clean(d.name, 60), "label": clean(d.parent.name, 10), "verdict": clean(r.get("verdict", "?"), 12),
            "commit": clean(r.get("runner_commit", ""), 40)[:7].lower(), "reason": clean(r.get("reason", ""), 70)}


def runner_results(results: Path) -> dict | str:
    """The newest results and the newest evidence run, or why there are none."""
    dirs = []
    for label in ("evidence", "agent"):
        try:
            # Only names the runner gives, so no other directory sorts first and hides a newer result.
            dirs += [d for d in (results / label).iterdir() if RESULT_NAME.fullmatch(d.name) and d.is_dir()]
        except OSError as e:
            return f"{results / label}: not readable ({e.strerror})"
    dirs.sort(key=lambda d: d.name, reverse=True)
    evidence = next((d for d in dirs if d.parent.name == "evidence"), None)
    return {"latest": [read_result(d) for d in dirs[:SHOWN]],
            "evidence": read_result(evidence) if evidence else None}


def reviews(done: Path, repo: Path) -> list[dict] | str:
    """Newest review verdicts whose commit is in this repository, from a queue only this user writes."""
    try:
        st = done.lstat()
    except OSError as e:
        return f"{done}: not readable ({e.strerror})"
    # The queue sits under the world-writable /var/tmp: anyone could have made a directory there.
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        return f"{done}: not trusted (not a directory of this user that only it can write)"
    out = []
    for md in sorted(done.glob("*.md"), key=lambda p: p.name, reverse=True):
        req = read_json(md.with_name(md.name[:-3] + ".request.json"))
        try:
            with md.open("rb") as f:
                text = f.read(MAX_JSON).decode("utf-8", "replace")
        except (OSError, ValueError):
            continue
        sha = str(req.get("commit", "")) if isinstance(req, dict) else ""
        # The full sha is checked before git sees it, so no file can hand git an option.
        if not SHA.fullmatch(sha) or subprocess.run(
                ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True).returncode:
            continue
        verdict = re.search(r"^Verdict: (.+)$", text, re.M)
        out.append({"name": clean(md.stem, 80), "commit": sha[:7],
                    "verdict": clean(verdict.group(1), 20) if verdict else "?"})
        if len(out) == SHOWN:
            break
    return out


CHECK_OK = ("SUCCESS", "NEUTRAL", "SKIPPED")
CHECK_FAILED = ("FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE", "STALE")


def pr_wait(pr: dict) -> str:
    """What an open pull request waits on; only the last two are the maintainer's."""
    checks = [c.get("conclusion") or c.get("state") or "" for c in pr.get("statusCheckRollup") or []]
    if not checks:
        return "CI not started"
    if any(c in CHECK_FAILED for c in checks):
        return "CI failing (agent fixes)"
    if any(c not in CHECK_OK for c in checks):
        return "CI running"
    if pr.get("isDraft"):
        return "draft (agent)"
    if pr.get("reviewDecision") == "CHANGES_REQUESTED":
        return "changes requested (agent)"
    if pr.get("mergeStateStatus") in ("BEHIND", "DIRTY"):
        return "rebase (agent)"
    # No review required ("") still merges by hand: the bot's merges are blocked (2026-10-09).
    return "maintainer review" if pr.get("reviewDecision") == "REVIEW_REQUIRED" else "maintainer merge"


def open_prs(repo: Path) -> list[dict] | str:
    fields = "number,title,reviewDecision,mergeStateStatus,statusCheckRollup,isDraft"
    try:
        p = subprocess.run(["gh", "pr", "list", "--state", "open", "--json", fields], cwd=repo,
                           capture_output=True, text=True, timeout=30)
        prs = json.loads(p.stdout) if p.returncode == 0 else None
    except (OSError, ValueError, RecursionError, subprocess.TimeoutExpired) as e:
        return f"gh failed ({clean(e, 100)})"
    if not isinstance(prs, list):
        return f"gh failed ({clean(p.stderr, 100)})"
    return [{"number": clean(pr.get("number", "?"), 8), "title": clean(pr.get("title", ""), 80), "wait": pr_wait(pr)}
            for pr in prs if isinstance(pr, dict)]


def warnings(status: dict, adrs: list[dict], facts: dict, results, revs, prs, today: dt.date) -> list[str]:
    w = []
    age = (today - status["updated"]).days
    if age > STALE_DAYS:
        w.append(f"STATUS.md was updated {age} days ago")
    if age < 0:
        w.append(f"STATUS.md is dated {status['updated']}, after today")
    if facts["status_behind"] is not None and facts["status_behind"] > STALE_COMMITS:
        w.append(f"STATUS.md is {facts['status_behind']} commits behind HEAD")
    for a in adrs:
        days = (today - a["date"]).days
        if a["state"] in ("proposed", "unmerged") and days > PROPOSED_DAYS:
            w.append(f"ADR {a['num']} {a['state']} for {days} days")
        if days < 0:
            w.append(f"ADR {a['num']} is dated {a['date']}, after today")
    for source in (results, revs, prs):
        if isinstance(source, str) and source != NOT_ASKED:
            w.append(f"cannot check: {source}")
    ev = results.get("evidence") if isinstance(results, dict) else None
    if ev:
        if ev["verdict"] != "PASS":
            w.append(f"latest evidence run {ev['id']} is {ev['verdict']}")
        if status["installed"] and not any(ev["commit"] == c[:7] for c in status["installed"]):
            w.append(f"STATUS.md says runner installed at {', '.join(status['installed'])}; "
                     f"latest evidence ran {ev['commit']}")
    if isinstance(prs, list) and len(prs) > MAX_OPEN_PRS:
        w.append(f"{len(prs)} open pull requests (agreed limit {MAX_OPEN_PRS})")
    return w


NOT_ASKED = "not asked (--prs)"
COLORS = {"accepted": "32", "proposed": "33", "unmerged": "33", "superseded": "2", "PASS": "32", "FAIL": "31"}


def part_color(state: str) -> str:
    s = state.lower()
    if "not started" in s:
        return "2"
    return "32" if any(k in s for k in ("on `main`", "installed", "configured", "done")) else "33"


def render(repo: Path, results: Path, done: Path, want_prs: bool, all_metrics: bool, color: bool,
           today: dt.date) -> str:
    status = parse_status((repo / "STATUS.md").read_text(encoding="utf-8"))
    adrs = parse_adrs(repo)
    acc = parse_acceptance(repo / "acceptance" / "0.toml")
    facts = git_facts(repo)
    res = runner_results(results)
    revs = reviews(done, repo)
    prs = open_prs(repo) if want_prs else NOT_ASKED
    lines: list[str] = []

    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color and code else text

    def head(text: str) -> None:
        lines.extend(["", paint(text, "1;36")])

    lines.append(paint(f"Balistid Blue  ·  HEAD {facts['head']}", "1"))
    lines.append(f"STATUS.md updated {status['updated']}  ·  today {today}")
    w = warnings(status, adrs, facts, res, revs, prs, today)
    head(f"Warnings ({len(w)})")
    lines += [paint(f"  ! {x}", "31") for x in w] or [paint("  none", "2")]
    head("Waiting on the maintainer")
    waiting = [f"decide: {d}" for d in status["decisions"]]
    waiting += [f"accept ADR {a['num']}: {a['title']}" for a in adrs if a["state"] == "proposed"]
    waiting += [f"merge ADR {a['num']}: {a['title']}" for a in adrs if a["state"] == "unmerged"]
    if isinstance(prs, list):
        waiting += [f"#{p['number']} {p['wait']}: {p['title']}" for p in prs if p["wait"].startswith("maintainer")]
    lines += [f"  - {x}" for x in waiting] or ["  nothing"]
    head("Next (STATUS.md)")
    lines += [f"  {i}. {s}" for i, s in enumerate(status["next"], 1)] or ["  none written"]
    head(f"Floor {acc['floor']} parts (STATUS.md)")
    width = max(len(p[0]) for p in status["parts"])
    lines += [f"  {part:<{width}}  " + paint(state, part_color(state)) for part, _, state in status["parts"]]
    head(f"ADRs ({len(adrs)})")
    lines += [f"  {a['num']}  " + paint(f"{a['state']:<10}", COLORS[a["state"]]) + f" {a['title']}"
              + (paint(f"  (amended by {', '.join(a['amended_by'])})", "2") if a["amended_by"] else "")
              for a in adrs]
    by_adr: dict[str, list[str]] = {}
    for adr, mid in acc["metrics"]:
        by_adr.setdefault(adr, []).append(mid)
    head(f"Acceptance floor {acc['floor']}: {len(acc['metrics'])} metrics, {acc['status']}")
    lines += [f"  ADR {adr}: {len(ids)}" + (f"  {', '.join(ids)}" if all_metrics else "")
              for adr, ids in sorted(by_adr.items())]
    head("Runner results (newest first)")
    if isinstance(res, str):
        lines.append(paint(f"  {res}", "2"))
    else:
        lines += [f"  {r['id']:<44} {r['label']:<8} " + paint(f"{r['verdict']:<8}", COLORS.get(r["verdict"], "33"))
                  + f" {r['commit']:<7}  {r['reason']}" for r in res["latest"]] or ["  none"]
    head("Reviews (Codex queue)")
    if isinstance(revs, str):
        lines.append(paint(f"  {revs}", "2"))
    else:
        lines += [f"  {r['verdict']:<14} {r['commit']}  {r['name']}" for r in revs] or [paint("  none", "2")]
    head("Open pull requests")
    if isinstance(prs, str):
        lines.append(paint(f"  {prs}", "2"))
    else:
        lines += [f"  #{p['number']:<4} {p['wait']:<26} {p['title']}" for p in prs] or ["  none"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--results", type=Path, default=Path("/var/lib/balistid/results"))
    ap.add_argument("--reviews", type=Path, default=Path("/var/tmp/codex-review/done"))
    ap.add_argument("--prs", action="store_true", help="also ask GitHub for open pull requests (gh)")
    ap.add_argument("--all", action="store_true", help="list every acceptance metric by ADR")
    a = ap.parse_args(argv)
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    try:
        sys.stdout.write(render(a.repo, a.results, a.reviews, a.prs, a.all, color, dt.date.today()))
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        print(f"status: {clean(e)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
