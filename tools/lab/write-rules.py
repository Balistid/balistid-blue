#!/usr/bin/env python3
"""T1: blind rule authors for one pair, the same way for every vendor. The maintainer runs it outside the agent sandbox.

Each author gets the same prompt (prompt-v1.txt with the pair's brief and one example event of another pair), in a
fresh empty directory, with tools off where the CLI allows it, one attempt per sample, no retry. For each answer it
keeps the raw record (prompt, stdout, stderr, rc, CLI version, times) and, when the answer is one valid rule, a rule
file in the lab's format (model, sample, params, brief_sha256). An invalid answer stays a recorded failure.

  python3 write-rules.py --pair lab/pairs/tmp-hidden.json --out ~/scratch/balistid/pilot/t1/out --samples 3 \
      --author claude:claude-opus-5-5 --author codex:gpt-6.2-sol --author agy:<model>
"""
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time

HERE = pathlib.Path(__file__).resolve().parent
TIMEOUT = 900


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def need_flags(cli, flags):
    if cli == "gemini-api":  # no CLI: this script makes the request itself
        if not os.environ.get("GEMINI_API_KEY"):
            sys.exit("STOP: GEMINI_API_KEY is not set; nothing was run for gemini-api")
        return
    h = subprocess.run([cli, "--help"] if cli != "codex" else ["codex", "exec", "--help"],
                       capture_output=True, text=True, timeout=60)
    out = h.stdout + h.stderr  # Go's flag package (agy) prints its help on stderr
    missing = [f for f in flags if f not in out]
    if missing:
        sys.exit(f"STOP: {cli} --help lacks {missing}; nothing was run for it")


def command(vendor, model, prompt, work):
    if vendor == "claude":
        return ["claude", "-p", "--model", model, "--output-format", "json", "--tools", "",
                "--strict-mcp-config", "--settings", '{"disableAllHooks": true}'], prompt
    if vendor == "codex":
        # project_doc_max_bytes=0: no AGENTS.md (the global one holds the maintainer's own instructions)
        return ["codex", "exec", "-m", model, "-s", "read-only", "--skip-git-repo-check", "--ephemeral",
                "-c", "project_doc_max_bytes=0", "-C", work, "--json", "-o", os.path.join(work, "last.txt"), "-"], prompt
    if vendor == "agy":
        # Go's flag package stops at the first non-flag word: every flag first, the prompt last
        return ["agy", "--model", model, "--mode", "plan", "--sandbox", "--output-format", "json", "--print", prompt], None
    if vendor == "gemini":
        # headless: shell and writes are never approved, file tools stay inside the empty working directory;
        # --skip-trust trusts only that empty directory for this run (headless refuses an untrusted one)
        return ["gemini", "-m", model, "--output-format", "json", "--approval-mode", "default", "--skip-trust",
                "-p", prompt], None
    if vendor == "gemini-api":
        # no agent around the model: one request with no tools declared, so it cannot call any
        return [sys.executable, "-I", str(pathlib.Path(__file__).resolve()), "--gemini-api-call", model], prompt
    sys.exit(f"STOP: unknown vendor {vendor}")


GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"


def gemini_api_call(model):
    """Prompt on stdin, the API's JSON reply on stdout. The key comes from the environment, never argv or output.
    A 429 (free tier) or a 500/503 (overloaded) is not an answer, so it waits and asks again (at most 3 times);
    any other error ends it."""
    import urllib.error, urllib.request
    body = json.dumps({"contents": [{"role": "user", "parts": [{"text": sys.stdin.read()}]}]}).encode()
    for attempt in range(4):
        time.sleep(13)  # about 5 requests a minute
        req = urllib.request.Request(GEMINI_URL.format(model), data=body, method="POST", headers={
            "Content-Type": "application/json", "x-goog-api-key": os.environ["GEMINI_API_KEY"]})
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                sys.stdout.write(r.read().decode())
                return 0
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")[:600]
            if e.code in (429, 500, 503) and attempt < 3:
                print(f"HTTP {e.code}, waiting 65 s (attempt {attempt + 1})", file=sys.stderr)
                time.sleep(65)
                continue
            print(f"HTTP {e.code}: {msg}", file=sys.stderr)
            return 1
        except OSError as e:
            print(f"request failed: {type(e).__name__}", file=sys.stderr)
            return 1
    return 1


FLAGS = {"claude": ["--tools", "--strict-mcp-config", "--settings", "--output-format"],
         "codex": ["--sandbox", "--skip-git-repo-check", "--ephemeral", "--json", "--output-last-message"],
         "agy": ["--print", "--model", "--mode", "--sandbox", "--output-format"],
         "gemini": ["--model", "--output-format", "--approval-mode", "--skip-trust", "--prompt"],
         "gemini-api": []}

TOOL_MARKS = ("command_execution", "exec_command", "mcp_tool_call", "web_search", "file_change", "tool_use",
              "function_call", "toolCall", "tool_call")


def tool_use(vendor, stdout):
    """How many tool events the author's run shows (0 = none seen), or None when the CLI's output cannot tell.
    A blind author must not look around: an answer after any tool event is recorded but not used as a rule."""
    if vendor == "claude":
        try:
            d = json.loads(stdout)
        except ValueError:
            return None
        return max(0, int(d.get("num_turns", 1)) - 1) if isinstance(d, dict) else None
    if vendor == "gemini":
        try:
            d = json.loads(stdout)
            return int(d["stats"]["tools"]["totalCalls"])
        except (ValueError, KeyError, TypeError):
            return None
    if vendor == "gemini-api":  # no tools declared; a functionCall part would still be counted
        try:
            json.loads(stdout)
        except ValueError:
            return None
        return stdout.count('"functionCall"')
    hits = sum(stdout.count(m) for m in TOOL_MARKS)
    if vendor == "codex":
        return hits
    return hits if hits else None  # agy: a hit is proof, silence is not


def answer_text(vendor, stdout, work):
    if vendor == "codex":
        p = pathlib.Path(work, "last.txt")
        return p.read_text() if p.exists() else ""
    try:
        d = json.loads(stdout)
    except ValueError:
        return stdout
    if vendor == "gemini-api":
        try:
            return "".join(x.get("text", "") for x in d["candidates"][0]["content"]["parts"] if not x.get("thought"))
        except (KeyError, IndexError, TypeError):
            return ""
    for k in ("result", "response", "text", "output"):
        if isinstance(d, dict) and isinstance(d.get(k), str):
            return d[k]
    return stdout


def one_rule(text):
    """The answer's single JSON object if it is a rule in the lab's language, else (None, why)."""
    s = text.strip()
    s = re.sub(r"^```(?:json)?\s*|\s*```$", "", s)
    try:
        r = json.loads(s)
    except ValueError as e:
        return None, f"not one JSON object ({e})"
    if not (isinstance(r, dict) and len(r) == 1 and next(iter(r)) in ("any", "all")
            and isinstance(next(iter(r.values())), list)):
        return None, "not {any|all: [leaves]}"
    for leaf in next(iter(r.values())):
        if not (isinstance(leaf, dict) and isinstance(leaf.get("field"), list) and leaf.get("op") in ("eq", "contains", "has")):
            return None, f"bad leaf {json.dumps(leaf)[:120]}"
    return r, ""


def main():
    ap = argparse.ArgumentParser()
    if len(sys.argv) == 3 and sys.argv[1] == "--gemini-api-call":
        return gemini_api_call(sys.argv[2])
    ap.add_argument("--pair", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--prompt-record", default="lab/results/t1-prompt-v1.json")
    ap.add_argument("--author", action="append", default=[],
                    help="vendor:model, vendor in claude|codex|agy|gemini|gemini-api (key in GEMINI_API_KEY)")
    ap.add_argument("--preflight", action="store_true", help="one 'reply OK' call per author: checks model, flags, login")
    ap.add_argument("--collect", action="store_true", help="copy rules and one raw record file into lab/ of the cwd")
    ap.add_argument("--add-vendor", default="", help="with --collect: add only this vendor's answers to a pair that has "
                    "rules already (its rules next to the others, its records in t1-authors-<pair>-<vendor>.json)")
    a = ap.parse_args()
    if a.collect:
        return collect(a)
    if a.preflight:
        return preflight(a)
    pair = json.loads(pathlib.Path(a.pair).read_text())
    name = pathlib.Path(a.pair).stem
    brief = pair["brief"]
    rec = json.loads(pathlib.Path(a.prompt_record).read_text())  # the record committed to main before any rule
    prompt = rec["template"].replace("{BRIEF}", brief).replace("{EXAMPLE}", json.dumps(rec["example_event"], indent=1) + "\n")
    p_sha = hashlib.sha256(prompt.encode()).hexdigest()
    b_sha = hashlib.sha256(brief.encode()).hexdigest()
    out = pathlib.Path(a.out).expanduser()
    (out / "rules" / name).mkdir(parents=True, exist_ok=True)
    (out / "raw" / name).mkdir(parents=True, exist_ok=True)
    (out / f"prompt-{name}.txt").write_text(prompt)
    authors = [x.split(":", 1) for x in a.author]
    for vendor, _ in authors:
        need_flags(vendor, FLAGS.get(vendor, []))
    summary = []
    for vendor, model in authors:
        cli_version = ("api v1beta generateContent" if vendor == "gemini-api" else
                       subprocess.run([vendor, "--version"], capture_output=True, text=True, timeout=60).stdout.strip())
        for n in range(1, a.samples + 1):
            stem = f"{vendor}-{re.sub(r'[^a-z0-9-]', '-', model.lower())}-{n}"
            old = out / "raw" / name / f"{stem}.json"
            if old.exists():
                r = json.loads(old.read_text())
                if r.get("rc") in (0, "timeout") or r.get("stdout"):
                    summary.append((stem, "kept (already recorded)")); continue
                # the service failed before the model answered (no output): not an attempt, kept aside and run again
                keep = out / "raw" / name / "infra-failed" / f"{stem}-{r.get('started_at', 'x')}.json"
                keep.parent.mkdir(exist_ok=True)
                old.rename(keep)
            work = tempfile.mkdtemp(prefix="t1-author-")
            cmd, stdin = command(vendor, model, prompt, work)
            started = utc()
            try:
                p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=TIMEOUT, cwd=work)
                rc, so, se = p.returncode, p.stdout, p.stderr
            except subprocess.TimeoutExpired as e:
                rc, so, se = "timeout", e.stdout or "", e.stderr or ""
            text = answer_text(vendor, so if isinstance(so, str) else so.decode(), work)
            shutil.rmtree(work, ignore_errors=True)
            rule, why = one_rule(text)
            tools = tool_use(vendor, so if isinstance(so, str) else "")
            if rule is not None and tools:
                rule, why = None, f"the author used tools ({tools} events): not blind"
            raw = {"vendor": vendor, "model": model, "sample": n, "cli_version": cli_version, "started_at": started,
                   "ended_at": utc(), "rc": rc, "prompt_sha256": p_sha, "brief_sha256": b_sha, "answer": text,
                   "stdout": so if isinstance(so, str) else "", "stderr": se if isinstance(se, str) else "",
                   "tool_events": tools, "valid": rule is not None, "why_invalid": why}
            (out / "raw" / name / f"{stem}.json").write_text(json.dumps(raw, ensure_ascii=True, indent=1) + "\n")
            if rule is not None:
                rf = {"rule": rule, "model": f"{vendor}/{model}", "sample": n,
                      "params": {"cli_version": cli_version, "prompt": rec["version"], "prompt_sha256": p_sha, "started_at": started,
                                 "tool_events": "none seen" if tools == 0 else "not visible in this CLI's output"},
                      "brief_sha256": b_sha}
                (out / "rules" / name / f"{stem}.json").write_text(json.dumps(rf, ensure_ascii=True) + "\n")
            summary.append((stem, "rule" if rule is not None else f"INVALID: {why} (rc {rc})"))
            print(stem, summary[-1][1], flush=True)
    print(f"prompt sha256 {p_sha}; {sum(1 for _, s in summary if s == 'rule')} rules of {len(summary)} answers")


def preflight(a):
    bad = 0
    for vendor, model in (x.split(":", 1) for x in a.author):
        need_flags(vendor, FLAGS.get(vendor, []))
        work = tempfile.mkdtemp(prefix="t1-pre-")
        cmd, stdin = command(vendor, model, "Reply with exactly one word: OK", work)
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=300, cwd=work)
            text = answer_text(vendor, p.stdout, work).strip()
            ok = p.returncode == 0 and "OK" in text
            print(f"{'ok  ' if ok else 'FAIL'} {vendor}:{model} rc={p.returncode} answer={text[:60]!r} "
                  f"tools={tool_use(vendor, p.stdout)} err={p.stderr.strip()[-160:]!r}")
            bad += not ok
        except subprocess.TimeoutExpired as e:
            err = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
            print(f"FAIL {vendor}:{model} timeout err={err.strip()[-200:]!r}"); bad += 1
        shutil.rmtree(work, ignore_errors=True)
    print("PREFLIGHT OK" if not bad else f"PREFLIGHT: {bad} author(s) fail, fix before the real run")
    return 1 if bad else 0


def scrub(text):
    """Host data out of a record bound for the public repo: home path, user name, host name."""
    import getpass, socket
    for real, mark in ((str(pathlib.Path.home()), "~"), (getpass.getuser(), "<user>"), (socket.gethostname(), "<host>")):
        if real and len(real) > 2:
            text = text.replace(real, mark)
    return text


ACCOUNT_KEYS = ("session_id", "uuid", "credential_expires_at", "thread_id", "conversation_id", "request_id",
                "responseId")


def drop_account_metadata(text):
    """Values of account metadata keys (not secrets, but the repo is public) replaced in a CLI's raw output."""
    for k in ACCOUNT_KEYS:
        text = re.sub(r'(\\?"' + k + r'\\?"\s*:\s*\\?")[^"\\]*(\\?")', r"\1<dropped>\2", text)
    return text


def collect(a):
    """Copies out/rules/<pair>/*.json into lab/rules/<pair>/ and joins out/raw/*.json into
    lab/results/t1-authors-<pair>.json (every answer, valid or not). Refuses to overwrite."""
    name = pathlib.Path(a.pair).stem
    out = pathlib.Path(a.out).expanduser()
    v = a.add_vendor
    lab_rules = pathlib.Path("lab/rules") / name
    res = pathlib.Path("lab/results") / (f"t1-authors-{name}-{v}.json" if v else f"t1-authors-{name}.json")
    if res.exists() or (lab_rules.exists() and not v):
        sys.exit(f"STOP: {lab_rules} or {res} exists already")
    glob_pat = f"{v}-*.json" if v else "*.json"
    raws = [json.loads(p.read_text()) for p in sorted((out / "raw" / name).glob(glob_pat))]
    raws = [r for r in raws if r["brief_sha256"] == hashlib.sha256(json.loads(pathlib.Path(a.pair).read_text())["brief"].encode()).hexdigest()]
    for r in raws:  # read off the stored output after the run, the same for every author
        r["tool_attempt_denied"] = "auto-denied" in r.get("stderr", "") or '"denied_actions":["' in r.get("stdout", "").replace(" ", "")
        for k in ("stdout", "stderr"):
            r[k] = drop_account_metadata(r.get(k, ""))
    if not raws:
        sys.exit(f"STOP: no recorded answers for {name} in {out / 'raw' / name}")
    res.parent.mkdir(parents=True, exist_ok=True)
    body = scrub(json.dumps({"pair": name, "answers": raws}, ensure_ascii=True, indent=1)) + "\n"
    res.write_text(body)
    lab_rules.mkdir(parents=True, exist_ok=bool(v))
    for p in sorted((out / "rules" / name).glob(glob_pat)):
        if (lab_rules / p.name).exists():
            sys.exit(f"STOP: {lab_rules / p.name} exists already; nothing after it was copied")
        (lab_rules / p.name).write_text(p.read_text())
    print(f"{len(list(lab_rules.iterdir()))} rules into {lab_rules}, {len(raws)} answers into {res}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
