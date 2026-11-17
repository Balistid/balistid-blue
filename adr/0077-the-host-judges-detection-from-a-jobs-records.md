# 0077 — The host judges detection from a job's records

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-17
- Decided-by: jvc0n (2026-11-17, in session)
- Agent: claude/opus-5.5
- Amends ADR 0009 point 7 (who computes the verdict, from what), ADR 0011 (an agent job as a measured run), ADR 0014
  and 0049 (the threat model's cap), the layout allowlist and the secret scan's allowlist.

## Context

Floor 1 starts as measurement (ADR 0076): a rule must catch a technique and stay quiet on its legitimate twin. The
runner's agent jobs (ADR 0011) export the Laurel records a job caused, its window, and give RAN only with the canary
seen and the window whole, as reported by a guest the agent's code ran in (T30). Rules, pairs and windows are files an
agent at the maintainer's uid can write (T33): a verdict rests on checks of their content and on the runner's originals.

## Decision

1. Data lives in `lab/` as JSON: `pairs/<pair>.json` (a technique and its twin, two variants each, as four runs with
   their programs as text; the brief for rule authors; a reference rule; the ATT&CK id; the author),
   `rules/<pair>/<author>-<n>.json` (the rule and its origin: model, sample, call parameters, the brief's sha256),
   `windows/<result id in lower case>/` (`result.json` and `job-laurel.txt` with the runner's bytes unchanged),
   `results/<date>.json` and `agent-errors.jsonl`. The known image commits (2c09799 today) are a constant in code.
2. A job's name binds it to content: `<pair>-<run>-<16 hex of sha256 over the pair file and its rule files>`. The
   judge recomputes it and uses no clock and no git, so a rule or pair changed after its run makes the window INVALID.
   Not closed: a run under another name to see a window first; `verify` lists such runs of a pair's program.
3. A window is valid only if: `result.json` is schema 1, label agent, kind exec, one run, RAN, `job_result` success,
   exit 0, a known image, the name of point 2, `program_sha256` the run's program, the directory its id in lower case;
   the unescaped window is `laurel_bytes` long, under 6 MiB, and escapes back to the same file; every line is a JSON
   object with no duplicate key of differing value; it holds the exec of `/run/balistid-job/program` under the job's
   uid and the canary's exec under root; one window per run, the runs' programs distinct. Every other case is
   INVALID with a reason from a closed list, and INVALID never counts as MISSED or QUIET (R6).
4. A rule is data: `all` or `any` over leaves `{field, op, value}`, op `eq`, `contains` or `has`; a field is a path in
   an event, a path step on a list means some element, keys match exactly. A leaf is judged on one event, and only
   events whose `SYSCALL.UID` is `balistid-job`. A rule that does not decode is INVALID, never QUIET. Regex waits for
   a reference rule that needs it. The controls are built in: empty `any` and empty `all`.
5. Verdicts as ADR 0009 point 7: a technique run CAUGHT or MISSED, a twin run NOISY or QUIET. A pair counts only if
   its reference rule gives CAUGHT and QUIET on all four runs; otherwise it is reported as excluded with its reason.
   Every rule also runs on every other pair's windows, and those matches are reported apart.
6. `balistid-lab` (no privilege, no network, standard library, about 500 lines): `job` writes a job directory,
   `import` copies a runner result into `lab/windows`; `table` and `verify` write nothing. `verify` compares each
   window with the runner's original byte for byte (missing is unverified), lists the runner's results of a pair's
   program that `lab/` lacks, and runs as the maintainer before a results tag is signed.
7. The lock: `internal/detect` and `cmd/balistid-lab` join the mutation gate in their first pull request; after gate
   B1, CODEOWNERS and `go_gate.py`'s owned roots, proven by a trial pull request that cannot pass unapproved.
8. Every report states: it measures whether a rule tells a technique from its twin and stays quiet on the pilot's
   other windows; not false alarms in daily use, not a model's general skill; agent jobs are advisory (ADR 0011);
   the window is guarded only against rotation and its cap.

## Alternatives considered

- Order by git commit time: agent-set locally and undefined in a shallow clone; the name binds the content instead.
- Pairs in TOML: no TOML module in `go.mod`, and a hand parser is one more fuzz target.
- Reuse `internal/rangevm`'s judge: owned range code this week's plan keeps unchanged; the verdicts differ.

## Consequences

- `acceptance/1.toml` holds the instrument's bar; T38 to T40 are designed rows; the threat model's cap is 120 lines.
- The secret scan lets through only a window's `content_key`, a sha256 it reads as a key. Revert: a pull request
  removing this file, `acceptance/1.toml`, the rows, the layout lines and that allowlist entry.
