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
seen and the window whole, as a guest the agent's code ran in reports it (T30). Rules, pairs and windows are files an
agent at the maintainer's uid can write (T33); the runner's results are not, but it keeps only the newest 24.

## Decision

1. Data lives in `lab/` as JSON: `pairs/<pair>.json` (technique and twin, two variants each: four runs with programs
   as text, the authors' brief, a reference rule, the ATT&CK id, the author), `rules/<pair>/<author>-<n>.json` (rule,
   model, sample, call parameters, the brief's sha256), `windows/<result id in lower case>/` (`result.json`,
   `job-laurel.txt` as the runner wrote them), `results/<date>.json`, `agent-errors.jsonl`. Known image commits
   (2c09799 today) are a constant in code; test fixtures are a decoded real window as `.jsonl` testdata.
2. A job's name binds content: `<pair>-<run>-<32 hex>`, the hex a sha256 over each of the pair's and its rules' files,
   path and bytes length-prefixed, in sorted path order, as the runner's content key. The judge recomputes it, with no
   clock and no git: a pair or rule changed or renamed after its run makes the window INVALID.
3. A window is valid only if: `result.json` is schema 1, label agent, kind exec, one run, RAN, `job_result` success,
   exit 0, a known image, the name of point 2, `program_sha256` the run's program, the directory its id in lower case;
   the unescaped window is `laurel_bytes` long, at most 6 MiB, and escapes back to the same file; every line is a JSON
   object, no duplicate key of differing value; it holds an event of the job's uid whose `EXECVE.ARGV` is
   `/bin/sh /run/balistid-job/program`, and the canary's exec under root; one window per run, programs distinct.
4. A rule is data: `all` or `any` over leaves `{field, op, value}`, op `eq`, `contains` or `has`; a field is a path in
   an event, a step on a list means some element, keys match exactly. A leaf is judged on one event, and only on
   events whose `SYSCALL.UID` is `balistid-job`; events without `SYSCALL` are outside. Pairs, rules and results decode
   strictly: exact-case keys, an unknown, duplicate or missing key or an unknown op fails. Regex waits for a reference
   rule that needs it. The controls are built in: empty `any` and empty `all`.
5. Every failed check of points 2 to 4 is INVALID with a reason from a closed list, each reason with a fixture that
   breaks only it; INVALID never counts as MISSED or QUIET (R6). Verdicts as ADR 0009 point 7: a technique run CAUGHT
   or MISSED, a twin run NOISY or QUIET. A pair counts only if its reference rule gives CAUGHT and QUIET on all four
   runs, else it is reported excluded with its reason. Each rule also runs on every other pair's windows, apart.
6. `balistid-lab` (no privilege, no network, standard library, about 500 lines): `job` writes a job directory,
   `import` copies a result into `lab/windows`, `table` and `verify` write nothing. Before signing a results tag the
   maintainer runs `verify --since <the pairs' merge on GitHub>`: each window equals the runner's original byte for
   byte, every kept result since then of a pair's program is in `lab/`, and the oldest kept result is older than
   `--since`, else a pruned run may hide a window and it fails. So the pilot stays under 24 jobs from that merge.
7. The lock: `internal/detect` and `cmd/balistid-lab` join the mutation gate in their first pull request; after gate
   B1, CODEOWNERS and `go_gate.py`'s owned roots, proven by a trial pull request that cannot pass unapproved.
8. Not closed, said in every report: a run of other content to see a window before its rule; records lost during a
   run (2c09799 reports none); events without `SYSCALL`. It measures whether a rule tells a technique from its twin
   and stays quiet on the pilot's other windows, not daily false alarms nor general skill; jobs are advisory (0011).

## Alternatives considered

- Order by git commit time: agent-set locally, undefined in a shallow clone. TOML pairs, or Go's default JSON
  decoding: no TOML module, and the defaults ignore unknown keys and case.

## Consequences

- `acceptance/1.toml` is the bar; T38 to T40 are designed rows, under a cap of 120 lines; the secret scan lets
  through only a window's `content_key`, a sha256. Revert: one pull request removing all of it.
