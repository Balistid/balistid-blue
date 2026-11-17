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
agent at the maintainer's uid can write (T33); the runner's results are not, and it prunes the oldest beyond 24.

## Decision

1. `lab/` holds JSON: `pairs/<pair>.json` (technique and twin, two variants each: four runs, each a `#!/bin/sh`
   program as text with its program name and `timeout_s`; the authors' brief; a reference rule; the ATT&CK id; the
   author), `rules/<pair>/<author>-<n>.json` (rule, model, sample, call parameters, the brief's sha256),
   `windows/<result id in lower case>/` (`result.json`, `job-laurel.txt` as the runner wrote them), `results/`,
   `agent-errors.jsonl`. Known images (2c09799) are a code constant; test results and keys are built at runtime.
2. A job's name is `<pair>-<run>-<32 hex>` (pair and run in 30 characters), the hex a sha256 over each of the pair's
   and its rules' files, path and bytes length-prefixed in sorted order. The judge recomputes it and the runner's
   `content_key` from the run's request, with no clock and no git: changed or renamed content makes a window INVALID.
3. A window is valid only if: `result.json` is schema 1, label agent, kind exec, one run, RAN, `job_result` success,
   exit 0, a known image, name and `content_key` of point 2, `program_sha256` the run's, the directory its id in lower
   case; it is the only window in `lab/` of that program; the unescaped window is `laurel_bytes` long, at most 6 MiB,
   and escapes back to the same file; every line a JSON object, no duplicate key of differing value; it holds an event
   of the job's uid whose `EXECVE.ARGV` is `/bin/sh /run/balistid-job/program`, and the canary's exec under root.
4. A rule is data: `all` or `any` over leaves `{field, op, value}`, op `eq`, `contains` or `has` (no `value`); a
   field is a path in an event, a step on a list means some element. A leaf is judged on one event, only on events
   whose `SYSCALL.UID` is `balistid-job`. Pairs, rules and results decode strictly: exact-case keys, each object's
   closed set of required and optional keys (the runner's `omitempty` keys optional, `job_exit` required for RAN).
5. Each failed check of points 2 to 4 is INVALID with a reason from a closed list, each with a fixture breaking only
   it; INVALID never counts as MISSED or QUIET (R6). A pair counts only if its reference rule gives CAUGHT and QUIET
   on all four runs, else it is reported excluded with its reason; each rule also runs, apart, on other pairs' windows.
6. `balistid-lab` (no privilege, no network, standard library, about 500 lines): `job` writes a job directory,
   `import` copies a result into `lab/windows`; `table` and `verify` take no time or name and write nothing. The
   anchor is a code constant, the runner's result `20261116T163124Z-ba1549c1-p0-smoke-1`, made before any pair. As
   the runner prunes oldest first, while the anchor is kept every later result is. Before signing a results tag the
   maintainer runs `verify` (`GOENV=off GOFLAGS= GOWORK=off`) from a clean checkout of the tagged commit: it fails
   unless the anchor is kept in `results/agent` and the results after it are exactly `lab/windows`, files and bytes.
   The pilot ends 23 jobs after the anchor, a new one needs an ADR; `job-laurel.txt` waits for a decoded secret scan.
7. The lock: `internal/detect` and `cmd/balistid-lab` join the mutation gate in their first pull request; after gate
   B1, CODEOWNERS and `go_gate.py`'s owned roots, proven by a trial pull request that cannot pass unapproved.
8. Not closed, said in every report: a window made outside the runner (the image boots under any KVM) can inform a
   rule, so blindness is procedure, not proof; loss during a run (2c09799 reports none); host root, its clock too; a
   shell running what an agent prepared; an extra run excluding a pair. It measures if a rule tells a technique from
   its twin and stays quiet on other windows, not daily false alarms nor general skill; jobs are advisory (ADR 0011).

## Alternatives considered

- A time or merge given to `verify`: the agent moves it; a root read of the ledger shows only what the anchor shows.

## Consequences

- `acceptance/1.toml` is the bar; T38 to T40 are designed rows, under a cap of 120 lines; the secret scan lets
  through only a window's `content_key`, a sha256. Revert: one pull request removing all of it.
