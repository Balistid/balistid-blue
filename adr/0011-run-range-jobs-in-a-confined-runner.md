# 0011 — Run range jobs for agents in a confined runner

- Status: proposed
- Date: 2026-10-04
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Agents have no `/dev/kvm`, so the maintainer pastes range commands; building an image runs the
commit's PKGBUILD and mkosi configuration with the maintainer's rights (ADR 0010). 9.3 and 9.6 need
many runs. Measured 2026-10-04 in user units: build 2 GiB peak in 1 min, run 1.6 GiB in 13 s.

## Decision

1. `kordon-runner` is built by the maintainer from the ADR 0010 export of a `main` commit in the
   runner's bare repository, with the ADR 0010 point 4 environment (`GOENV=off`, own `GOCACHE` and
   `GOMODCACHE`, `GOPROXY=off`), commit set with `-ldflags -X`, never from a work tree; installed
   where agents cannot write, never self-updated; a user oneshot and timer run one job at a time. It
   boots only its own commit's image, built into its state at install by the maintainer (ADR 0010),
   sha256 recorded; others refused.
2. Agents cannot write its binary, configuration, deploy key (read-only, never the bot key,
   unreadable by agents) or state; they read their results. At start it checks these denials, that
   the sandbox cannot be turned off and that excluded commands are only allowlisted, in the Claude
   managed, user and repository settings and every Codex profile (`/run/user/$UID` denied), else
   refuses; empty environment. Its git: no system or global config or hooks, ssh `-F /dev/null`; it
   fetches `main`.
3. Agent code never runs on the host. An agent job names one program file in the job directory, both
   capped; its bytes are copied onto a raw job disk attached `readonly=on`, which the guest unit
   runs only when attached. VMs run as in ADR 0009.
4. Jobs: `run` (self-test, N trials), `exec` (the job-disk program); output capped on results disk.
5. Every inbox request is an agent job, whatever it claims: strict, capped JSON, one inbox quota,
   expiry (R5). Maintainer jobs come only from `kordon-runner` writing its own state, which agents
   cannot (point 2); they and the timer go first.
6. A job runs in a transient unit (`MemoryHigh` below `MemoryMax`, no swap, `TasksMax`, idle CPU,
   `KeyringMode=private`, a wall clock). It starts only with free memory and disk above a reserve;
   the runner stops it if available memory falls below the reserve. A stopped job is INVALID.
7. The runner reads a job directory only through an `os.Root`, without blocking: regular files,
   capped. Results name job, source, image and job disk sha256, runner commit, limits and exit;
   guest output is untrusted, printable text only. Evidence is only a `run` of the runner's own
   image by the timer or the maintainer, with no job disk; every run is kept, one FAIL fails the
   commit. Agent verdicts are advisory, labelled `agent`; evidence has its own retention.

## Alternatives considered

- A launcher per `main` commit runs repository code on the host again; a dedicated uid (better on
  T33) waits for `kordon-install`; `/dev/kvm` for agents widens every session.

## Consequences

- ADR 0009 point 6 (job disks) and ADR 0010 point 1 amended; ADR 0010's promise of confined branch
  builds is withdrawn. Evidence covers the installed commit; a newer `main` needs a reinstall.
- A CI gate keeps every package the runner, guest and launcher import, and all in the image,
  code-owned (`go list -deps`); no external modules (`GOPROXY=off`) without a new ADR.
- `exec` tests the installed sensor only; the agent judges its stream, the host takes no pattern.
- Unsandboxed tools at this uid, or project settings in a directory the runner does not check, can
  change runner state (T33); agents can starve evidence (DoS).
- Tests: job-dir links, hard links and FIFOs refused unopened; missing denials stop the runner; any
  inbox request is an agent job that builds nothing and is never evidence. T31, T33, T34 change,
  T35–T37 added, numbers first (R3); a second VM gets its own ADR.
