# 0011 — Run range jobs for agents in a confined runner

- Status: accepted 2026-10-10 (PR 13 on 506f775: 22 runs PASS, a memory-filling exec job RAN, no OOM kill)
- Date: 2026-10-04
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Sandboxed agents have no `/dev/kvm`, so the maintainer pastes range commands; building runs the
commit's PKGBUILD and mkosi configuration with the maintainer's rights (ADR 0010). 9.3 and 9.6 need
many runs. Measured 2026-10-04 in user units: build 2 GiB peak in 1 min, run 1.6 GiB in 13 s.

## Decision

1. `balistid-runner` runs as its own system user and group, never as the maintainer: a build unit, a tick unit and
   its timer (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `StateDirectory=`, `NoNewPrivileges`, no
   capabilities, user namespaces allowed; the tick's syscalls an allowlist whose text tests pin, each tick probing
   for it as a tripwire), one job at a time under a lock. Everything root installs (binary of
   `cmd/balistid-runner`; units, timer, sysusers, tmpfiles under `/deploy/`) is one manifest a code-owned CI step
   hashes with `sha256sum` on a push to `main`; the maintainer reads that sha256 in the CI log and types it into a
   root shell, which copies the files without following links into a root-only directory, checks and installs them.
2. Its commit is `buildinfo.Version`, set by CI's `-X` (40 hex digits, else refused). At its own uid
   it builds its image: it copies the object files the maintainer drops beside the inbox with the
   ADR 0010 rules, exports its commit checked by hash, and builds there. It runs git only in that
   stage and fetches only the pinned snapshot and checked PKGBUILD sources; jobs fetch nothing.
3. Agent code never runs on the host. An agent job names one program file in the job directory, both
   capped; its bytes go on a raw job disk attached `readonly=on`, run by the guest as an unprivileged
   user in a transient unit; only the root disk boots. VMs otherwise run as in ADR 0009.
4. Jobs: `run` (self-test, N trials), `exec` (the job-disk program); output capped on results disk.
5. Agents, at the maintainer's uid, write only the inbox and read their results: a maintainer-owned
   directory of the runner's group, mode 2750, in a root-owned parent outside `/home`, `/root` and
   `/run/user`, opened without following links. The runner never changes it: it reads jobs into its
   state, keeps quota and expiry there and skips the rest (R5); the maintainer clears the inbox.
   Every inbox job is an agent job, whatever it claims. Results: the runner's 2750 setgid `agent/`,
   `evidence/` (checked). Evidence: only from the timer or install, never a request; it goes first.
6. Jobs run in that unit (`MemoryMax` without `MemoryHigh`, no swap, `TasksMax`, idle CPU, a wall
   clock). A job starts only above a memory reserve and, on each filesystem it writes, a disk reserve
   plus the sum of its caps (4x per-file `--fsize`: overlay, results, vars, scratch, ADR 0022; job disk; kept output);
   below the memory reserve it is stopped, and INVALID.
7. The runner reads a job directory only through an `os.Root`, without blocking: Lstat before
   open, regular files with one link, capped. Results name job, source, image and job disk sha256,
   runner commit, limits and exit; guest output is untrusted, printable text only. Evidence is only
   a `run` of the runner's own image with no job disk; every run is kept, one FAIL fails the
   commit. Agent verdicts are advisory, labelled `agent`; evidence has its own retention.

## Alternatives considered

- Runner at the maintainer's uid checking Claude settings (version 1): each critic round found a way
  around it; root installing a maintainer build: the agent can alter it first; `/dev/kvm` for agents.

## Consequences

- ADR 0009 point 6 and ADR 0010 point 1 amended; ADR 0010's confined branch builds are withdrawn.
- Until `balistid-install` exists this manual root install is an exception to R1 and R8, checked
  by a written procedure. `cmd/balistid`, `cmd/balistid-runner` and `internal/buildinfo` are
  code-owned and in the `go list -deps` gate; the inbox needs a sandbox allowWrite. Agents can delay, invalidate or
  (disk full) lose a FAIL of evidence (T36); forging a PASS takes a runner bug or a guest escape past QEMU and bwrap, or past KVM (T31, T37). A newer `main` is a reinstall.
- Tests: job-dir links, hard links, FIFOs refused unopened; an inbox job builds nothing, is never
  evidence; the procedure refuses a sha256 CI did not log. T31, T33, T34 change, T35-T37 added.
