# 0037 — Run one range trial on GitHub's KVM on request

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-31
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Measuring code goes to KVM before review, and a time trial needs a run of its own (ADR 0036). An agent's sandbox
has no `/dev/kvm`, the local runner builds only its installed commit (ADR 0011), and `range-kvm` runs only the
self-test (ADR 0028). So the maintainer built and ran each new trial by hand: L11a's six took 2.5 hours, twice.

## Decision

1. Workflow `range-trial`, on `workflow_dispatch` with one input `trial`, checks out the dispatched ref, builds its
   image and runs `balistid-range trial <trial>` once, through `tools/ci/range_kvm.py --trial`. The name must be
   `^[a-z0-9-]{1,32}$` before anything runs, reaches the container only as an environment variable, and the
   launcher's closed table refuses any other (T37).
2. The rest is ADR 0028 points 2 and 3 unchanged: the same container and pins, no secret, `contents: read`, no
   checkout credentials, nothing uploaded, workflow commands off while the build prints. The input reaches the
   step only through `env`, never as expression text in `run`. 60 minutes cover a build and a trial's wall clock
   (at most 29 minutes, ADR 0018).
3. Like `range-kvm`, the verdict is advisory and never evidence or an acceptance verdict. A run whose trial gives
   its expected verdict replaces the maintainer's KVM run of that trial before review. Dispatching needs write
   access to Actions (the maintainer; the bot only if its installation grants it); the run executes what the
   ref's pull request CI already executes.

## Alternatives considered

- Every trial on every pull request: over 30 trials of 5 to 26 minutes each, hours of runners for changes that touch no
  trial. A label on the pull request: same reach, and a label is easier to set by mistake than a dispatch.
- The local runner building a ref on request: refused in ADR 0028 (agent code on the host at the evidence uid).

## Consequences

- Amends ADR 0028 points 1 and 4: besides the self-test, one trial per dispatch.
- Residuals: GitHub's runner is not the reference host, so steal, timing and CPU differ (the reason the verdict
  is advisory); the workflow must be on `main` before it can be dispatched.
- Tests: a bad trial name fails before docker; the name goes in by environment, not script text; the job has no
  secret or write permission and runs one command with the input from `env`.
