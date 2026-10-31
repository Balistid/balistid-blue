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

1. Workflow `range-trial`, on `repository_dispatch` of type `range-trial`, runs as it is on `main`: a dispatched
   commit cannot rewrite it. The payload's `sha` (40 hex) and `trial` (`^[a-z0-9-]{1,32}$`) are checked first,
   then that commit is checked out as data, its image built and `balistid-range trial <trial>` run once through
   `tools/ci/range_kvm.py --trial`; an empty or bad name fails there too, never falls back to the self-test. The
   name reaches the container only as an environment variable; the launcher's table refuses any other (T37).
2. The rest is ADR 0028 points 2 and 3 unchanged: the same container and pins, no secret, `contents: read`, no
   checkout credentials, nothing uploaded, workflow commands off while the build prints. The payload reaches
   steps only through `env` and the checkout's `ref`, never as expression text in `run`. 60 minutes cover a
   build and a trial's wall clock (at most 29 minutes, ADR 0018). Only a run whose launcher exits non-zero, a
   verdict other than the trial's expected one, is annotated: a control's expected MISS is no error.
3. Like `range-kvm`, the verdict is advisory and never evidence or an acceptance verdict. A run whose trial gives
   its expected verdict replaces the maintainer's KVM run of that trial before review. Dispatching needs
   `contents: write`, which the bot holds: an agent runs its own trial before review; the run executes the
   named commit as a pull request's CI already would.

## Alternatives considered

- Every trial on every pull request: over 30 trials of 5 to 26 minutes each, hours of runners for changes that touch no
  trial. A label on the pull request: same reach, and a label is easier to set by mistake than a dispatch.
- `workflow_dispatch`: it runs the definition on the dispatched ref, which that ref can rewrite to ask for the
  token's write scopes or secrets; only the bot's missing `workflows` permission, not the repository, stops it.
- The local runner building a ref on request: refused in ADR 0028 (agent code on the host at the evidence uid).

## Consequences

- Amends ADR 0028 points 1 and 4: besides the self-test, one trial per dispatch.
- Residuals: GitHub's runner is not the reference host, so steal, timing and CPU differ (the reason the verdict
  is advisory); any commit the repository reaches can be named, a fork's pull request head too, and its
  `range_kvm.py` runs with sudo on the throwaway runner, as in pull request CI.
- Tests: a bad or empty trial name fails before docker; the name goes in by environment, not script text; an
  expected MISS is not annotated; the workflow is `repository_dispatch` only, checks the payload before the
  checkout and takes it only through `env` and `ref`.
