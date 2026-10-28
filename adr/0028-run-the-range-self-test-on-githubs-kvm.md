# 0028 — Run the range self-test of every pull request on GitHub's KVM

- Status: proposed (accepted when merged with the maintainer's approval, after the job PASSes on its pull request)
- Date: 2026-10-28
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Sandboxed agents have no `/dev/kvm` (ADR 0011), so the maintainer builds and runs each commit an agent wants
checked in the range, under the maintainer's uid, before review: what ADR 0010's consequences rule out. A runner
that builds a commit an agent names would run that commit's PKGBUILD, mkosi configuration and assembly on the
host at the runner's uid, which also writes evidence (ADR 0011 points 3 and 7, T37). The repository is public;
GitHub's standard `ubuntu-24.04` runner has 4 vCPUs, 16 GB RAM and a 14 GB SSD, and its Linux runners expose
KVM after a udev rule (docs.github.com runner reference and changelog 2024-04-02, read 2026-10-28; not yet run).

## Decision

1. CI job `range-kvm` builds the pull request's head commit with `balistid-range build` (ADR 0010's verified
   export) and runs its self-test with `balistid-range run`, on every pull request and push to `main`.
2. `tools/ci/range_kvm.py` refuses anywhere but a GitHub-hosted runner, opens `/dev/kvm` with the changelog's
   udev rule and allows unprivileged user namespaces there; a missing `/dev/kvm`, too little disk or a verdict
   other than PASS fails the job, never skips it (R6).
3. The Arch tools run in `archlinux` pinned by digest, packages from a dated archive snapshot (R14), as an
   unprivileged user with the runner's uid; the source is mounted read-only. The job has no secret, no write
   permission and does not persist the checkout's credentials. Results are kept 14 days as an artifact (R5).
4. The verdict is advisory and never evidence: evidence and acceptance metrics come only from the local runner
   on the reference host (ADR 0011 point 7, ADR 0025). A green `range-kvm` replaces the maintainer's KVM run
   before review; trials and timing metrics stay with the runner. The job is not a required check until a week
   of runs shows how often it fails for reasons outside the commit.

## Alternatives considered

- The runner builds a commit an agent asks for: agent code on the host at the uid that writes evidence, a new
  uid, units and a root install, all to save the maintainer a paste on one host.
- No change: the maintainer keeps building unreviewed commits at their own uid for every check.

## Consequences

- ADR 0009 point 1 amended: the range also runs on GitHub's runners. ADR 0011 is unchanged.
- The range build downloads the image snapshot, Go modules and Laurel in CI, as it does locally (T23).
- A pull request runs its own workflow and script, so an agent can make its job pass; the result is trusted only
  as far as review of the commit and GitHub (T33, T37), which is why it is advisory.
- 14 GB of disk fits the self-test, not the 16 GiB scratch of the sustained trial: trials stay local.
- Nested KVM on a shared Azure host is slower and noisier than the reference host: no timing metric is read.
- Tests: `test_range_kvm.py` (pins, no secret or privilege, refusal off GitHub, missing KVM, disk, a FAIL);
  the job's first PASS on its pull request accepts this ADR, and one commit whose guest withholds a fact FAILs.
