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
GitHub's standard `ubuntu-24.04` runner has 4 vCPUs and 16 GB RAM, and its Linux runners expose KVM after a udev
rule (docs.github.com runner reference and changelog 2024-04-02, read 2026-10-28). Measured on pull request #146:
PASS at a875251 in 4 min with 87 GiB free; a commit whose guest reported a wrong laurel user (eb0272e) FAILed.

## Decision

1. CI job `range-kvm` builds the commit CI checked out with `balistid-range build` (ADR 0010's verified export)
   and runs its self-test with `balistid-range run`, on every pull request and push to `main`.
2. `tools/ci/range_kvm.py` opens `/dev/kvm` with the changelog's udev rule and allows unprivileged user namespaces,
   with sudo on the throwaway runner: R8 and R13 govern the host, not GitHub's VM; a check keeps the script off
   other machines by mistake. A missing `/dev/kvm`, too little disk or a verdict other than PASS fails the job,
   never skips it (R6). Workflow commands are off while the build prints, so no package output can annotate the
   run whose log carries the runner bundle's sha256.
3. The Arch tools run in `archlinux` pinned by digest, as an unprivileged user with the runner's uid, the source
   read-only. Host packages, Arch's go among them, are pinned by a dated archive snapshot and Arch's signatures,
   not by hash: the R14 exception `range/mkosi.conf` already makes. The job has no secret, no write permission,
   does not persist the checkout's credentials and uploads nothing: the tested code writes the state directory,
   and upload-artifact follows its symlinks into the runner's own files.
4. The verdict is advisory and never evidence: evidence and acceptance metrics come only from the local runner
   on the reference host (ADR 0011 point 7, ADR 0025). The pull request controls its launcher, judge, guest and
   this job, as it did when the maintainer built it; review is the control. A green `range-kvm` replaces the
   maintainer's KVM run before review; a change to the judge or this job that lets it pass more often is a gate
   change and review reads it as one (ENGINEERING.md 3). It is not a required check, and not in `go-release`'s
   `needs`, until a week of runs shows how often it fails for reasons outside the commit.

## Alternatives considered

- The runner builds a commit an agent asks for: agent code on the host at the uid that writes evidence, a new
  uid, units and a root install, all to save the maintainer a paste on one host.
- No change: the maintainer keeps building unreviewed commits at their own uid for every check.

## Consequences

- ADR 0009 point 1 amended: the range also runs on GitHub's runners. ADR 0011 is unchanged.
- The range build downloads the image snapshot, Go modules and Laurel in CI, as it does locally (T23).
- Nested KVM on a shared Azure host is slower and noisier than the reference host, so trials and timing
  metrics stay with the runner even where the disk would hold them.
- An approved fork's pull request gets a 45-minute KVM runner; the repository's fork-approval setting bounds it.
- Tests: `test_range_kvm.py` (pins, no secret, permission, upload or skip, refusal off GitHub, missing KVM,
  disk, a FAIL, workflow commands off around the build); the PASS and FAIL runs above.
