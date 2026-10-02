# Status

Updated: 2026-10-02 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed, acceptance numbers approved, Go toolchain and gates live (PR #11).
No floor-0 code yet beyond `kordon version`. ADR 0004 stays proposed
until its smoke test.

## Done in the last session

- PR #8–#10: pin gate tests, ADR 0003–0007, THREAT_MODEL.md and acceptance/0.toml.
- PR #11: Go 1.27.1 toolchain, four isolated Go CI jobs, layout gate on every commit, rescan of files
  gitleaks skips across history; the ruleset requires all ten checks.
- This pull request: ADR 0008 and ENGINEERING.md section 7 (Go rules) with the matching lint config.
- The project name is still open; "Kordon" is a working name (kordon.app is an existing product).

## Next step

1. Smoke test auditd + Laurel in the range VM (needs `/dev/kvm` and the VM image), then ADR 0004
   becomes accepted.
2. Floor 0 code, package by package, each with its acceptance tests.

## Open decisions (maintainer)

- Project name.
- Hardware signing keys for R2 (budget approved in principle).
