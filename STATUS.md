# Status

Updated: 2026-10-03 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed, acceptance numbers approved, Go toolchain and gates live. The attack
range of ADR 0009 is being built: `kordon-range build` makes an Arch image with mkosi, `kordon-range
run` boots it once in QEMU inside bwrap and judges what the guest reports. No sensor in the image yet.
ADR 0004 and 0009 stay proposed until their first runs pass.

## Done in the last session

- PR #13: ADR 0009 (attack range as throwaway QEMU VMs, no root). PR #14: AGENTS.md simplicity rule.
- This pull request: `internal/rangevm`, `cmd/kordon-range`, `cmd/kordon-range-guest`,
  `range/mkosi.conf` (Arch snapshot 2026/10/02, kernel 7.2.8-arch1-2), layout gate and CODEOWNERS
  for `range/`, THREAT_MODEL rows T30–T33.

## Next step

1. On the range host: `go test -tags rangehost ./internal/rangevm/`, then `kordon-range build` and
   `kordon-range run <image>`; a PASS accepts ADR 0009.
2. Sensor in the image: Laurel PKGBUILD, audit rules, auditd and Laurel config, and the ADR 0004
   smoke checks; a passing smoke test accepts ADR 0004.
3. Floor 0 code, package by package, each with its acceptance tests.

## Open decisions (maintainer)

- Project name.
- Hardware signing keys for R2 (budget approved in principle).
