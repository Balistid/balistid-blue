# Status

Updated: 2026-10-01 by claude/opus-5.5

## Where we are

Floor 0 (recorder) designed and its acceptance numbers approved (PR #10); the Go toolchain and CI
job land in this pull request. No floor-0 code yet beyond `kordon version`. ADR 0004 stays proposed
until its smoke test.

## Done in the last session

- PR #8: zizmor replaces the regex pin check, with executable tests against the pinned binary.
- PR #9: ADR 0003–0007; R7 reshaped them to components and properties.
- PR #10: `THREAT_MODEL.md` (28 rows) and `acceptance/0.toml` (33 metrics), approved.
- This pull request: Go 1.27.1 toolchain, a `go` CI job (format, modules, vet, golangci-lint,
  govulncheck, race tests, reproducible build), and the layout gate for Go and deploy paths, which
  refuses every path gitleaks would skip and holds `go.mod`/`go.sum` to a line grammar.
- The project name is still open; "Kordon" is a working name (kordon.app is an existing product).

## Next step

1. Maintainer pushes this branch (workflow change) and adds `go` to the required checks.
2. Smoke test auditd + Laurel in the range VM (needs `/dev/kvm`).
3. Floor 0 code, package by package, each with its acceptance tests.

## Open decisions (maintainer)

- Project name.
- Hardware signing keys for R2 (budget approved in principle).
