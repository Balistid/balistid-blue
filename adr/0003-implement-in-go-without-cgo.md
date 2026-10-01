# 0003 — Implement Kordon in Go, without cgo

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Floor 0 is a set of long-running daemons, a CLI, SQLite stores, a Merkle log and a witness on a
Raspberry Pi (ADR 0005–0007). The libraries we build on are Go: Tessera v1.0.4 (Go 1.26),
torchwood/litewitness v0.10.0 (Go 1.27), modernc.org/sqlite v1.60.1 (pure Go, SQLite 3.53.4).
Go 1.27.1 is current; 1.27 and 1.26 are supported (go.dev/dl, 2026-10-01). Arch's `go` package
reports `go1.27.1-X:nodwarf5`, a different build from upstream's. The maintainer ruled out C.

## Decision

1. Runtime code (daemons, CLI, Pi helpers) is Go only; Python stays for CI tooling and never runs on
   the host or the Pi.
2. Dependency selection is `go.mod` plus `go.sum`, both committed. Builds run with
   `GOFLAGS=-mod=readonly`, `GOWORK=off`, `GOTOOLCHAIN=go1.27.1` (the upstream toolchain, not the
   distribution's) and `CGO_ENABLED=0 -trimpath -buildvcs=false`. A `replace` directive to a local
   path fails CI. A toolchain or dependency bump is its own commit (R14).
3. Release binaries are built only in CI. CI runs `gofmt -l` (empty), `go vet`, golangci-lint
   v2.14.0, govulncheck v1.8.0 and `go test -race ./...`; the race detector needs cgo, so only the
   test job enables it. Tool binaries are installed pinned by sha256.
4. A follow-up pull request extends the layout gate (`tools/ci/docs_budget.py`) to admit exactly:
   `go.mod`, `go.sum`, `.golangci.yml`; `cmd/<name>/*.go`; `internal/<pkg>/*.go` and one level of
   `internal/<pkg>/<sub>/*.go`; `testdata/*.json` and `*.jsonl` under those directories;
   `packaging/<name>/PKGBUILD`; `deploy/audit/*.rules`; `deploy/auditd/auditd.conf`;
   `deploy/laurel/config.toml`; `deploy/systemd/*.service`, `*.socket`, `*.timer`. Each pattern ships
   with a positive and a negative test. Nothing else is admitted by this ADR.

## Alternatives considered

- Rust: Laurel is Rust, but Tessera and torchwood are Go; using them from Rust means FFI or a rewrite.
- cgo SQLite (mattn/go-sqlite3): rejected to avoid a C toolchain and to keep static cross-builds
  for the Pi simple. Durable end-to-end throughput on the target hardware is still to be measured.
- Python runtime: no static binary and a larger interpreter surface in a privileged process.

## Consequences

- CI builds the same commit twice in different directories and fails unless both sha256 match.
  A build with cgo enabled or a local `replace` fails the release job.
- New CI jobs and their required-check entries in the `main` ruleset are added by the maintainer,
  because the bot cannot change workflows (ADR 0002).
- `govulncheck` findings in reachable code fail CI; an accepted exception needs an ADR.
- The toolchain pin is reviewed at every Go release; Go 1.26 support ends when Go 1.28 ships.
