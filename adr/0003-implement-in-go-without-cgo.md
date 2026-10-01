# 0003 — Implement Kordon in Go, without cgo

- Status: accepted
- Date: 2026-10-01
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Floor 0 is a long-running daemon, a CLI, a SQLite store, a Merkle log and a witness on a Raspberry Pi
(ADR 0005, 0006). The libraries we build on are Go: Tessera v1.0.4 (Go 1.26), torchwood/litewitness
v0.10.0 (Go 1.27), modernc.org/sqlite v1.60.1 (pure Go). Go 1.27.1 is the current release; 1.27 and
1.26 are supported (go.dev/dl, checked 2026-10-01). The maintainer ruled out C; Rust would mean
reimplementing or wrapping the transparency-log stack. Python is already used for CI tools.

## Decision

1. Runtime code (daemon, CLI, Pi helpers) is Go only. `go.mod` declares `go 1.27` and
   `toolchain go1.27.1`; a toolchain bump is its own commit (R14).
2. Release binaries build with `CGO_ENABLED=0 -trimpath` and no build ID or VCS stamping that differs
   between machines. Dependencies come from `go.sum` only.
3. CI runs `gofmt -l` (empty), `go vet`, golangci-lint v2.14.0, govulncheck v1.8.0 and
   `go test -race ./...`. The race detector needs cgo, so only the test job enables it.
   Tool binaries are installed pinned by sha256, as for the existing gates.
4. Python stays for CI tooling only and never runs on the host or the Pi.
5. The repository layout gate (`tools/ci/docs_budget.py`) is extended by a follow-up pull request
   to admit exactly: `go.mod`, `go.sum`, `.golangci.yml`, `cmd/<name>/*.go`,
   `internal/<pkg>/[<sub>/]*.go`, and `testdata/` directories under those with `*.json`/`*.jsonl`
   fixtures. Each new pattern ships with a negative test. Nothing else is admitted by this ADR.

## Alternatives considered

- Rust: Laurel is Rust, but Tessera, torchwood and the C2SP Go clients have no maintained Rust
  equivalent; we would write our own Merkle log client (R9).
- cgo SQLite (mattn/go-sqlite3): about 1.6× faster inserts in one benchmark (cvilsmeier/go-sqlite-bench,
  March 2026), but breaks static, reproducible builds and cross-compiling to the Pi. The pure-Go driver
  has about 40× headroom over our peak rate (ADR 0005), so speed does not decide.
- Python runtime: no static binary, larger attack surface on a root daemon.

## Consequences

- Two release builds of the same commit from different directories produce the same sha256; CI checks
  it. A build with cgo enabled fails the release job.
- New CI jobs and their required-check entries in the `main` ruleset are added by the maintainer,
  because the bot cannot change workflows (ADR 0002).
- `govulncheck` findings in reachable code fail CI; an accepted exception needs an ADR.
- Go 1.26 support ends when Go 1.28 ships; the toolchain pin is reviewed at every Go release.
