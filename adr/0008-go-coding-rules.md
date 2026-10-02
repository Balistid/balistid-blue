# 0008 — Write Go to the rules in ENGINEERING.md section 7

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-02
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

ADR 0003 chose Go and its tools but no coding rules, and ENGINEERING.md §3 leaves language rules to
an ADR. Floor 0 is a set of long-running services that parse untrusted records, hold a signing key
and decide health (ADR 0004–0007). The failure modes that matter are swallowed errors that turn into
"healthy" (R6), unbounded work driven by input (T20), files written without durability or with the
wrong mode, the wall clock deciding retention (T22), and dependencies that change what we ship (R14).

## Decision

1. ENGINEERING.md gains §7 Go: errors, context, goroutines, untrusted input, files, processes, time,
   logging, packages, forbidden packages, dependencies and tests. Each rule says whether lint or
   review enforces it.
2. `.golangci.yml` enforces what a linter can check: errcheck, errorlint, wrapcheck (errors);
   forbidigo (`panic`, `print`, `context.Background`/`TODO` outside `main` and tests); contextcheck
   and noctx (contexts); depguard (`unsafe`, `math/rand`, `log`); gosec (exec, files, crypto).
   A `//nolint` needs a named linter and a reason (nolintlint).
3. The rest (goroutine ownership, atomic writes, symlink-safe opens, monotonic time, licences) is a
   review item for every pull request that touches `internal/`.

## Alternatives considered

- Adopting the Uber or Google Go style guide wholesale: broad and mostly about style; it does not
  name our failure modes, and a long guide nobody checks becomes the documentation SP1 drowned in.
- Lint only: catches calls, not design (who stops a goroutine, how a file becomes durable).

## Consequences

- Current code passes the stricter lint with 0 issues; a probe file in a scratch copy triggered
  every new linter before this was merged.
- Code that needs an exception carries a `//nolint:<linter> // reason` that the reviewer sees.
- Changing a rule needs an ADR, as for any rule in ENGINEERING.md.
