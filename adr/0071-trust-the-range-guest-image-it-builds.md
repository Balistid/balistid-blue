# 0071 — The range trusts the guest image it builds

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-09
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-09)
- Agent: claude/opus-5.5
- Closes issue #275; amends THREAT_MODEL.md T30.

## Context

The host binds a guest's result stream only to the trial and phase it gave the guest (`echoes` in
`internal/rangevm/vm.go`), so a stream saved from an earlier valid run is judged again as a new one. Codex review of
#273 reproduced it for `anchor-sustained`, `truncation-11` and `truncation-10`; `rate-sustained` on `main` is the same.

A replay is one case of a guest that lies. A guest able to write an old stream can as well write new values it never
measured, so a check against replay alone would refuse nothing a lying guest needs. Only facts the host observes
itself, outside the guest, would bind a result to the run; the guest's filesystem stays unopened (ADR 0009).

The guest that would lie is this repository's own code. A result counts only when the launcher is a clean build of
the image commit (T33, ADR 0011, 0018), and each run and boot gets a new sparse results disk in a new run directory
(`boot` and `prepare` in `vm.go`), so no stream is left from an earlier run by accident.

## Decision

1. The range trusts the guest image it builds as it trusts its judge: a guest that replays or invents facts needs
   code in the image, which lands only through a reviewed commit, the path a judge that passes without facts takes.
2. T30 keeps its defences of the host reader against hostile bytes. It does not claim that a well-formed stream
   comes from the current run; the image commit and the new results disk are the only binding.
3. No nonce is added: the guest echoes it onto any values, so it would claim a binding it does not give.
4. A new ADR reopens this when the guest runs code that is not from this repository's commits (a third party's
   workload, a user's sample), or when range results serve as evidence for someone who does not trust those commits.

## Alternatives considered

- A nonce the guest echoes: stops only an accident the new results disk already stops.
- A per-run key the host injects and the guest signs with: the guest holds the key and signs old values.
- Facts the host observes per trial (QEMU's clock, a read of the guest's disk after power-off): binds a result to
  its run, but every fact needs its own host path and the disk read breaks ADR 0009; it buys nothing while the
  guest's code is reviewed, and a reviewer can ask for it once point 4 holds.

## Consequences

- T30 says the range trusts its own image. Changes to `cmd/balistid-range-guest` keep their review (ENGINEERING §5):
  a guest that writes a fact not taken from the current boot (a constant, a cached value) is a finding, as a judge
  that passes without facts would be.
- The reproductions of #275 stay true and are not a defect under this ADR.
- Revert: a pull request removing this file and the T30 sentence.
