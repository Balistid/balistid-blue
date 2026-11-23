# 0080 — The judge reads Laurel's quoting

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-23
- Decided-by: architect at the gate after T2 (2026-11-23), maintainer's approve
- Agent: claude/opus-5.5
- Amends ADR 0079 point 4 (how `eq` and `contains` compare strings).

## Context

Laurel 0.8.2 writes a byte string (ARGV among them) with `%`, `+`, bytes below 0x20, 0x7f, invalid UTF-8 and the
BOM as `%` and two lower-case hex digits (`src/quote.rs`, URIEscapeWriter). The judge compared rule values with
those strings as written, while the prompt every author had before any window (`lab/results/t1-prompt-v1.json`)
says ARGV holds "the list of argument strings as typed". T2's `time-now` pair did not count: its reference rule,
written as typed (`strftime("%Y...`), gave MISSED on tech-b, whose ARGV holds `%25Y`. Under ADR 0077-0079 the table of
the 12 T2 windows has sha256 `f03da395...` (time-now's 22 rule rows uncounted, no verdict).

## Decision

1. `eq` on a string and `contains` compare the rule's value with the record's string as Laurel decodes to: every
   `%xx` decoded, and only when quoting the result as Laurel does gives the string back byte for byte. A string
   Laurel could not have written (`%2B`, `%2`, `%zz`, a raw `+` next to `%25`) is compared as it is, as before.
2. A string with no `%` is the same either way, so no window of T1's pairs but time-now changes: the verdicts of
   `dev-read` and `tmp-hidden` rules on all 16 windows are unchanged, and the reference of `time-now` now gives
   CAUGHT, CAUGHT, QUIET, QUIET.
3. Firewall: this ADR and its code merge before the pull request that adds the T2 windows to `lab/`; its tests use
   synthetic rules and ARGV strings copied from the windows, never `lab/rules/time-now`; no verdict of a time-now
   author rule is computed before that merge.

## Alternatives considered

- Rewrite the reference in Laurel's quoting (authors would be scored on an encoding nobody told them of, and a
  changed pair needs new jobs). A window with a malformed `%` INVALID (which Laurel fields are byte strings is
  decided in `linux_audit_parser` and not checked here, so a raw `%` elsewhere would drop a valid window).

## Consequences

- The quoting is pinned to Laurel 0.8.2 by its own test cases in `laurel_test.go`; a Laurel bump re-checks them.
  Not closed: Laurel's quoting of map keys and of `str` fields is serde's, not checked.
