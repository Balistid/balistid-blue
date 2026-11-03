# 0052 — Name where each floor-0 metric is decided

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: claude/opus-5.5 (delegated by alex, 2026-11-02)
- Agent: claude/opus-5.5
- Closes the decision of issue #213; amends ADR 0022 point 2 (who measures `headroom_gib`).

## Context

The 9.5 gate needs every floor-0 metric decided somewhere. Six in `acceptance/0.toml` have no range trial and no
stated place: `raw_cap_gib`, `shard_max_gib`, `headroom_gib`, `truncation_alarm_per_hour`, `verify_freshness_s` and
`anchor_interval_s`; `rangerun.Metrics()` lists only the twelve the range decides. Go tests prove the logic of
three (`TestTruncationAlarm11vs10`, `TestVerifyFreshness` in `internal/watch/alarm_test.go`,
`TestBatchesCoverTheStreamInCuts` in `internal/anchor/anchor_test.go`) with fake clocks or events, not on a
real host. ADR 0022 sent the
store's three to B5 "with the installed value", but the range runs a 64 MiB reserve, and #202 changes the defaults.

## Decision

1. A metric is decided by a range trial, a test on the installed defaults, or a measurement on the Pi or the host
   named here; a Go test proves only the logic and never decides a number on its own.
2. `raw_cap_gib`, `shard_max_gib` and `headroom_gib` are decided by the fill test of the install defaults that #202
   adds for `disk_default_gib`: on a scratch volume with the installed cap, shard size and reserve, the store seals
   at the shard size, drops at the cap with a loss entry, and still writes 10000 loss and health entries from the
   reserve. Store unit tests keep the mechanism at small sizes. The range's 64 MiB reserve stays a range value.
3. `truncation_alarm_per_hour` is decided in 9.5 by a range trial: local mode puts the watcher on the host (ADR 0043),
   so 11 truncated records within an hour alert once at the range's ntfy sink and 10 do not, as the method says.
4. `verify_freshness_s` is decided where the watcher runs: on the host in local mode (ADR 0043, #203) and on the Pi
   at L12 (#210), by stopping its schedule; its 3600 s exceed a range trial's 29 min.
5. `anchor_interval_s` is decided in 9.5 by a range fact: the largest gap between the ledger's entries while the
   sustained trial records, against the 1 s limit. The method's 1 h run becomes the L12 24 h run (#210).
6. Each `method` in `acceptance/0.toml` names its decider when its test lands; that change is the maintainer's.

## Alternatives considered

- Let the Go tests decide: they use fake clocks and events, so a wrong limit in a unit file would pass.
- Measure the store's three in the range: its 512 MiB scratch and 64 MiB reserve are not the installed values.
- Leave the Pi metrics to L12 only: 9.5's local mode runs the watcher on the host, so they apply before L12.

## Consequences

- New work in 9.5: the fill test in #202, a truncation-alarm trial and the anchor-gap fact; #213 stays open for them.
- `verify_freshness_s` has no range evidence; its host measurement waits for local mode's install.
- Revert: a pull request removing this file and restoring ADR 0022 point 2's last sentence.
