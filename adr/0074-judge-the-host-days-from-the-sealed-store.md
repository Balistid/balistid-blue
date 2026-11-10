# 0074 — Judge the host's days from the sealed store

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-10
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-09)
- Agent: claude/opus-5.5
- Fixes the judge's method within ADR 0073 point 3 for #201, amending its short days and its midnight split.

## Context

ADR 0073 has a oneshot of the collector's uid judge the 7 days as its own component. The installed
`balistid-install` knows `recorder` and `runner` only, and the records leave gaps: health is written only on a
change, with wall time only; stopping is skipped when the store is down; a dropped record shows only in stats'
`lost_health`, and the oldest dropped first is a run's started; no record names the kernel.

## Decision

1. Before the recorder installs, the collector's started record carries `kernel` (`/proc/sys/kernel/osrelease`)
   and `balistid-install` knows a component `judge`: `balistid-judge` and a oneshot `balistid-judge.service` as
   `balistid-collector`, no network, the store read-only, results in `/var/lib/balistid/judge`, no timer. It
   installs in the days, changing no recorder unit or sensor file (only the shared installer, as any component),
   and judges the recorder installed. Not in `CPUUnits`, as it is no cost of recording: the CPU test names it.
2. The judge reads `store.ReadSeals` and each sealed shard through `shard.Read`'s hashed copy, from seq 1. An open
   shard and its sidecars are accepted only above the last seal, a torn last index line only as such; any other
   read error makes every day not yet written UNKNOWN. The result names the last seal's seq and sha256, for a
   later check against the ledger; until then a collector rewriting a shard and its index is not seen (T18).
3. A day passes only on records that all hold: a known kind decoding strictly, `lossOf` without an error, in runs
   each begun by a started record at `note_seq` 1, `note_seq` without a skip, `lost_health` 0 at the first stats
   and not rising in the day, `lost` matched by lost records by the run's end, a run ended by stopping or going on
   into the next day's sealed records, at most 90 s of awake clock between records, never going back, no
   `mono_err`, `boot_err`, `cpu.err` or unit `err`, `info.version` `balistid ` and 40 hex, and a `kernel`.
   Anything else is UNKNOWN with its reason; UNKNOWN fails the day as a MISS does.
4. The window is the installed version's first started record to its 7th day of at least 4 h awake. A started
   record of another version inside it makes every later day UNKNOWN. A shorter day inside the window is not one
   of the 7, but its loss, reconnects, health samples and UNKNOWNs count as a counted day's do. A day is final once
   the next day has a sealed record; until then it is PENDING, never PASS.
5. Wall time maps to the awake clock linearly between the two nearest records carrying both. Across midnight an
   interval splits by the awake clock (ADR 0073); one with a suspend (boot minus awake clock over 1 s) or a clock
   step (wall minus boot over 1 s) goes whole to its end record's day, its samples taking its worst health.
6. `healthy_ok` samples every 30 s of awake time from each started record: the last health record at or before
   the sample; before a run's first health record and between a stopping and a started record of the same boot it
   is not OK. The 7 days' samples pool for the 99.9 %. Boot to the first start and the last stop to shutdown are
   not seen, nor a boot whose collector never stored a record: named residuals, against A2 and A6 only.
7. `loss_per_day` counts what `lossOf` counts (truncated sensor records, the dispatcher at least 1 per flip),
   `reconnects_per_day` the `reconnect` cause, each on every day its window touches.
8. Results go to `/var/lib/balistid/judge/<commit>/`: `day-YYYY-MM-DD.json` per day and `summary.json`, 0644,
   whole files, the same bytes for the same store, with each day's awake hours, kernels, samples and CPU per unit.

## Alternatives considered

- Reinstall the recorder after the days for a newer installer: it judges a version no longer installed, only once
  the window has ended. The runner's bundle also brings the installer, but runs range VMs on the host in the days.
- `sqlite3`, `jq` or the range guest's reader: no hashed read, the wrong uid, or the VM's barrier; a `balistid`
  subcommand changes the recorder's CLI within the days; a daily timer adds a unit nothing needs.

## Consequences

- The recorder installs from the commit that adds `kernel` and `judge`; the judge's later bundles change no table.
- The judge copies a shard of up to 512 MiB into a tmpfs scratch off the store's device; MemoryMax covers it.
- Revert: a pull request removing this file, `kernel`, the judge's component and the acceptance changes.
