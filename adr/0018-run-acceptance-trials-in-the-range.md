# 0018 — Run the collector's acceptance trials in the range

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-11
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

The collector's acceptance methods need trials the runner cannot run: an exec job lasts at most 300 s and a VM 10 min,
one boot each; QEMU has `-no-reboot` and no second boot; agent programs run unprivileged; the image has no generator and
294 MiB free on root. A tick may take 40 min and one evidence FAIL stops the runner (`rangerun/runner.go:113-119`).

## Decision

1. Trials are a closed table in code: name, wall clock for all its boots, serial budget, boots (1 or 2), scratch disk
   size and a maximum count, with count × wall clock + setup ≤ 30 min. Name (`^[a-z0-9-]{1,32}$`) and phase reach the
   guest only as `-fw_cfg name=opt/io.systemd.credentials/balistid.<key>,string=<value>`; its first facts echo both, or
   the run is INVALID. The guest runs the trial's program from the image as root; a job disk with a trial is refused;
   exec is unchanged: agents never choose root code.
2. Limits are a parameter of each run, recorded in its result; self-test and exec keep 10 min and 1 MiB. A scratch disk
   sized per trial for the store is a fourth writable run file, inside the size cap and the disk admission.
3. Failure trials (sysrq `b` for a reset, SIGKILL of the measured writer for kill -9, at a random time under load) use
   one sequential generator. Just before the failure the guest writes a serial line with H, the end of the contiguous
   numbers returned 900 ms earlier; the host stamps it on arrival, and unless QEMU exits (reset) or the guest's kill
   line follows within 100 ms the run is INVALID. Every number up to H must be stored, and with the collector every
   number it acknowledged as committed. Reset keeps `-no-reboot` and no `cache=`: boot 1 syncs its facts (echo, armed)
   before the load; only if they parse and are armed does the host zero the results disk and boot the same run files
   with phase 2. Boot 2 reads the scratch superblock before mounting it (no fstab or mount unit does): ext4 magic, a
   journal and the recovery flag that only a clean unmount clears, or INVALID.
4. A record is one Laurel line (ADR 0016). The generator numbers every event: in exec argv for `sustained_rate`, as the
   address of `ptrace(PEEKDATA)` of no process for `burst_rate`. Stored numbers are read through one interface; until
   the collector's store reader is in the table it follows Laurel's log across rotation, and those runs are `baseline`:
   they never pass a metric. Zero loss: every number stored once and none outside the generated set, audit `lost`
   unchanged, no dispatcher overflow, the rate held in every 10 s window; guest steal over 1 % is INVALID. Must miss: a
   reader dropping one number; under kill -9 a writer holding records 2 s before write(); a writer last synced 1500 ms
   before a reset. Must pass: one syncing every 250 ms. Rates, the credential, sysrq and steal need KVM to verify.
5. Each tick runs one slot: the self-test when due, else an acceptance batch (≤ 30 min) and an agent job in turn; a
   batch also runs when no agent job is admissible. `TimeoutStartSec` stays 40 min.
6. Acceptance verdicts (PASS, MISS, INVALID per metric) have their own capped state file and label `acceptance`,
   scheduled only by the runner for its own image. A MISS is saved before its result and stands for the commit; INVALID
   runs repeat, never replace a MISS, and more of them than the metric's trials make a MISS; a metric passes only when
   all its trials are valid PASS. A new commit restarts the suite. Acceptance never stops the runner (a self-test FAIL
   does); an inbox `trial` job is an agent job, advisory.

## Alternatives considered

- A 24 h `healthy_ok` range run holds the runner a day. A QMP reset with `cache=none` proves no more: QEMU's writes
  reach the host file in every cache mode. Root agent programs: the job disk would choose root code (T35).

## Consequences

- Amends ADR 0009 points 2-5 (fw_cfg and second boot, scratch disk, limits per run, a results stream per boot) and ADR
  0011 points 4, 5 and 7 (kind `trial`, acceptance slot; evidence and "one FAIL fails the commit" are the self-test's).
  Methods: `healthy_ok` over seven days on the reference host (2 to 20 non-OK samples), `crash_loss_ms` by sysrq `b` (no
  device write cache), rates by numbered events; no limit changes.
- T4 and T24 are measured here (T24 keeps the device cache as a stated hole); T36: host contention makes acceptance
  INVALID and agents can delay it; T37: range acceptance only from the runner's compiled table.
- Tests: argv unchanged without a trial, exact with one and with a scratch disk; a name off the table refused; no
  unarmed second boot; a late failure, no recovery flag or a wrong echo INVALID; a MISS stands; batches fit 30 min.
