# 0022 — Run the collector in the range image and read its sealed shards

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-24
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Floor-0 numbers come from the collector's store, but the image has no collector (`imageFiles`, `rangevm/session.go`):
Laurel writes `audit.log` and no trial run passes a metric (ADR 0018 point 4). The collector fallocates 2 GiB of headroom
at Open (`cmd/balistid-collector/main.go`, `store/store.go`); root has 294 MiB free and only trials get a scratch disk
(`rangevm/vm.go`). The store must be read while Laurel keeps writing (ADR 0016). The build sets `GOPROXY=off` with an
empty module cache in the stage (`toolEnv`); the collector and a guest that reads shards need `modernc.org/sqlite`.

## Decision

1. The image installs the collector from `deploy/collector/` and Laurel writes to its socket. The guest reads records
   only from sealed shards through `store.ReadSeals` and `shard.Read`, never `store.Open` (a static test).
2. Every run, self-test and exec included, has a scratch disk for the store (512 MiB; a trial's sized by volume, at most
   `MaxScratch`). An image-only oneshot mounts it `noexec,nosuid,nodev` (plus `commit=300` in a failure trial, ADR 0020)
   at the installed store path before the collector; it formats only in boot 1 and checks the superblock first in boot 2
   (ADR 0018 point 3). An image drop-in only adds the new `-headroom 67108864` and `-log-commits`, never set on the host;
   cap and shard size stay as installed. B5 measures `headroom_gib` with the installed value.
3. Read: the guest execs `/usr/bin/true <token>` as a barrier and waits, at most `waitLimit` (30 s), until the collector's
   `committed through` journal line (one `journalctl -f`) moved and then held for 1 s, then stops only `balistid-collector.service`, once. systemd keeps
   the socket, Laurel reconnects and may start the collector again at once; Close sealed the open shard. `ReadSeals`
   returns the pending shards, their sidecars, sidecars beside a seal and a torn last line as typed fields: the guest
   accepts only pending shards (with `-wal`, `-shm`, `-journal`) and a torn line above the last seq of the seal holding
   the barrier; a sidecar beside a seal is an error. A read without its barrier is `missing`: INVALID for a trial
   (ADR 0021), not whole for an exec job, never a MISS. An exec window is whole only if every health record from its start to
   the stopped run's `stopping` (a tick's health follows its lines) is stats without loss, lag, refused, OK, or behind the barrier an eof-only connection (T25).
4. Modules: `toolEnv` sets `GOPROXY=https://proxy.golang.org` without `direct` and `GOSUMDB=sum.golang.org`, keeps
   `-mod=readonly` and sets no `GONOSUMDB`, `GOPRIVATE` or `GOINSECURE`; go.mod and go.sum come from the verified export
   (ADR 0010). Integrity rests on the code-owned go.sum, which every download must match; with it complete go never asks
   the checksum database. A `replace` to a path is refused before the build.
5. B4 measures sustained_rate, burst_rate, crash_loss_ms, record_max_kib, refusal_summary_s, ready_s, systemd_exposure
   and cpu_cores, plus the facts collector CapEff 0 (T18) and peer_refused (T2). sensor_down_s and alarms go to 9.4,
   canary_interval_s and rss_mib to B6, headroom_gib, raw_cap_gib, shard_max_gib to B5, healthy_ok, daily rates to 9.5.

## Alternatives considered

- Root-filled module cache: a root action outside the hashed manifest, against ADR 0010 point 4; runner uid can overwrite it.
- Collector built by CI: the image is no longer built from one export; a second binary path into the bundle (T37).
- Production limits everywhere: an exec job's scratch of at least 2.5 GiB, about 10 GiB of disk admission per run.
- Stopping the socket: Laurel exits (ADR 0016), each restart spends `max_restarts`. A seal-now signal: changes ADR 0013.

## Consequences

- Needs ADR 0015 point 3 first: store, shard, collector and `cmd/balistid-collector` code-owned, the collector in
  `OWNED_ROOTS` and in ci.yml's `go list -deps`. docs_budget LAYOUT gains `range/balistid-range-store.service` and
  `range/balistid-collector-range.conf`, copied into `balistid-collector.service.d/` in the image.
- Amends ADR 0009 point 3 and 0018 points 2 and 3 (a scratch disk in every run, formatted only in boot 1), 0010 point 4
  and 0011 point 2 (a fresh stage cache from one proxy, checked by go.sum), 0011 point 6 (one more write cap per admission).
  T34: proxy modules must match go.sum, proxy settings choose the path only (outage is DoS); T36: a 4 GiB trial needs
  16 GiB plus the reserve; T37: both binaries from one export. B4.1 measures runner_build_memory_gib again.
- A proxy outage fails the install. Trials stop being `baseline` once the guest reads the store (B4.4).
- Tests: B4.1 `TestToolEnvIsExactlyTheAllowlist` with proxy and GOSUMDB, a tampered zip and a missing go.sum line fail, a
  path `replace` is refused. B4.2 `TestCommittedOnlyAfterCommit`, `TestCommittedAfterSealThenFlushFails`. B4.4
  `TestGuestNeverOpensStore`, `TestBarrierRequiredWithUnindexed`, `TestSidecarBesideSealRefused`; KVM self-test PASS.
