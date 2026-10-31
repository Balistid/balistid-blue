# Threat model — floor 0 (recorder)

Scope: an Arch Linux host recording via auditd and Laurel (ADR 0004), raw SQLite shards (0005),
a Tessera log cosigned and watched from a Raspberry Pi (0006), five processes (0007), and the attack
range VM that tests them (0009) and its runner (0011). Detection and
response start on floor 1. Each row names its control and proof in `acceptance/0.toml` or a test.
Status: **designed** (control decided, test not passing yet), **partial** (a stated hole), **gap** (no
control; the floor to close it, or "open"), **assumption**. No row is
"covered" until its test passes in CI or the range.

## Assets and actors

Assets: raw records and sealed shards, the Merkle log and cosigned checkpoints, the signing key, the
truth of health and loss signals, the alert path to the maintainer's phone.
- **A1 agent**: an AI agent or malware at the maintainer's uid. The main adversary.
- **A2 root**: root on the host, including A1 after escalation. Root controls every host process,
  key and network peer, so anything it sends to the Pi is hostile input.
- **A3 input**: crafted records or responses aimed at a parser. **A4 network**: LAN or hotspot.
- **A5 supply chain**: dependency, toolchain, Laurel or package. **A6 failure**: crash, power, disk,
  kernel upgrade, clock, Pi failure.

## Threats

| ID | Actor | Threat | Control | Proof | Status |
|---|---|---|---|---|---|
| T1 | A1 | Alter or delete shards, keys, units, config | Service uids own them (0007) | test perm_matrix | designed |
| T2 | A1 | Impersonate Laurel, squat its socket, read the raw stream | systemd-held socket root:_laurel 0660 in root-owned `/run/balistid`, `SO_PEERCRED` (0016) | refusal-flood: root and a uid in `_laurel`'s group refused and counted (0023) | designed |
| T3 | A1 | Act through io_uring, unseen by exit rules | io_uring disabled, `kernel.io_uring_disabled=2` (0004) | range smoke test | partial: root can re-enable it at runtime |
| T4 | A1 | Flood audit to cause loss or fill the store | Loss alarms per stage, auditstat's too (0038); cap drops new; maintainer expiry | loss_alarm_s, raw_cap_gib, rates by range trials (0018) | partial: blind until handled; overflows uncounted, hide later ones (0038) |
| T5 | A1 | Change or disable audit rules | Needs root; `-e 2` (0004) | range smoke test, test rules_locked | designed |
| T6 | A1 | Read secrets in recorded command lines | Raw stream closed to A1; derived DB readable | — | gap: redaction before the derived DB, designed with the normalizer (9.3), not floor 3 |
| T7 | A1 | Read or delete alerts | Push to phone; no alert client on the host | — | assumption |
| T8 | A1 | Evade recording: ptrace or `process_vm_writev` into own processes, memfd/execveat, interpreters | Rules for ptrace, execveat, memfd_create | drill | partial: interpreters, mmap exec, envp and the middle of truncated argv (floor 1); x32 ABI syscalls match no syscall rule or watch on kernels with `CONFIG_X86_X32_ABI` (Arch `linux`), mitigation decided before the host install |
| T9 | A1 | Tamper with the Laurel or Balistid Blue build before install | Builds in CI or range; installer takes rules and binaries from a root-owned checkout, checks sha256 | test install_hash | partial: no R2 hardware key yet; sha256 proves CI provenance, not review, of unowned source (0015) |
| T10 | A1 | Fill the shared filesystem so loss records cannot be written | Physically reserved headroom, free space a second cap (0013); auditd `disk_full_action` set, `-f 1` | test reserve | partial: a writer that keeps filling a shared filesystem takes the freed reserve; btrfs frees no part of it (UNKNOWN at once) |
| T11 | A1 | Ptrace, alias or fake the CLI | Host CLI is advisory; truth is the Pi and phone | — | partial: host CLI output can lie |
| T12 | A2 | Rewrite or roll back cosigned history | Witness refuses; Pi verifies (0006, 0031) | fork_refused (range); Pi tests (0031) | partial: Pi only in tests (L11, L12) |
| T13 | A2 | Alter or replace records not yet cosigned | — | — | gap: undetected, window unbounded |
| T14 | A2 | Blind the sensor, forge health, loss or shutdown entries | Announced quiet capped | announced_quiet_max_h | gap: open beyond the cap |
| T15 | A2 | Delete evidence and pass it off as retention | — | — | gap: open |
| T16 | A2 | Attack the Pi through WireGuard, litewitness or tile fetching | Minimal Pi services, pinned, updated; entries decoded strictly (0026) | FuzzDecodeEntry, Pi fuzz (0031) | partial: Pi parsers face root; ntfy needs outbound internet (0026) |
| T17 | A2 | Start a new log origin to reset history | Pi adds a new origin only after the old log's cosigned final (0030) | TestRollover* | designed |
| T18 | A3 | Parser bug in collector or normalizer gains privilege | No capabilities, sandboxed units (0007) | test caps_matrix, fuzz_hours; exposure of the recorder's units (0023) | designed; audit.log readable by the collector's group (0038) |
| T19 | A3 | Parser bug in the ledger misuses its signing key | No network; key only signs checkpoints; only the collector's and own uid connect (0027, 0030) | fuzz_hours, FuzzDecodeMessage | partial: a compromised ledger signs, steers retention (0029), announces, ends the log (0030) |
| T20 | A3 | Crafted records exhaust memory, disk or the refused-request log | Truncated oversize records, store caps, refusal summaries, ledger link and log caps (0027) | record-max, refusal-flood (0023); rss_mib; cpu_cores on the reference host (0025) | designed |
| T21 | A4 | Reach the witness, relay or Pi | WireGuard, relay-uid nftables (0032); relay: Pi /32 (0031) | test_net_deploy, test_relay_deploy; pi_reach | partial: Pi side, IPv6 (L12) |
| T22 | A4 | Shift the host clock so retention deletes early | Age by the witness's clock and the host's (0029) | TestRetention* | partial: root sets both |
| T23 | A5 | Malicious dependency or toolchain | Pins, sha256, reproducible build, govulncheck | CI | partial: Laurel trusted |
| T24 | A6 | Crash or power loss loses committed records | WAL `FULL`, a commit at every Flush (250 ms) or 2 MiB, sealing barrier (0005, 0013); the ledger logs a prefix, a re-issued seq fails its handshake (0027) | crash_loss_ms: kill -9 and reset of the collector under load, every seq it journaled committed survives (0018, 0023) | designed; hole: a device's volatile write cache is not modelled |
| T25 | A6 | Loss between Laurel and collector | Reconnects are events (0004); drops counted per stage, never blocking (0016) | reconnects_per_day | partial: unread bytes at a collector restart or of a dead Laurel stay uncounted (0016); range trials read sealed shards to a barrier 7 s after the job (Laurel holds unended events 5 s) and keep an exec window whole only when all health to the run's end is known safe and `lost` and the overflow flag held; a guest clock step back (root or hypervisor) undoes it (0022); a health record dropped under load is unseen |
| T26 | A6 | Kernel upgrade breaks the sensor, or alarms every week | Results bound to versions; one alarm per kernel | smoke test; ready-1..4 boots to health OK (0023) | designed |
| T27 | A6 | Pi or its alarms die | Dead-man ping (0034) | dead_site_alarm_s | partial (0034) |
| T29 | A1 | Land a secret or untested code via an intermediate commit, a file gitleaks skips, or a swapped toolchain | Layout gate on every commit, rescan of skipped files, pinned toolchain and module hashes (ADR 0003) | tests RangeTest, RescanTest, RescanDetectionTest, ChangeRangeTest, GoGateTest | partial: Go checks run on the head tree only; intermediate commits may not build |
| T28 | A6 | Host offline: outage looks like attack | Cosigned shutdown, suspend announcements (0030); silence alarm | silence_alarm_s | partial: outages and missed announcements alarm too |
| T30 | A3 | Hostile guest output (results disk, serial) attacks the host reader or QEMU tools | Read as bytes: length-prefixed, capped, unknown JSON fields refused, zero padding after the end; `format=` on every drive; serial budget; no guest filesystem opened (0009) | rangevm tests TestParse*, TestQemuArgv, TestRunCommand, TestPlantedQcow2HeaderIsData, TestExecReport, Fuzz* | designed |
| T31 | A3 | Guest escapes QEMU or KVM | QEMU in bwrap: no network or `$HOME`, read-only root, `/dev` and run dir, 3 capped writable files; `-sandbox` (0009); seccomp allowlist (0011) | TestSandboxIsolatesHost (range host only) | partial: QEMU escape: runner's uid (CLI: maintainer's) in bwrap; KVM escape: host kernel (0011) |
| T32 | A5 | Malicious or changed Atomic Red Team test or runner | — | — | gap: pinned commit and review, floor 1 |
| T33 | A1 | Forge or edit range results, or the local git state an image is built from, at the maintainer's uid | Result names image and launcher commit; PASS only if the launcher is a clean build of the image commit, else UNKNOWN (a FAIL stays FAIL) | TestJudge | gap: CLI results trust that uid (0009) |
| T34 | A1 | Make a range build run code or read files on the host: through the work tree, index flags, replace refs, repository config or attributes, a forged object, a symlink, the environment or a shared cache | Build the launcher's own commit from a verified export: git never runs in or reads the source repository; objects copied through an `os.Root` (no links out, no FIFO), `index-pack` and export under data, size and time limits; fixed tool environment, caches, workspace in the stage, no VCS stamp (0010) | tests TestExport*, TestObjectStore*, TestSourceRepositoryIsNotRead, TestForeignRepositoryIsNotCopied, TestOnlyObjectFilesAreCopied, TestStageGitRunsUnderAMemoryLimit, TestBuild*, TestCopyEndsWhenPackObjectsFails, TestReadCappedStopsAtTheLimit, TestForgedObjectIsRefused, TestToolEnvIsExactlyTheAllowlist, TestGuestBuildRunsNoGitAboveTheStage, TestGoUsesNoHTTPProxy | partial: building a commit runs its PKGBUILD and mkosi configuration (build only reviewed commits, 0011); the launcher is as clean as its checkout and storage; a process at that uid can change the build directory during a build, go.mod after its checks included; a module's assembly `#include` reads what the build unit can, like the commit's own code (0010); proxy settings only choose the path (DoS); inflation is bounded only by git memory and time limits (DoS) |
| T35 | A1 | Run code or read host files via the runner's inbox or job directory, or pose as maintainer | Any request is an agent job (strict capped JSON, quota, expiry); job files via `os.Root`, capped; program, time limit on a read-only job disk (0011) | tests: links, hard links, FIFOs refused; inbox builds nothing | designed |
| T36 | A1 | Exhaust host memory or disk, starve evidence | Unit: MemoryMax, no swap, TasksMax, idle CPU, wall clock; starts above memory and disk reserves plus write caps (0011) | runner_build_memory_gib, runner_job_memory_gib | partial: agents can delay evidence and acceptance; host contention makes acceptance INVALID (0018); every tick needs the largest run's admission, 16 GiB for the 4 GiB sustained trial's scratch, plus the reserve (0022); a build measures its module cache (1 GiB) only after the download, so a reviewed go.sum can take about 1 GiB per module version first, and GOCACHE and inodes are not capped (DoS) |
| T37 | A1 | Change runner/image/state; pass agent results as evidence | Own uid; root installs CI's hashed manifest only, from a checked export; evidence: timer/install only (0011), not CI (0028) or a dispatch (0037: payload allowlisted, runs as PR CI); acceptance only from its table (0018) | BootstrapTest: unprinted sha256 refused; inbox job never evidence; TrialWorkflow: bad payload refused | partial: trusts CI/GitHub |

## Assumptions

The kernel, firmware and boot chain are not compromised. The maintainer reads alerts on the phone,
runs no alert client on the host and keeps the Pi's admin credentials off the host. auditd and
Laurel are trusted OS components (ADR 0004). A gap stays listed until a floor closes it with a test.
