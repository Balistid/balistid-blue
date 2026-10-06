# Threat model — floor 0 (recorder)

Scope: one Arch Linux host recording through auditd and Laurel (ADR 0004), raw SQLite shards (0005),
a Tessera log cosigned and watched from a Raspberry Pi (0006), five processes (0007), and the attack
range VM that tests them (0009) and its runner (0011). Detection and
response start on floor 1. Each row names its control and its proof in `acceptance/0.toml` or a test.
Status: **designed** (control decided, test not yet passing), **partial** (control leaves a stated
hole), **gap** (no control; the floor meant to close it, or "open"), **assumption**. No row is
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
| T2 | A1 | Impersonate Laurel, squat its socket, read the raw stream | Socket in collector-owned dir, `SO_PEERCRED` | test peer_refused | designed |
| T3 | A1 | Act through io_uring, unseen by exit rules | io_uring disabled, `kernel.io_uring_disabled=2` (0004) | range smoke test | partial: root can re-enable it at runtime |
| T4 | A1 | Flood audit to cause loss or fill the store | Loss entries alarm; cap drops new; maintainer expiry | loss_alarm_s, raw_cap_gib | partial: blind until handled |
| T5 | A1 | Change or disable audit rules | Needs root; `-e 2` (0004) | range smoke test, test rules_locked | designed |
| T6 | A1 | Read secrets in recorded command lines | Raw stream closed to A1; derived DB readable | — | gap: redaction, floor 3 |
| T7 | A1 | Read or delete alerts | Push to phone; no alert client on the host | — | assumption |
| T8 | A1 | Evade recording: ptrace or `process_vm_writev` into own processes, memfd/execveat, interpreters | Rules for ptrace, execveat, memfd_create | drill | partial: interpreters, mmap exec, envp and the middle of truncated argv (floor 1); x32 ABI syscalls match no syscall rule or watch on kernels with `CONFIG_X86_X32_ABI` (Arch `linux`), mitigation decided before the host install |
| T9 | A1 | Tamper with the Laurel or Balistid Blue build before install | Builds in CI or range; installer takes rules and binaries from a root-owned checkout, checks sha256 | test install_hash | partial: no R2 hardware key yet |
| T10 | A1 | Fill the shared filesystem so loss records cannot be written | Physically reserved headroom; auditd `disk_full_action` set, `-f 1` | test reserve | designed |
| T11 | A1 | Ptrace, alias or fake the CLI | Host CLI is advisory; truth is the Pi and phone | — | partial: host CLI output can lie |
| T12 | A2 | Rewrite or roll back cosigned history | Witness refuses; Pi verifies (0006) | test fork_refused | designed |
| T13 | A2 | Alter or replace records not yet cosigned | — | — | gap: undetected, window unbounded |
| T14 | A2 | Blind the sensor, forge health, loss or shutdown entries | Announced quiet capped | announced_quiet_max_h | gap: open beyond the cap |
| T15 | A2 | Delete evidence and pass it off as retention | — | — | gap: open |
| T16 | A2 | Attack the Pi through WireGuard, litewitness or tile fetching | Minimal Pi services, pinned and updated | — | partial: Pi parsers are exposed to root |
| T17 | A2 | Start a new log origin to reset history | Pi accepts a new origin only after the old log's final checkpoint | test rollover | designed |
| T18 | A3 | Parser bug in collector or normalizer gains privilege | No capabilities, sandboxed units (0007) | test caps_matrix, fuzz_hours | designed |
| T19 | A3 | Parser bug in the ledger misuses its signing key | Ledger has no network; key only signs checkpoints | fuzz_hours | partial: a compromised ledger can sign |
| T20 | A3 | Crafted records exhaust memory, disk or the refused-request log | Truncated oversize records, store caps, refusal summaries | record_max_kib, rss_mib | designed |
| T21 | A4 | Reach the witness, relay or Pi | WireGuard, relay-uid firewall (0006) | test pi_reach | designed |
| T22 | A4 | Shift the host clock so retention deletes early | Shard age from the cosigned seal time on the Pi | test clock_skew | partial: Pi has no RTC |
| T23 | A5 | Malicious dependency or toolchain | Pins, sha256, reproducible build, govulncheck | CI | partial: Laurel trusted |
| T24 | A6 | Crash or power loss loses committed records | WAL `FULL`, sealing barrier (0005) | crash_loss_ms | designed |
| T25 | A6 | Loss between Laurel and collector | Reconnects are events (0004) | reconnects_per_day | gap: not fully measurable |
| T26 | A6 | Kernel upgrade breaks the sensor, or alarms every week | Results bound to versions; one alarm per kernel | smoke test | designed |
| T27 | A6 | Pi dies, or push delivery fails | — | — | gap: dead-man switch, floor 3 |
| T29 | A1 | Land a secret or untested code via an intermediate commit, a file gitleaks skips, or a swapped toolchain | Layout gate on every commit, rescan of skipped files, pinned toolchain and module hashes (ADR 0003) | tests RangeTest, RescanTest, RescanDetectionTest, ChangeRangeTest, GoGateTest | partial: Go checks run on the head tree only; intermediate commits may not build |
| T28 | A6 | Host offline: outage looks like attack | Announced shutdown and suspend; silence alarm | silence_alarm_s | partial: outages alarm too |
| T30 | A3 | Hostile guest output (results disk, serial) attacks the host reader or QEMU tools | Results read as raw bytes: length-prefixed, capped, JSON with unknown fields rejected, zero padding after the end; `format=` on every drive; serial budget; no guest filesystem opened (0009) | tests TestParseRejects, FuzzParse, TestQemuArgv, TestRunCommand, TestPlantedQcow2HeaderIsData | designed |
| T31 | A3 | Guest escapes QEMU or KVM | QEMU in bwrap: no network, no `$HOME`, read-only root, `/dev` and run directory, three size-limited writable files; `-sandbox` (0009) | test TestSandboxIsolatesHost (range host only) | partial: an escape runs as the maintainer's uid |
| T32 | A5 | Malicious or changed Atomic Red Team test or runner | — | — | gap: pinned commit and review, floor 1 |
| T33 | A1 | Forge or edit range results, or the local git state an image is built from, at the maintainer's uid | Result names image and launcher commit; a run can only PASS when the launcher is a clean build of the image commit, otherwise UNKNOWN (a FAIL stays FAIL) | test TestJudge | gap: results are trusted only as far as that uid (0009) |
| T34 | A1 | Make a range build run code or read files on the host: through the work tree, index flags, replace refs, repository config or attributes, a forged object, a symlink, the environment or a shared cache | Build the launcher's own commit from a verified export: git never runs in or reads the source repository; objects copied through an `os.Root` (no links out, no FIFO), `index-pack` and export under data, size and time limits; fixed tool environment, private caches, no VCS stamp (0010) | tests TestExport*, TestObjectStore*, TestSourceRepositoryIsNotRead, TestForeignRepositoryIsNotCopied, TestOnlyObjectFilesAreCopied, TestStageGitRunsUnderAMemoryLimit, TestBuild*, TestCopyEndsWhenPackObjectsFails, TestReadCappedStopsAtTheLimit, TestForgedObjectIsRefused, TestToolEnvIsExactlyTheAllowlist, TestGuestBuildRunsNoGitAboveTheStage | partial: building a commit runs its PKGBUILD and mkosi configuration (build only reviewed commits, 0011); the launcher is as clean as its checkout and storage; a process at that uid can change the build directory or mkosi's `/var/tmp` during a build; inflation is bounded only by git memory and time limits (DoS) |
| T35 | A1 | Run code or read host files via the runner's inbox or job directory, or pose as maintainer | Any request is an agent job (strict capped JSON, quota, expiry); job files via `os.Root`, capped; program, time limit on a read-only job disk (0011) | tests: links, hard links, FIFOs refused; inbox builds nothing | designed |
| T36 | A1 | Exhaust host memory or disk, or starve evidence | Unit: MemoryMax, no swap, TasksMax, idle CPU, wall clock; starts above memory and disk reserves plus write caps (0011) | runner_build_memory_gib, runner_job_memory_gib | partial: agents can delay evidence |
| T37 | A1 | Change the runner, its image or state, or pass agent results as evidence | Own uid; root installs only the CI-hashed manifest, whose binary builds its image from a hash-checked export; evidence only from timer or install (0011) | install procedure refuses a sha256 CI did not log; inbox job never evidence | partial: CI and GitHub are trusted |

## Assumptions

The kernel, firmware and boot chain are not compromised. The maintainer reads alerts on the phone,
runs no alert client on the host and keeps the Pi's admin credentials off the host. auditd and
Laurel are trusted OS components (ADR 0004). A gap stays listed until a floor closes it with a test.
