# 0009 — Run the attack range as throwaway QEMU VMs under a dedicated uid

- Status: proposed (accepted after the first range run passes)
- Date: 2026-10-02
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R10 needs an attack and a legitimate scenario for every detection; ADR 0004 needs a smoke test of
auditd and Laurel on the target kernel. Attacks must not run on the host, and containers share its
kernel. From documentation read on 2026-10-02 (not yet from runs): mkosi 27.1 builds Arch images
through user namespaces; Arch's udev rule gives `/dev/kvm` mode 0666; QEMU runs without libvirt;
libguestfs warns that disk format autodetection on guest-written images can read host files
(CVE-2010-3851). Atomic Red Team (commit 388942ad) has 423 Linux tests (508 index rows), about 97 %
`sh`/`bash`. The AI agents run as the maintainer's uid (A1), so nothing they can write may decide a
range result.

## Decision

1. Range runs execute as a dedicated system user `kordon-range`, created with the launcher, its
   configuration and the QEMU argument allowlist by `kordon-install` (R8); all are root-owned. The
   maintainer's user only submits a run request (range commit, test id) to a root-owned unit.
2. QEMU starts with `-nodefaults`, `-nic none`, `-sandbox on,obsolete=deny,elevateprivileges=deny,
   spawn=deny,resourcecontrol=deny`, inside bwrap that binds only the run directory and `/dev/kvm`,
   under `timeout` and `prlimit --fsize`. Every `-drive` sets `format=` explicitly: the overlay
   qcow2 (`qemu-img create -f qcow2 -b base -F qcow2`), inputs and results `format=raw`.
3. The base image is built by mkosi from `range/` with a pinned package snapshot, `Seed=` and
   `SourceDateEpoch`, converted with `qemu-img convert -f raw -O qcow2`. Tests reach the guest on a
   read-only input disk only; the base, input and overlay sha256 are recorded by the launcher.
4. Results come out through the serial log and a raw results disk read by `guestfish --ro
   --format=raw -a` (never `-i`) as `kordon-range`. The host, not the guest, computes each verdict
   from the extracted audit records: CAUGHT, MISSED, FALSE_POSITIVE (legitimate scenario alerted),
   INVALID (setup failed, timeout or crash — R6, never a pass).
5. Each result is bound to the range commit, the base, input and overlay sha256, and the guest
   `uname -r` and package versions. A kernel other than the target one makes the result UNKNOWN.
6. Atomic Red Team is pinned to a commit and run by our own small runner (shell commands and cleanup).
7. Installing mkosi and libguestfs on the development host is a dev-host exception to R8.

## Alternatives considered

- Running QEMU as the maintainer's user: A1 controls the launcher, isolation and results.
- libvirt system mode: root-owned networks and pools the range does not need.
- `invoke-atomicredteam` (PowerShell, AUR) or `atomic-operator` (archived 2023).

## Consequences

- The layout gate admits `range/` in the pull request that adds it, with tests.
- Tests: a results disk carrying a qcow2 header is read as raw; a guest filling serial output stops
  at the size cap as INVALID; the guest sees no network interface besides loopback and no device
  outside the allowlist; a launcher argument outside the allowlist is refused.
- `THREAT_MODEL.md` gains rows for hostile guest content, Atomic Red Team as supply chain and forged
  range evidence. Until R2 signs results, a result is trusted only as far as root on the host is.
- Known risk: mkosi #4438 affects Overlay=/BaseTrees builds; `MKOSI_FORCE_USERNS_FALLBACK=1` is
  documented but untested. A hardened kernel may disable unprivileged user namespaces for the build.
