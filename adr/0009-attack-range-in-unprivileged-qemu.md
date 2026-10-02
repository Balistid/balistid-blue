# 0009 — Run the attack range as throwaway QEMU VMs, confined on the host

- Status: proposed (accepted after the first range run passes)
- Date: 2026-10-02
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R10 needs an attack and a legitimate scenario for every detection; ADR 0004 needs a smoke test of
auditd and Laurel on the target kernel. Attacks must not run on the host, and containers share its
kernel. From documentation read on 2026-10-02, not yet from runs: mkosi 27.1 builds Arch images
through user namespaces; Arch's udev rule gives `/dev/kvm` mode 0666; QEMU runs without libvirt; a
guest-written disk opened with format autodetection can make QEMU tools read host files. Atomic Red
Team (commit 388942ad) has 423 Linux tests, about 97 % `sh`/`bash`, non-malicious test scripts.

## Decision

1. The VM is the isolation boundary. The range runs as the maintainer's user; no dedicated uid,
   no libvirt, no root at run time.
2. QEMU runs with `-nodefaults -nic none -display none -no-reboot -sandbox on,obsolete=deny,
   elevateprivileges=deny,spawn=deny,resourcecontrol=deny`, `-enable-kvm`, a fresh qcow2 overlay per run
   (`qemu-img create -f qcow2 -b base -F raw`) and `format=` set on every `-drive`.
3. QEMU runs inside bwrap with `--unshare-all --die-with-parent --new-session --cap-drop ALL
   --clearenv --setenv PATH /usr/bin`, read-only `/usr` and base image, a writable run directory
   and `--dev-bind /dev/kvm` only. It cannot reach a listener on the host's 127.0.0.1 and has no view of `$HOME`. It runs
   under `prlimit --fsize` sized to the base's virtual size plus the results disk; hitting the
   limit is INVALID.
4. The launcher reads the serial console through a pipe with a byte budget and a wall-clock limit;
   hitting either kills QEMU and makes the run INVALID.
5. Results: the guest writes one length-prefixed record stream to a raw results disk; the host
   reads at most N bytes of it as data. No guestfish, no mounting, no filesystem from the guest.
6. The base image is built by mkosi from `range/` with a pinned package snapshot, `Seed=` and
   `SourceDateEpoch=`; audit rules and the Laurel config come from `deploy/` and are baked in.
   Tests and the runner are baked in as well, so the base sha256 identifies everything the guest ran.
7. The host computes each verdict from the extracted records against the test's expected record
   pattern: CAUGHT, MISSED, QUIET (legitimate scenario, no match, and the canary records of the
   run present, so a silent sensor cannot pass), NOISY (legitimate scenario
   matched), INVALID (setup failed, timeout, budget, crash, or a results stream without a final end record
   with the record count, over N bytes, or unparsable). INVALID never counts as a pass (R6).
8. Each result records the range commit, base sha256, guest `uname -r` and package versions; a kernel
   other than the target kernel makes the result UNKNOWN. Run directories are deleted after
   extraction (R5); overlay virtual size and run directory are capped, and base images and
   results get retention. Installing mkosi on the development host is a dev-host exception to R8.

## Alternatives considered

- A dedicated range uid and root launcher: guards results against agents; revisit with real malware.
- libvirt, guestfish, PowerShell runners: root-owned parts, a big parser or a big runtime we do not need.

## Consequences

- Tests: a planted qcow2 header with a backing file to a host file is never opened by QEMU, and every
  `-drive` in the argv has `format=`; serial output past the budget
  ends INVALID; QEMU cannot reach a listener the test starts on the host's 127.0.0.1, or read `$HOME`; the guest lists no network
  interface besides loopback; the smoke test shows Laurel output, not only a running service.
- The layout gate admits `range/` in the pull request that adds it, with tests.
- `THREAT_MODEL.md` gains rows for hostile guest output, Atomic Red Team as supply chain, and range
  results trusted only as far as the maintainer's uid (agents could forge them).
- Risks: mkosi #4438 (Overlay=/BaseTrees); a hardened kernel may block the user namespaces we need.
