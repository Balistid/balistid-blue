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
Team (commit 388942ad) has 423 Linux tests, about 97 % `sh`/`bash`, all benign test scripts.

## Decision

1. The VM is the isolation boundary. The range runs as the maintainer's user; no dedicated uid,
   no libvirt, no root at run time.
2. QEMU runs with `-nodefaults -nic none`, `-enable-kvm`, a fresh qcow2 overlay per run
   (`qemu-img create -f qcow2 -b base -F qcow2`) and `format=` set on every `-drive`.
3. QEMU runs inside bwrap with `--unshare-all --die-with-parent --new-session --cap-drop ALL`,
   read-only `/usr`, the base image read-only, the run directory writable and `--dev-bind /dev/kvm`
   only. It has no network namespace route out, not even to loopback, and no view of `$HOME`.
4. The launcher reads the serial console through a pipe with a byte budget and a wall-clock limit;
   hitting either kills QEMU and makes the run INVALID.
5. Results: the guest writes one length-prefixed record stream to a raw results disk; the host
   reads at most N bytes of it as data. No guestfish, no mounting, no filesystem from the guest.
6. The base image is built by mkosi from `range/` with a pinned package snapshot, `Seed=` and
   `SourceDateEpoch=`; audit rules and the Laurel config come from `deploy/` and are baked in.
   Tests and the runner are baked in as well, so the base sha256 identifies everything the guest ran.
7. The host computes each verdict from the extracted records against the test's expected record
   pattern: CAUGHT, MISSED, QUIET (legitimate scenario, no match), NOISY (legitimate scenario
   matched), INVALID (setup failed, timeout, budget, crash). INVALID never counts as a pass (R6).
8. Each result records the range commit, base sha256, guest `uname -r` and package versions; a kernel
   other than the target kernel makes the result UNKNOWN. Run directories are deleted after
   extraction (R5). Installing mkosi on the development host is a dev-host exception to R8.

## Alternatives considered

- A dedicated range uid and root-owned launcher: guards range results against the agents, but they
  are benign tests whose results only inform us; revisit with real malware samples (floor 2).
- libvirt: root-owned networks and pools the range does not need. guestfish: a large parser of
  guest-written data where a byte stream suffices. PowerShell runners: a large runtime for shell.

## Consequences

- Tests: a results disk carrying a qcow2 header is read as raw bytes; serial output past the budget
  ends INVALID; QEMU cannot connect to 127.0.0.1 or read `$HOME`; the guest lists no network
  interface besides loopback; the smoke test shows Laurel output, not only a running service.
- `THREAT_MODEL.md` gains rows for hostile guest output, Atomic Red Team as supply chain, and range
  results trusted only as far as the maintainer's uid (agents could forge them).
- Known risks: mkosi #4438 for Overlay=/BaseTrees builds; a hardened kernel may disable the
  unprivileged user namespaces both mkosi and bwrap need — checked before the first run.
