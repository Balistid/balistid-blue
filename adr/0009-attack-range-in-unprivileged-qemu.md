# 0009 — Run the attack range as throwaway QEMU VMs built by mkosi, without root

- Status: proposed (accepted after the first range run passes)
- Date: 2026-10-02
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R10 needs an attack and a legitimate scenario for every detection, and ADR 0004 needs a smoke test of
auditd and Laurel on the target kernel. Attacks must not run on the host, and Docker shares its kernel.
Checked on 2026-10-02 (facts in the maintainer's analyse notes, versions from the Arch package API):
mkosi 27.1 (Arch `extra`) builds an Arch image as an unprivileged user through user namespaces; Arch's
udev rule gives `/dev/kvm` mode 0666; QEMU 11.1.1 runs without libvirt; libguestfs 1.60.1 reads disk
images without root. mkosi outputs raw disks, not qcow2. Atomic Red Team has 508 Linux tests, about
98 % plain `sh`/`bash`; its runner needs PowerShell (AUR only).

## Decision

1. The range runs as the maintainer's user, no root and no libvirt: `qemu-system-x86_64 -enable-kvm`
   on a fresh qcow2 overlay per run (`qemu-img create -b base -F qcow2`), deleted afterwards.
2. The guest has **no network device** (`-nic none`). Everything it needs is baked into the image at
   build time: Arch base, kernel, audit, our Laurel package (ADR 0004), the rules and configs from
   `deploy/`, and the tests to run. Network techniques get a separate sink VM in a later ADR.
3. The base image is built by mkosi from configuration in the repository (`range/`), pinned to a
   package snapshot date, and converted to qcow2 once. Its sha256 is recorded per build.
4. Inputs go in on a read-only disk; results come out through `-serial file:` and a second throwaway
   disk read afterwards with `guestfish --ro`. No shared folders, no host sockets in the guest.
5. Atomic Red Team is pinned to a commit and run by our own small runner that executes the test's
   shell commands and its cleanup; each run ends CAUGHT, MISSED or INVALID (setup failed).
6. Root is needed once, by the maintainer: `pacman -S mkosi libguestfs`. If a later step needs root, it
   gets its own ADR.

## Alternatives considered

- libvirt system mode: networks and storage pools need root; nothing the range needs that plain QEMU
  lacks. Containers: share the host kernel, so a kernel-level attack hits the host.
- `invoke-atomicredteam` (PowerShell from the AUR) or `atomic-operator` (archived 2023): a large
  runtime or a dead dependency for running shell snippets.
- Building the guest with archinstall or a cloud image: not reproducible from repository config.

## Consequences

- The layout gate admits `range/` (mkosi config, runner) in the pull request that adds it, with tests.
- A range run is evidence only if the overlay was fresh, the base sha256 matches the recorded build
  and the result is not INVALID. The VM never reaches the network or the host filesystem; a test
  starts the guest and checks that it has no network interface besides loopback.
- Known risk: mkosi issue #4438 (systemd 262 overlay refusal) has the documented fallback
  `MKOSI_FORCE_USERNS_FALLBACK=1`. The AUR Laurel package installs no active plugin config, so the
  smoke test must prove Laurel output appears, not only that the service started.
- Claude's sandbox cannot see `/dev/kvm`; range runs happen from the maintainer's shell or with the
  sandbox off, and their logs are committed as results, not trusted from memory.
