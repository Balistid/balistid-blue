# 0068 — Install the recorder as the first component

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-07: recorder first, plan approved in session)
- Agent: claude/opus-5.5
- Amends ADR 0064 points 1 and 3 (order, #243) and ADR 0058 points 5 and 7 (what the first install runs).

## Context

ADR 0064 installs the runner, then the recorder. The host's runner already runs at 2c09799 from the shell script;
the 7 days measure the recorder, which has never run on a host. On the maintainer's host `/var/lib` is btrfs and
the kernel command line has no `audit=1` (`findmnt`, `/proc/cmdline`, 2026-11-07). Local mode (ADR 0043) needs
files nothing ships yet: a relay unit without `balistid-net` (a drop-in cannot drop its `Requires=`), the witness's
and ssh-agent's units, a witness key; `balistid status` asks for `balistid-net` and the relay.

## Decision

1. Components install in this order, each from its own signed bundle `balistid-<component>-bundle.tar`:
   `recorder`, then `witness` (relay, litewitness, ssh-agent, Pi watcher, announce, ntfy token; #203, #204), then
   `runner` (ADR 0058). The bootstrap command (ADR 0058 point 5) runs `recorder`; the others use the installed
   `balistid-install`. `deploy/runner/install` stays until `runner` runs from the installer.
2. `recorder` is the sensor, the collector, the ledger, auditstat and the CLI: the four binaries, the collector's
   service and socket, the ledger's and auditstat's services, their three `sysusers.conf` and two `tmpfiles.conf`,
   `balistid.rules`, `auditd.conf`, Laurel's plugin and config, the io_uring sysctl, `allowed_signers` and the
   installer last. Units, sysusers and tmpfiles go under `/etc` as the runner's; the sensor's files where the range
   image puts them. Before the first write it refuses unless: `/usr/bin/laurel`, `/usr/bin/augenrules`,
   `/usr/bin/auditd` and `/usr/bin/gawk` are root's regular files no group or other may write; `_laurel` exists;
   `/proc/cmdline` holds `audit=1` and `audit_backlog_limit=65536`; `/etc/audit/rules.d` holds no `*.rules` (what
   augenrules reads) but `balistid.rules` (it decides #240: the recorder owns them; it moves none); and every unit of
   its own is stopped. auditd may run: its new `auditd.conf` takes effect at the reboot.
3. It writes the files, runs `systemd-sysusers` and `systemd-tmpfiles --create` on its own files, makes the ledger's
   key where none is installed (Ed25519 note key, origin `balistid.dev/log/` and 16 random hex digits, private
   0600 and public 0644 in `/etc/balistid`; an installed pair must parse and match, else it refuses), reloads,
   enables `auditd.service`, the collector's socket and service, the ledger and auditstat, and starts nothing. The
   reboot after it loads the rules and locks them (`-e 2`); the installer and `verify` say so before it writes,
   with io_uring off for the whole host. The first `auditd.conf` it replaces is kept once in
   `/etc/balistid/auditd.conf.orig` for the uninstall.
4. `audit=1` and the backlog limit stay the maintainer's line in the boot entry on 9.5: editing boot entries of every
   loader is the stranger-facing form, decided at ADR 0056's checkpoint with `install_min` and `install_steps`, which
   are measured on fresh VMs as `acceptance/0.toml` says, not on this host. x32 stays a named gap (#197, T8).
5. The store stays on the existing filesystem with its reserve (ADR 0040 point 4); `balistid-install` refuses no
   btrfs on 9.5, as the only 9.5 host is btrfs; T10's btrfs gap is measured in the 7 days. #243's refusal moves to
   `after-install` with its own filesystem.
6. Until `witness` is installed nothing cosigns, so no shard retires and `balistid status` names the missing relay,
   tunnel and announce units: never OK, as ADR 0043 point 4 wants for history. The caps of #202 land before install.

## Alternatives considered

- Runner first (ADR 0064): installs again what already runs and leaves the recorder unmeasured.
- All of local mode at once: three new units and a key format no range trial ran yet, before any day of data.
- The installer edits the boot entry: archinstall's systemd-boot entries, GRUB and UKIs differ; a wrong edit
  stops the boot, a refusal stops nothing.

## Consequences

- Tests as ADR 0058's for the recorder's table, each precondition refused alone, an installed key kept, a
  mismatched pair refused, `auditd.conf.orig` written once. The bootstrap command test runs `recorder`.
- T9 stays partial for Laurel: the package is the PKGBUILD's pinned release (#244), not in the signed bundle.
- Revert: revert the pull request; then ADR 0064 and 0058 apply as written.
