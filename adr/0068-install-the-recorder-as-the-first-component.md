# 0068 — Install the recorder as the first component

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-07
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-07: recorder first, plan approved in session)
- Agent: claude/opus-5.5
- Amends ADR 0064 points 1 and 3 (order, #243) and ADR 0058 points 4 and 5 (`verify` names it; what the first install runs).

## Context

ADR 0064 installs the runner, then the recorder; the host's runner already runs at 2c09799, the 7 days measure the
recorder, which never ran on a host. There `/var/lib` is btrfs and the command line has no `audit=1` (2026-11-07).
Local mode (ADR 0043) needs files nothing ships yet: a relay unit without `balistid-net` (a drop-in cannot drop its
`Requires=`), the witness's and ssh-agent's units and key; `balistid status` asks for `balistid-net` and the relay.

## Decision

1. Components install in this order, each from its own signed bundle `balistid-<component>-bundle.tar`:
   `recorder`, then `witness` (relay, litewitness, ssh-agent, Pi watcher, announce, ntfy token; #203, #204), then
   `runner` (ADR 0058). The bootstrap command (ADR 0058 point 5) runs `recorder`; the others, the host's runner
   included, use the `balistid-install` it installs.
2. `recorder` is the sensor, the collector, the ledger, auditstat and the CLI: four binaries, the collector's service
   and socket, the ledger's and auditstat's services, three `sysusers.conf` and two `tmpfiles.conf` (each checked
   alone), `balistid.rules`, `auditd.conf`, Laurel's plugin and config, the io_uring sysctl, `allowed_signers` and the
   installer. Units, sysusers and tmpfiles go under `/etc` as the runner's; the sensor's files where the range image
   puts them. Before the first write it refuses unless: laurel, augenrules, auditd, auditctl and what augenrules runs
   through PATH are root's executables in `/usr/bin` only root may write (a link only to a name beside it), and no
   directory earlier on systemd's boot PATH holds those names; `_laurel` exists; the command line, printable ASCII,
   holds before `--` exactly one `audit=1` and one decimal `audit_backlog_limit` of at least 65536 and no other audit
   parameter (`-` read as `_`); `/etc/audit/rules.d` holds no `*.rules` but `balistid.rules` and no other root-only
   sysctl file names `io_uring_disabled` (this decides #240: the recorder owns both, moving nothing); the audit
   package's `auditd.conf` exists; and every unit of its own is stopped.
3. It writes its units and configuration, runs `systemd-sysusers` and `systemd-tmpfiles --create` on its own files,
   makes the ledger's key where none is installed (Ed25519 note key, origin `balistid.dev/log/` and 16 random hex
   digits, public 0644 then private 0600 in `/etc/balistid`; an installed pair must sign and verify; a public key alone
   before the log exists is replaced), reloads, enables `auditd.service` and its own units, then writes the sensor's
   files and itself, and starts nothing. The reboot loads the rules and locks them (`-e 2`); the installer and `verify`
   say so first, with io_uring off for the whole host. The first `auditd.conf` it replaces is kept once in
   `/etc/balistid/auditd.conf.orig` for the uninstall.
4. `audit=1` and the backlog limit stay the maintainer's line in the boot entry on 9.5: editing boot entries of every
   loader is the stranger-facing form, decided at ADR 0056's checkpoint with `install_min` and `install_steps`, which
   are measured on fresh VMs as `acceptance/0.toml` says, not on this host. x32 stays a named gap (#197, T8).
5. The store stays on the existing filesystem with its reserve (ADR 0040 point 4); `balistid-install` refuses no
   btrfs on 9.5, as the only 9.5 host is btrfs; T10's btrfs gap is measured in the 7 days. #243's refusal moves to
   `after-install` with its own filesystem.
6. Until `witness` is installed nothing cosigns, no shard retires and `balistid status` is never OK (ADR 0043 point 4).
   The 7 days run with today's caps; #202 stays the maintainer's: a yearly log alone fills `disk_default_gib`.

## Alternatives considered

- Runner first (ADR 0064): installs again what already runs and leaves the recorder unmeasured.
- All of local mode at once: three new units and a key format no range trial ran yet, before any day of data.
- The installer edits the boot entry: systemd-boot, GRUB and UKIs differ; a wrong edit stops the boot, a refusal not.
- Read the command line and PATH as the kernel and systemd do: each reading misses a rule; an allowlist refuses.

## Consequences

- Tests: the table as release.py's, each precondition refused alone, the keys and `auditd.conf.orig`, the bootstrap.
- T9 stays partial for Laurel: the package is the PKGBUILD's pinned release (#244), not in the signed bundle.
- Revert: revert the pull request; then ADR 0064 and 0058 apply as written.
