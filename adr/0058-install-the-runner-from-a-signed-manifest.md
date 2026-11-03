# 0058 — Install the runner from a signed manifest

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex (2026-11-03: runner only, README fingerprint, replay residual, sk key and flags); claude the rest
- Agent: claude/opus-5.5
- Amends ADR 0011 point 1 (the typed hash) and the layout allowlist; implements ADR 0053 for #196.

## Context

Root installs the range runner with a shell script after typing the bundle's sha256 from the CI log: an exception
to R1 and R8 (ADR 0011), with no R2 key (T9). ADR 0053 picked an `ed25519-sk` key and `ssh-keygen -Y verify`.

## Decision

1. CI's release job writes `MANIFEST` v1: `balistid-manifest 1`, `component runner`, `commit <40 hex>`, then one
   `<sha256>  <name>` line per file, sorted. A push to `main` prints it and uploads it beside the bundle (the
   deterministic tar of MANIFEST and the files). The maintainer signs it (ADR 0053 point 2) into `MANIFEST.sig`.
2. `balistid-install` (`cmd/balistid-install`, `internal/install`) reads bundle and signature once into memory
   (regular, one link, capped, through `os.Root`). `/usr/bin/ssh-keygen -Y verify` (ADR 0053 point 3; signers and
   signature as pipes, `LC_ALL=C`, 10 s) must exit 0; then it verifies the SSHSIG itself with the allowed key and
   requires the sk flags user presence (0x01) and verification (0x04), which ssh-keygen 10.6 does not check, before
   it parses the MANIFEST. A table in its code maps each name to its destination (binaries to
   `/usr/local/lib/balistid/`, units, the two `.conf`s, `allowed_signers`); tar, manifest and table name the same files.
3. `/etc/balistid/allowed_signers` is one line: `maintainer@balistid.dev`, exactly `namespaces="install@balistid.dev"`
   and a `sk-ssh-ed25519@openssh.com` key (tests use software sk keys), root:root 0644 in a 0755 directory, never
   links. The type is a label: that the key lives on a token is the maintainer's word, unattested.
4. `verify <dir> [<fingerprint>]` is the unprivileged dry run. `runner <dir> <maintainer> [<fingerprint>]` runs as
   root, keeps every check of the shell script and adds the signature, the hashes, each destination's path (no link,
   owned by root, not group or other writable, not setgid), each target, `/var/lib/balistid` and each directory
   tmpfiles.conf names with its parent (type and owner only where tmpfiles gives it to another user and restores its
   mode), all before its first write. It writes files whole, runs `systemd-sysusers`, `systemd-tmpfiles --create`,
   `usermod -aG balistid-agents` and `systemctl daemon-reload` by absolute path, checks the units again, writes itself
   last and starts nothing. Each run logs a record (`schema_version`, outcome, reason, manifest sha256, commit, signer
   fingerprint, version) to stderr and `logger`.
5. First install only, trust on first use (ADR 0053 point 4): CI prints a root command taking the fingerprint
   README.md and balistid.dev publish; it refuses while `/usr/local/lib/balistid/balistid-install` exists. In a
   root-only directory tar reads `allowed_signers`, MANIFEST and `balistid-install` from stdin under `ulimit -f`, its
   status checked; ssh-keygen must exit 0 with an output ending in the typed fingerprint; only the file named by the
   MANIFEST's 64-hex digest runs, the installer renamed to its sha256. It trusts ssh-keygen, which does not check sk
   flags: a T9 residual of the first install until OpenSSH does. Given a fingerprint, the runner takes the bundle's
   key if it has it and none is installed, or an installed key that passes every check, equals the bundle's and has
   it (a stopped first install runs again). Without one, another `allowed_signers` in the bundle is refused.
6. An older signed MANIFEST still verifies: replay is a residual of T9 until the 9.5 components add a stored,
   increasing release number. ADR 0034 point 4 (install time and steps) moves to the ADR of the 9.5 components.
7. `deploy/runner/install` goes (its layout entry after merge: `--range`); `deploy/install/allowed_signers` comes later.

## Alternatives considered

- A signature check added to the shell script: no Go tests for `os.Root`, R6 and fuzzed parsers; 9.5 adds eight more.
- Destinations in the manifest: the signer would decide paths; the table keeps them in reviewed code.

## Consequences

- Tests (fake root, runtime software sk keys, fake commands); a refusal leaves the tree (path, mode, owner, sha256)
  as it was and runs no command: unsigned, altered, other namespace or signer, sk flags without touch and PIN, sha256
  mismatch, a file outside manifest or table, missing, duplicate, `..`, `/` or a link in the tar; a linked, foreign or
  writable destination or tmpfiles directory; a linked, FIFO, hard-linked or oversized input; a bad allowed_signers;
  ssh-keygen failing, hanging or missing; every `InstallTest` case. `BootstrapTest` covers every dropped character.
  The release job fails until the key comes with its README row. Revert: revert the pull request (ADR 0011 pt 1).
