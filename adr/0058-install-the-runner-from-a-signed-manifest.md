# 0058 — Install the runner from a signed manifest

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-03
- Decided-by: alex (2026-11-03: runner only, README fingerprint, replay a residual, sk key); claude/opus-5.5 the rest
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
   (regular, one link, capped, through `os.Root`) and verifies the MANIFEST bytes with `/usr/bin/ssh-keygen -Y verify`
   (ADR 0053 point 3; signers and signature as pipes, `LC_ALL=C`, 10 s) before parsing them. A table in its code maps
   names to destinations: runner binary and itself to `/usr/local/lib/balistid/`, units to `/etc/systemd/system/`,
   `{sysusers,tmpfiles}.conf` to `/etc/{sysusers,tmpfiles}.d/balistid-runner.conf`, `allowed_signers` to
   `/etc/balistid/`. Tar, manifest and table name the same files, each matching its sha256.
3. `/etc/balistid/allowed_signers` is one line: `maintainer@balistid.dev`, exactly `namespaces="install@balistid.dev"`
   and a `sk-ssh-ed25519@openssh.com` key (a config field tests set to a software type). It and `/etc/balistid` are
   root:root, 0644 and 0755, never links.
4. `verify <dir> [<fingerprint>]` runs unprivileged and writes nothing: the dry run. `runner <dir> <maintainer>
   [<fingerprint>]` runs as root and keeps every check of the shell script, adding the signature, the hashes, each
   destination's path (no link, owned by root, not group or other writable, not setgid) and target, all before its
   first write. It writes files whole (`wholefile.WriteIn`), runs `systemd-sysusers`, `systemd-tmpfiles --create`,
   `usermod -aG balistid-agents` and `systemctl daemon-reload` by absolute path, checks the units again and writes
   its own binary last; it starts nothing. Each run logs install or refuse, the reason, the manifest's sha256 and
   commit, the signer's fingerprint and its version, to stderr and through `logger`.
5. First install, trust on first use (ADR 0053 point 4): CI prints a root command that takes the key fingerprint
   from `README.md`. In a root-only directory it takes `allowed_signers`, MANIFEST and `balistid-install` out of the
   bundle with `tar -O`, accepts only a verify output ending in the typed fingerprint, names the binary by its
   sha256 and runs it only by the name the signed MANIFEST gives, with the fingerprint. Given one, the runner
   requires no `/etc/balistid/allowed_signers` and a bundle key with that fingerprint, and installs the file.
   Without one, a bundle whose `allowed_signers` differs from the installed one is refused (ADR 0053 point 5).
6. An older signed MANIFEST still verifies: replay is a residual of T9 until the 9.5 components add a stored,
   increasing release number. ADR 0034 point 4 (install time and steps) moves to the ADR of the 9.5 components.
7. `deploy/runner/install` leaves the layout allowlist; `deploy/install/allowed_signers` (the maintainer's key) joins.

## Alternatives considered

- A signature check added to the shell script: no Go tests for `os.Root`, R6 and fuzzed parsers; 9.5 adds eight more.
- Destinations in the manifest: the signer would decide paths; the table keeps them in reviewed code.

## Consequences

- Tests in `internal/install` (fake root, runtime software keys, fake commands); each refusal leaves the tree (path,
  mode, owner, sha256) as it was and runs no command: unsigned, altered, other namespace, other signer, sha256
  mismatch, a file outside manifest or table, a missing file, a duplicate, `..`, `/` or a link in the tar, unknown
  version or component; a linked, foreign or writable destination directory; a linked, FIFO, hard-linked or
  oversized input; allowed_signers linked, foreign, writable, two lines, a wildcard, `cert-authority`, other
  namespaces or key type; ssh-keygen failing, timing out or missing; every `InstallTest` case. Success: exactly the
  expected files, modes and directories, commands `sysusers, tmpfiles, usermod, daemon-reload`. `BootstrapTest`
  covers the new root command, every dropped character included. The release job fails until the key is committed.
- Revert: revert the pull request; root then installs as ADR 0011 point 1 said.
