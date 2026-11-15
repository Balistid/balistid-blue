# 0076 — Keep the installed release number

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-15
- Decided-by: claude/opus-5.5 (delegated by jvc0n, 2026-11-15)
- Agent: claude/opus-5.5
- Closes ADR 0058 point 6: no signed release older than an installed one installs over it.

## Context

ADR 0058 point 6 leaves replay a T9 residual: an older signed MANIFEST still verifies, so a bundle the maintainer
signed earlier installs over a newer release. The next recorder release changes the shard format; an older collector
started on an unsealed new shard finds no `records` table, counts it empty and removes it (internal/shard
`Recover`, internal/store `recover`). The three components share one `balistid-install`, so the judge or the runner
installing an older release also brings back an older installer.

## Decision

1. MANIFEST v2 is v1 with a fourth header line `release <n>` after the commit, n from 1 to ten digits: the number of
   first-parent commits of `main` up to the release's commit. `release.py manifest --release <n>` writes it.
2. `balistid-install` reads v1 and v2. Right after creating its directories, before the release's first file, it
   writes `/etc/balistid/<component>.release` (`release <n>`, `manifest <sha256 of the MANIFEST>`, root's, 0644).
   After a stop anywhere later, older releases are refused over the files already written; the same one runs again.
3. Before its first write, and in the dry run, it refuses a release whose number is lower than any component's kept
   number; a v1 MANIFEST counts as 0. The same number installs again only for the same component from the
   identical MANIFEST. A kept file that is not root's plain 0644 file in that form refuses (R6). No switch allows a
   downgrade.
4. With no kept file (a first install, or a host with only v1 releases) it accepts. Removing the file needs root;
   that, and the releases before the first v2 one, stay T9 residuals.
5. Order: an installed v1-only installer refuses a v2 MANIFEST, and the bootstrap refuses while an installer exists
   (ADR 0058 point 5). The first release with this installer therefore ships a v1 MANIFEST; CI writes v2 from the
   next release on, in the pull request that needs it (the recorder's new store format).

## Alternatives considered

- The commit time as the number: wall clocks are not ordered (T22).
- A number per component only: the judge's older release would put back the recorder's older installer.
- A switch for a deliberate downgrade: the maintainer can still remove the kept file as root; a switch in the
  installer is one more path an attacker who runs it as root does not need.

## Consequences

- THREAT_MODEL T9: replay stays a residual only as point 4 says.
- The maintainer installs this release with the installed installer before the release that needs v2.
- Revert: a pull request removing the v2 reader, the kept file and this ADR; kept files left on a host are ignored.
