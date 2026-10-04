# 0010 — Build range images from a verified export of the launcher's own commit

- Status: proposed
- Date: 2026-10-04
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`kordon-range build` (ADR 0009) checked that the work tree matched HEAD, then built from the work
tree. Review of pull request #22 showed, with working probes, that an agent at the maintainer's uid
can pass that check while the build reads other bytes: `git replace`, `assume-unchanged`, a symlink,
or a loose object whose content does not match its name (git serves it unchecked). A local
`.git/config` (`core.fsmonitor`, filters) runs programs during `git status`. A second design, letting
a launcher from `main` build another commit when only guest code differed, failed review again: Go
compiles assembly from any imported package, and `#include` in it reads host files. Building a commit
runs its host-side inputs (the PKGBUILD is a shell script, `mkosi.conf` can name host paths, `go.mod`
can `replace` with a host directory), and no file list makes that safe (R7).

## Decision

1. Build makes an image of the commit the launcher was built from (its clean VCS stamp; a launcher
   without one is refused). Which commit's code may run on the host is decided by the maintainer who
   builds the launcher; building a commit means running it.
2. git never runs in the source repository: its configuration, attributes, refs and work tree are
   writable by an agent. A repository of ours borrows its object store (`alternates`) and, with our
   configuration, sends only the commit's objects (`rev-list --objects --no-walk`, `pack-objects`, no
   history) through `index-pack --fsck-objects`, which names every object by its recomputed hash and
   refuses malformed trees, into a fresh repository where all of them must be present, so a forged
   object is refused. A time limit ends a copy that stalls on the object store (a FIFO).
3. The commit is exported from that repository file by file (`git cat-file blob`) into an empty
   directory. Only regular files (modes 100644 and 100755) with plain relative paths are accepted:
   no symlink, submodule, `..` or `.git`. Every file is created (never opened if it exists) with mode
   0644 or 0755. Pack size, listing size, entry count, file size, export size, path length and depth
   are capped (R5).
4. Every tool runs in the export with one fixed environment, caches in the build directory,
   `-buildvcs=false` and no git repository above it (the build directory sits inside the
   maintainer's home repository).

## Alternatives considered

- Keep checking the work tree and patch each bypass: four shapes of one hole (R7).
- Build another commit with a launcher from `main` when only guest-side paths differ: refused in
  review round 2 (assembly `#include`); a safe build of commits nobody reviewed needs confinement.
- Build tools in bwrap without `$HOME`: that confinement. It belongs to the range runner, which is
  the first thing to build unreviewed commits (next ADR).

## Consequences

- Building a commit runs its PKGBUILD and mkosi configuration with the maintainer's rights. The
  launcher is only as clean as the checkout it was built from and the place it is stored (T34).
- An agent's branch is built by the maintainer only after review, until the runner confines builds.
- mkosi downloads the package snapshot on every build (no shared cache to poison); its workspace in
  `/var/tmp` stays a known gap, and a small pack can still inflate to large objects (DoS, T34).
- Tests: the source's configuration, attributes, replace refs, index and work tree are not read; a
  stalled or failed copy ends; forged objects, malformed trees, symlinks, submodules,
  unsafe paths, existing files and every limit are refused; unusual names and modes survive; no
  history is copied; a launcher of another commit is refused; no enclosing repository is stamped.
