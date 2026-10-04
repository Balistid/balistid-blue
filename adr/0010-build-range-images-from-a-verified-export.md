# 0010 — Build range images from a verified export; host-run inputs are the launcher's

- Status: proposed
- Date: 2026-10-04
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

`kordon-range build` (ADR 0009) checked that the work tree matched HEAD, then built from the work
tree. Review of pull request #22 showed, with working probes, that an agent at the maintainer's uid
can make that check pass while the build reads other bytes: `git replace`, `assume-unchanged`, a
loose object whose content does not match its name (git serves it unchecked), or a symlink. A local
`.git/config` (`core.fsmonitor`, filters) runs programs during `git status`. And building a commit
runs that commit's host-side inputs: the PKGBUILD is a shell script, `mkosi.conf` can name host paths
(`Include=`, `ExtraTrees=`, `BaseTrees=`, `PackageCacheDirectory=`), `go.mod` can `replace` a module
with a host directory. This was the fourth shape of one boundary (R7), so the boundary changes: it
names whose code runs on the host instead of checking files.

## Decision

1. Two commits: the launcher's own commit L (its clean VCS stamp; a launcher without one is refused)
   and the commit to build C (HEAD, or `kordon-range build <commit>`).
2. The build reads nothing from the work tree. `git pack-objects` copies C and L from the repository
   into a fresh repository in the build directory through `git index-pack --strict`, which recomputes
   every object hash; a forged object is refused. The source repository runs only `rev-parse` and
   `pack-objects`, with fsmonitor and lazy fetch off.
3. C is exported from that repository file by file (`git cat-file blob`) into an empty directory.
   Only regular files (modes 100644 and 100755) with plain relative paths are accepted: no symlink,
   submodule, `..` or `.git`. Size, entry count, path length and depth are capped (R5).
4. If C is not L, C may differ from L only where nothing runs on the host: Go source and test data
   under `cmd/` and `internal/` (mode 100644), `deploy/` and `acceptance/` data, Markdown, and the CI
   directories no build tool reads. Any other difference, including all of `range/` and `packaging/`
   and every top-level file, refuses the build (allowlist, R7). The PKGBUILD, mkosi configuration and
   `go.mod` that run are therefore always L's.
5. Every tool gets one fixed environment with its caches in the build directory, `-buildvcs=false`
   and no git repository above it (the build directory sits inside the maintainer's home repository).
6. The image stores C (`commit`) and L (`launcher`). Only the launcher that built an image can pass
   its run; any other gives UNKNOWN. A result of an image with C other than L has class `branch`:
   its guest program is C's code and reports its own facts, so it is feedback, not evidence (T33).

## Alternatives considered

- Keep checking the work tree and patch each bypass: four rounds showed the shape is wrong (R7).
- Build tools in bwrap without `$HOME`: still worth doing as defence in depth, but it does not decide
  whose PKGBUILD runs; a separate step.
- Refuse every C other than L: safe, but then no launcher from `main` can build an agent's branch,
  which the range runner (next ADR) needs.

## Consequences

- With C equal to L (the maintainer building their checkout), the host runs that commit's PKGBUILD and
  mkosi configuration: building an unreviewed commit runs its code. The launcher is only as clean as
  the checkout it was built from and the place it is stored (T34).
- A branch that changes `range/`, `packaging/` or `go.mod` is built with a launcher from that branch.
- mkosi downloads the package snapshot on every build (no shared cache to poison); its workspace in
  `/var/tmp` stays a known gap (T34).
- Tests: work tree, index flags, replace refs and untracked files do not reach the export; repository
  configuration runs nothing; a forged object, a symlink, a submodule and unsafe paths are refused; a
  branch changing host inputs is refused; the guest build stamps no enclosing repository.
