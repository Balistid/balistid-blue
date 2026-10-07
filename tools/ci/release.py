#!/usr/bin/env python3
"""The files root installs for the range runner and their MANIFEST (ADR 0011, point 1).

manifest:  copy the runner binary and deploy/runner into a new directory and write MANIFEST, the
           sha256sum line of each file (for a person reading the bundle; root checks the bundle hash).
bundle:    one deterministic tar of that directory. CI uploads it and prints its sha256 only on a
           push to main; the maintainer downloads it.
build:     the manifest directory from a commit of a local repository, built with the flags of CI's
           go-release job and the upstream toolchain go.mod pins, to compare with CI's.
bootstrap: the root command CI prints beside that hash. In an empty environment it reads the bundle
           with the maintainer's rights (root opens nothing they name), capped, into a new root-only
           directory, checks it against the hash and only then unpacks it and runs its install.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import go_gate

BINARY = "balistid-runner"
DEPLOY = ("install", "sysusers.conf", "tmpfiles.conf", "balistid-runner-build.service",
          "balistid-runner-tick.service", "balistid-runner-tick.timer")
FILES = (BINARY, *DEPLOY)
EXECUTABLE = {BINARY, "install"}
# Equal to the go build line and flags of ci.yml's go-release job (pinned by a test).
VERSION_FLAG = "-X github.com/Balistid/balistid-blue/internal/buildinfo.Version="
GO_BUILD = ("build", "-trimpath", "-buildvcs=false", "-ldflags")

BUNDLE = "balistid-runner-bundle.tar"
BUNDLE_MAX_MIB = 64
# $1 is the bundle's sha256 from the CI log (hex only). The bundle's directory and the maintainer are read
# as data, typed as dir=... and user=...: nothing typed is parsed by a shell, and a typo that makes sh
# read its commands from that input (-s for -c) only assigns. The gate is data flow: the download is
# renamed to its own hash and tar opens only the file named by the typed hash, so a typo that skips the if
# still finds nothing to unpack; the hasher's name does not start with "sh". The agent's directory ($dl)
# and root's copy ($ro), like ${hash} and ${1}, differ by more than one letter. A hand-typed command
# cannot be safe against every typo (an inserted ">" or a retargeted path remain): tests cover every
# dropped character and the typos review found, and root reads the command against the CI log before
# Enter. Under `env -i` and `sh -p`: root's shell may carry the maintainer's TMPDIR, PATH or exported
# functions. runuser -u keeps root's console as the reader's terminal; that it cannot be driven from there
# assumes Yama ptrace_scope >= 1.
BOOTSTRAP = (
    'IFS= read -r a && IFS= read -r b && case $a$b in dir=/*user=*) ;; *) false ;; esac && '
    'dl=${a#dir=} && m=${b#user=} && [ "$(id -u -- "$m")" -ge 1000 ] && '
    'ro=$(mktemp -d /tmp/balistid-install.XXXXXXXXXX) && '
    f'timeout -k 5 20 runuser -u "$m" -- cat -- "$dl/{BUNDLE}" </dev/null | head -c {BUNDLE_MAX_MIB << 20} > "$ro/b" && '
    'hash=$(cksum -a sha256 --untagged < "$ro/b") && mv -- "$ro/b" "$ro/${hash%% *}" && '
    'if [ -f "$ro/$1" ]; then tar -xf "$ro/$1" -C "$ro" && sh "$ro/install" "$ro" "$m" "$1"; '
    'else logger -s -t balistid-install "bundle does not match the typed sha256"; false; fi; '
    'r=$?; rm -rf -- "$ro" || r=9; [ $r = 0 ] || logger -s -t balistid-install "bootstrap stopped, status $r"; exit $r'
)
ROOT_PATH = "/usr/bin:/usr/sbin"



def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(binary: Path, deploy: Path, out: Path) -> str:
    out.mkdir(mode=0o700)
    for name in FILES:
        src = binary if name == BINARY else deploy / name
        if not stat.S_ISREG(src.lstat().st_mode):
            raise ValueError(f"{src}: not a regular file")
        shutil.copyfile(src, out / name, follow_symlinks=False)
        (out / name).chmod(0o755 if name in EXECUTABLE else 0o644)
    text = "".join(f"{sha256(out / name)}  {name}\n" for name in FILES)
    (out / "MANIFEST").write_text(text)
    return hashlib.sha256(text.encode()).hexdigest()


def bundle(src: Path, out: Path) -> str:
    """Packs src (as manifest left it) into out: fixed order, owner, time and modes, so equal inputs give
    equal bytes."""
    with tarfile.open(out, "x", format=tarfile.USTAR_FORMAT) as tar:
        for name in ("MANIFEST", *FILES):
            path = src / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"{path}: not a regular file")
            data = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755 if name in EXECUTABLE else 0o644
            tar.addfile(info, io.BytesIO(data))
    if out.stat().st_size > BUNDLE_MAX_MIB << 20:
        raise ValueError(f"{out}: over {BUNDLE_MAX_MIB} MiB, the bootstrap would cut it")
    return sha256(out)


def build(repo: Path, commit: str, out: Path) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"commit {commit!r} is not 40 hex digits")
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        src = t / "src"
        src.mkdir()
        archive = subprocess.run(["git", "-C", str(repo), "archive", commit], check=True, capture_output=True)
        subprocess.run(["tar", "-x", "-C", str(src)], input=archive.stdout, check=True)
        go_mod = (src / "go.mod").read_text()
        pinned = re.findall(r"^toolchain go(\S+)$", go_mod, re.MULTILINE)
        if len(pinned) != 1:
            raise ValueError("go.mod must pin exactly one toolchain")
        env = {"PATH": os.environ["PATH"], "HOME": str(t / "home"), "TMPDIR": tmp,
               "GOPATH": str(t / "gopath"), "GOCACHE": str(t / "cache"), "GOTOOLCHAIN": f"go{pinned[0]}",
               "GOFLAGS": "-mod=readonly", "GOWORK": "off", "CGO_ENABLED": "0"}
        # The proxy chooses the network path to the toolchain, not what is built.
        env |= {k: os.environ[k] for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY") if k in os.environ}
        goversion = subprocess.run(["go", "env", "GOVERSION"], cwd=src, env=env, check=True,
                                   capture_output=True, text=True).stdout.strip()
        if problems := go_gate.toolchain_problems(go_mod, goversion, pinned[0]):
            raise ValueError("; ".join(problems))
        binary = t / BINARY
        subprocess.run(["go", *GO_BUILD, VERSION_FLAG + commit, "-o", str(binary), f"./cmd/{BINARY}"],
                       cwd=src, env=env, check=True)
        manifest(binary, src / "deploy" / "runner", out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest")
    m.add_argument("--binary", type=Path, required=True)
    m.add_argument("--deploy", type=Path, required=True)
    m.add_argument("--out", type=Path, required=True)
    t = sub.add_parser("bundle")
    t.add_argument("--dir", type=Path, required=True)
    t.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("build")
    b.add_argument("--repo", type=Path, required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--out", type=Path, required=True, help="a new directory; gets files/ and the bundle")
    sub.add_parser("bootstrap").add_argument("sha256")
    args = parser.parse_args(argv)
    if args.cmd == "bootstrap":
        if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
            print("release: not a sha256", file=sys.stderr)
            return 1
        print("As root at a console login only (not sudo or su from a desktop session an agent can control),")
        print("hash read from a push run on main on another device; then type two lines, dir=<the bundle's")
        print("directory> and user=<the maintainer, uid 1000 or more>. Ctrl-C may leave /tmp/balistid-install.*:")
        print(f"/usr/bin/env -i PATH={ROOT_PATH} /usr/bin/sh -p -c '{BOOTSTRAP}' - {args.sha256}")
        return 0
    try:
        if args.cmd == "manifest":
            manifest(args.binary, args.deploy, args.out)
            return 0
        if args.cmd == "bundle":
            bundle(args.dir, args.out)
            return 0
        args.out.mkdir(mode=0o700)
        build(args.repo, args.commit, args.out / "files")
        digest = bundle(args.out / "files", args.out / BUNDLE)
    except (OSError, ValueError, subprocess.CalledProcessError) as err:
        print(f"release: {err}", file=sys.stderr)
        return 1
    print(f"local bundle sha256: {digest}")
    print("Root types only the hash CI printed; the bundle here is usable only if the two are equal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
