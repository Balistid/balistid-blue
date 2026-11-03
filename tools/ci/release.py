#!/usr/bin/env python3
"""The files root installs for the range runner and their MANIFEST (ADR 0011, point 1; ADR 0058).

manifest:  copy the runner and installer binaries, deploy/runner and the maintainer's allowed_signers into a new
           directory and write MANIFEST v1: its header, then the sha256sum line of each file, sorted. The
           maintainer signs it; balistid-install checks the signature and every file against it.
bundle:    one deterministic tar of that directory. CI uploads it with the MANIFEST and prints the MANIFEST only
           on a push to main; the maintainer downloads both.
build:     the manifest directory from a commit of a local repository, built with the flags of CI's
           go-release job and the upstream toolchain go.mod pins, to compare with CI's.
bootstrap: the root command CI prints for the first install, with the key's fingerprint. In an empty environment
           it reads the bundle and the signature with the maintainer's rights (root opens nothing they name),
           capped, into a new root-only directory, and runs the bundle's balistid-install only if the signature
           is by the key with that fingerprint and the binary is the one the signed MANIFEST names.
"""

from __future__ import annotations

import argparse
import base64
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
INSTALLER = "balistid-install"
SIGNERS = "allowed_signers"
DEPLOY = ("sysusers.conf", "tmpfiles.conf", "balistid-runner-build.service", "balistid-runner-tick.service",
          "balistid-runner-tick.timer")
FILES = tuple(sorted((BINARY, INSTALLER, SIGNERS, *DEPLOY)))
EXECUTABLE = {BINARY, INSTALLER}
COMPONENT = "runner"
# Equal to the go build line and flags of ci.yml's go-release job (pinned by a test).
VERSION_FLAG = "-X github.com/Balistid/balistid-blue/internal/buildinfo.Version="
GO_BUILD = ("build", "-trimpath", "-buildvcs=false", "-ldflags")

BUNDLE = "balistid-runner-bundle.tar"
BUNDLE_MAX_MIB = 64
SIG = "MANIFEST.sig"
SIG_MAX_BYTES = 4 << 10  # internal/install's maxSigBytes
# $1 is the key's fingerprint. The bundle's directory and the maintainer are read as data, typed as dir=... and
# user=...: nothing typed is parsed by a shell, and a typo that makes sh read its commands from that input (-s for
# -c) only assigns. The gate is data flow: the binary is renamed to its own sha256 and run only by the name the
# MANIFEST gives it, inside the one case arm a verify output ending in the typed fingerprint reaches, so a typo that
# skips a check finds nothing to run; tar only prints members (-O), so nothing in the bundle is resolved on disk. A
# hand-typed command cannot be safe against every typo: tests cover every dropped character and the typos review
# found, and root reads the command against the CI log before Enter. Under `env -i` and `sh -p`: root's shell may
# carry the maintainer's TMPDIR, PATH or exported functions. runuser -u keeps root's console as the reader's
# terminal; that it cannot be driven from there assumes Yama ptrace_scope >= 1.
BOOTSTRAP = (
    'IFS= read -r a && IFS= read -r b && case $a$b in dir=/*user=*) ;; *) false ;; esac && '
    'dl=${a#dir=} && m=${b#user=} && [ "$(id -u -- "$m")" -ge 1000 ] && '
    'ro=$(mktemp -d /tmp/balistid-install.XXXXXXXXXX) && '
    f'timeout -k 5 20 runuser -u "$m" -- cat -- "$dl/{BUNDLE}" </dev/null | head -c {BUNDLE_MAX_MIB << 20} > "$ro/{BUNDLE}" && '
    f'timeout -k 5 20 runuser -u "$m" -- cat -- "$dl/{SIG}" </dev/null | head -c {SIG_MAX_BYTES} > "$ro/{SIG}" && '
    f'tar -xOf "$ro/{BUNDLE}" {SIGNERS} > "$ro/k" && tar -xOf "$ro/{BUNDLE}" MANIFEST > "$ro/m" && '
    f'tar -xOf "$ro/{BUNDLE}" {INSTALLER} > "$ro/i" && h=$(cksum -a sha256 --untagged < "$ro/i") && '
    'mv -- "$ro/i" "$ro/${h%% *}" && '
    f'v=$(ssh-keygen -Y verify -f "$ro/k" -I maintainer@balistid.dev -n install@balistid.dev -s "$ro/{SIG}" < "$ro/m"); '
    f'case $v in *" key $1") x=$(sed -n "s/  {INSTALLER}\\$//p" "$ro/m") && chmod 700 -- "$ro/$x" && '
    '"$ro/$x" runner "$ro" "$m" "$1" ;; '
    '*) logger -s -t balistid-install "the manifest is not signed by the typed key"; false ;; esac; '
    'r=$?; rm -rf -- "$ro" || r=9; [ $r = 0 ] || logger -s -t balistid-install "bootstrap stopped, status $r"; exit $r'
)
ROOT_PATH = "/usr/bin:/usr/sbin"
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(binary: Path, installer: Path, deploy: Path, signers: Path, commit: str, out: Path) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"commit {commit!r} is not 40 hex digits")
    out.mkdir(mode=0o700)
    sources = {BINARY: binary, INSTALLER: installer, SIGNERS: signers} | {name: deploy / name for name in DEPLOY}
    for name in FILES:
        src = sources[name]
        if not stat.S_ISREG(src.lstat().st_mode):
            raise ValueError(f"{src}: not a regular file")
        shutil.copyfile(src, out / name, follow_symlinks=False)
        (out / name).chmod(0o755 if name in EXECUTABLE else 0o644)
    text = f"balistid-manifest 1\ncomponent {COMPONENT}\ncommit {commit}\n"
    text += "".join(f"{sha256(out / name)}  {name}\n" for name in FILES)
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


def fingerprint(signers: Path) -> str:
    """The SHA256 fingerprint ssh-keygen prints for the key of the one allowed_signers line."""
    text = signers.read_text()
    fields = text.removesuffix("\n").split(" ")
    if len(fields) != 4 or text.count("\n") != 1 or not text.endswith("\n"):
        raise ValueError(f"{signers}: not one allowed_signers line of four fields")
    blob = base64.b64decode(fields[3], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


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
        for cmd in (BINARY, INSTALLER):
            subprocess.run(["go", *GO_BUILD, VERSION_FLAG + commit, "-o", str(t / cmd), f"./cmd/{cmd}"],
                           cwd=src, env=env, check=True)
        manifest(t / BINARY, t / INSTALLER, src / "deploy" / "runner", src / "deploy" / "install" / SIGNERS,
                 commit, out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest")
    for flag in ("--binary", "--installer", "--deploy", "--signers", "--out"):
        m.add_argument(flag, type=Path, required=True)
    m.add_argument("--commit", required=True)
    t = sub.add_parser("bundle")
    t.add_argument("--dir", type=Path, required=True)
    t.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("build")
    b.add_argument("--repo", type=Path, required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--out", type=Path, required=True, help="a new directory; gets files/ and the bundle")
    sub.add_parser("bootstrap").add_argument("--signers", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "bootstrap":
            fp = fingerprint(args.signers)
            if not FINGERPRINT.fullmatch(fp):
                raise ValueError(f"{args.signers}: not a key")
            print("First install only, as root at a console login (not sudo or su from a desktop session an agent can")
            print("control), read on another device; the fingerprint at its end must be the one README.md publishes.")
            print(f"Then type two lines, dir=<the directory with {BUNDLE} and {SIG}> and user=<the maintainer, uid")
            print("1000 or more>. Ctrl-C may leave /tmp/balistid-install.*:")
            print(f"/usr/bin/env -i PATH={ROOT_PATH} /usr/bin/sh -p -c '{BOOTSTRAP}' - {fp}")
            return 0
        if args.cmd == "manifest":
            manifest(args.binary, args.installer, args.deploy, args.signers, args.commit, args.out)
            return 0
        if args.cmd == "bundle":
            bundle(args.dir, args.out)
            return 0
        args.out.mkdir(mode=0o700)
        build(args.repo, args.commit, args.out / "files")
        bundle(args.out / "files", args.out / BUNDLE)
    except (OSError, ValueError, subprocess.CalledProcessError) as err:
        print(f"release: {err}", file=sys.stderr)
        return 1
    print(f"local MANIFEST: {args.out / 'files' / 'MANIFEST'}")
    print("Sign the MANIFEST only if it equals the one CI printed for this commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
