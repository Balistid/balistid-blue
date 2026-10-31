#!/usr/bin/env python3
"""Build the checked-out commit's range image and run its self-test, or one trial, on a GitHub-hosted
runner's KVM (ADR 0028, ADR 0037).

The runner is a throwaway VM, so this script changes it with sudo: /dev/kvm for the runner user and
unprivileged user namespaces for bwrap and mkosi. The Arch tools run in an archlinux container pinned
by digest, with packages from a dated archive snapshot (R14), as an unprivileged user with the
runner's uid. The verdict is advisory; only the local runner records evidence (ADR 0011, point 7).
The runner check below only keeps the script off other machines by mistake; it proves nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

# archlinux:base-devel of 2026-10-27; the index digest, so docker picks the amd64 image under it.
IMAGE = "docker.io/library/archlinux@sha256:624bdc7fc6615155d67bc34cf7146c0c9fd0e3c92943977da63a630e4ca49c30"
# Host tools from this day of the Arch archive (go 1.27.3, mkosi 27.1); the image's own packages
# come from the snapshot in range/mkosi.conf.
SNAPSHOT = "2026/10/27"
# What the range build and run call besides base-devel (makepkg): internal/rangevm/session.go, vm.go,
# and the mkosi optional dependencies a bootable disk image needs (python-pefile, ukify, cpio, mkfs).
PACKAGES = ("git", "go", "mkosi", "qemu-base", "edk2-ovmf", "bubblewrap", "dosfstools", "mtools",
            "python-pefile", "systemd-ukify", "cpio", "e2fsprogs")
# Measured locally: a 1.5 GiB image, a build stage, the run's overlay and scratch disk (4 GiB cap).
MIN_FREE = 12 << 30
KVM = Path("/dev/kvm")
USERNS_SYSCTL = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
UDEV_RULE = 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"\n'

# Runs in the container as root, then as the runner's uid with a fixed environment; the packages are
# its arguments, the snapshot and uid come through --env, so nothing is spliced into the text.
CONTAINER_SCRIPT = r"""set -euo pipefail
printf 'Server = https://archive.archlinux.org/repos/%s/$repo/os/$arch\n' "$SNAPSHOT" > /etc/pacman.d/mirrorlist
pacman -Syyuu --noconfirm --needed "$@"
useradd --no-create-home --home-dir /cache/home --uid "$RANGE_UID" range
exec runuser -u range -- /usr/bin/env -i HOME=/cache/home XDG_CACHE_HOME=/cache XDG_STATE_HOME=/state \
  RANGE_TRIAL="${RANGE_TRIAL:-}" PATH=/usr/bin GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 /usr/bin/bash -euo pipefail -c '
mkdir -p "$HOME"
cd /src
go build -trimpath -o "$HOME/balistid-range" ./cmd/balistid-range
image=$("$HOME/balistid-range" build)
echo "image: $image"
if [ -n "$RANGE_TRIAL" ]; then "$HOME/balistid-range" trial "$RANGE_TRIAL" "$image"; else "$HOME/balistid-range" run "$image"; fi'
"""

# A verdict other than PASS becomes one annotation, which the API serves (check-runs/<id>/annotations)
# where the job's log host may be out of reach. Workflow commands are on again by then, so the guest's
# text is escaped as command data and capped.
ANNOTATION_MAX = 4000
RESULT_ID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
# A trial's name as ADR 0018 point 1 allows it; the launcher's closed table refuses any other (T37).
TRIAL_NAME = re.compile(r"[a-z0-9-]{1,32}")


def verdict_annotation(state: Path, title: str = "range-kvm self-test", unexpected: bool = False) -> str | None:
    """The newest run's verdict and reason as an ::error:: command, or None when it left none or passed and
    unexpected is false; with unexpected the launcher refused the verdict, so even a control's PASS is shown."""
    results = sorted(p for p in (state / "balistid-range" / "results").glob("*/result.json")
                     if RESULT_ID.fullmatch(p.parent.name))
    if not results:
        return None
    unreadable = f"::error title={title}::the result could not be read"
    # Container root can write the state directory: no symlink, no FIFO, a regular file only.
    try:
        fd = os.open(results[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return unreadable
            data = json.loads(f.read(1 << 20))
    except (OSError, ValueError):
        return unreadable
    if not isinstance(data, dict):
        return unreadable
    verdict, reason = data.get("verdict"), data.get("reason")
    if verdict == "PASS" and not unexpected:
        return None
    text = f"{verdict}: {reason}"[:ANNOTATION_MAX]
    return f"::error title={title}::" + text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class RangeError(Exception):
    """A condition under which the self-test did not run; the job fails (R6)."""


Runner = Callable[..., subprocess.CompletedProcess]


def check_runner(env: Mapping[str, str]) -> None:
    """Refuse anywhere but a GitHub-hosted runner: the script changes the machine with sudo."""
    if env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RangeError("runs only on a GitHub-hosted runner (GITHUB_ACTIONS, RUNNER_ENVIRONMENT)")


def check_kvm(path: Path) -> None:
    """Fail unless path is a character device: a runner without KVM must not pass as a skip."""
    try:
        mode = path.stat().st_mode
    except OSError as err:
        raise RangeError(f"no {path}: the runner has no KVM, the self-test did not run") from err
    if not stat.S_ISCHR(mode):
        raise RangeError(f"{path} is not a character device")


def check_free(path: Path, need: int) -> None:
    free = shutil.disk_usage(path).free
    print(f"free on {path}: {free >> 20} MiB", flush=True)
    if free < need:
        raise RangeError(f"{free} bytes free on {path}, the self-test needs {need}")


def prepare_host(run: Runner, kvm: Path, sysctl: Path) -> None:
    """Open /dev/kvm to the runner user (GitHub changelog 2024-04-02) and allow user namespaces."""
    run(["sudo", "tee", "/etc/udev/rules.d/99-kvm4all.rules"], input=UDEV_RULE, text=True,
        stdout=subprocess.DEVNULL, check=True)
    run(["sudo", "udevadm", "control", "--reload-rules"], check=True)
    run(["sudo", "udevadm", "trigger", "--name-match=kvm"], check=True)
    run(["sudo", "udevadm", "settle"], check=True)
    if not os.access(kvm, os.R_OK | os.W_OK):
        raise RangeError(f"{kvm} is not readable and writable after the udev rule")
    if sysctl.exists():
        run(["sudo", "sysctl", "-w", "kernel.apparmor_restrict_unprivileged_userns=0"], check=True)


def docker_argv(repo: Path, state: Path, cache: Path, uid: int, trial: str = "") -> list[str]:
    """The container: KVM, no added capability, the source read-only, state and cache from the work
    directory. seccomp, AppArmor and the masked /proc paths stay off because bwrap and mkosi make
    user namespaces and mount a fresh /proc in them. Without them, container root (the pacman step)
    can write the host's /proc/sys: on a hosted runner that is no more than the step's own sudo."""
    return [
        "docker", "run", "--rm",
        "--device", "/dev/kvm",
        "--security-opt", "seccomp=unconfined",
        "--security-opt", "apparmor=unconfined",
        "--security-opt", "systempaths=unconfined",
        "--volume", f"{repo}:/src:ro",
        "--volume", f"{state}:/state",
        "--volume", f"{cache}:/cache",
        "--env", f"SNAPSHOT={SNAPSHOT}",
        "--env", f"RANGE_UID={uid}",
        *(["--env", f"RANGE_TRIAL={trial}"] if trial else []),
        IMAGE,
        "/usr/bin/bash", "-c", CONTAINER_SCRIPT, "bash", *PACKAGES,
    ]


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] = os.environ, run: Runner = subprocess.run,
         kvm: Path = KVM, sysctl: Path = USERNS_SYSCTL) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work", type=Path, required=True, help="directory for the state and cache mounts")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--trial", help="run this trial of the table instead of the self-test (ADR 0037)")
    args = parser.parse_args(argv)
    trial = args.trial or ""
    what = f"trial {trial}" if TRIAL_NAME.fullmatch(trial) else "self-test"
    title = f"range-kvm {what}"
    try:
        if args.trial is not None and not TRIAL_NAME.fullmatch(args.trial):  # an empty one too: no silent self-test
            raise RangeError("--trial is not a trial name (^[a-z0-9-]{1,32}$)")
        check_runner(env)
        check_kvm(kvm)
        state, cache = args.work / "state", args.work / "cache"
        state.mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)
        check_free(args.work, MIN_FREE)
        prepare_host(run, kvm, sysctl)
    except (RangeError, OSError, subprocess.CalledProcessError) as err:
        print(f"range-kvm: {err}", file=sys.stderr)
        return 1
    # The build prints package and crate output; with workflow commands off, none of it can become an
    # annotation in the run whose log root reads the bundle sha256 from (ADR 0011, point 1).
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}", flush=True)
    try:
        done = run(docker_argv(args.repo.resolve(), state.resolve(), cache.resolve(), os.getuid(), trial), check=False)
    finally:
        # On a line of its own: the runner resumes commands only on a line that starts with "::".
        print(f"\n::{token}::", flush=True)
    # The launcher exits non-zero exactly when the verdict is not the expected one: a control's MISS is no error.
    if done.returncode != 0:
        annotation = verdict_annotation(state, title, unexpected=True) or \
            f"::error title={title}::no result: the build or {what} failed (exit {done.returncode})"
        print(annotation, flush=True)
    if done.returncode != 0:
        print(f"range-kvm: the build or {what} failed (exit {done.returncode})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
