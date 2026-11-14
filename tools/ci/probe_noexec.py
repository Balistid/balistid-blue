"""Root probe for T18 on a real systemd (probe.yml): every unit in deploy/ but the runner's runs as a transient
system unit with its own mount sandbox, and tries to execute a copied binary from each place it can write: /tmp,
/var/tmp, /dev/shm and every writable mount test_units_noexec.py derives. Any result but EXEC_DENIED fails.
Two controls made from the relay unit, its state directory listed only through its parent and /var/tmp left out,
must print EXEC_OK there, so a probe that cannot see an executable mount fails as well.

Only the mount settings are copied; ExecPaths becomes /usr so the probe's shell runs, and the unit runs as root,
which noexec binds as much as any uid. Needs systemd 258 or later (PrivateTmp=disconnected, test_units_noexec.py).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))

from test_runner_deploy import parse_unit  # noqa: E402
from test_units_noexec import EXECUTING, units, writable_mounts  # noqa: E402

SERVICE_KEYS = ("PrivateTmp", "ProtectSystem", "ProtectHome", "PrivateDevices", "DynamicUser", "NoExecPaths",
                "StateDirectory", "RuntimeDirectory", "CacheDirectory", "LogsDirectory", "ReadWritePaths",
                "BindPaths", "TemporaryFileSystem")
UNIT_KEYS = ("DefaultDependencies", "After", "RequiresMountsFor", "WantsMountsFor")
ALWAYS = ("/tmp", "/var/tmp", "/dev/shm")
# Runs inside the unit: copy a binary into each directory, run it, say which happened, remove it.
SCRIPT = """for d; do
  f="$d/.balistid-probe.$$"
  if ! cp /usr/bin/true "$f" 2>/dev/null || ! chmod 0755 "$f"; then echo "$d WRITE_FAILED"; continue; fi
  if "$f" 2>/dev/null; then echo "$d EXEC_OK"; else echo "$d EXEC_DENIED"; fi
  rm -f "$f"
done"""
MIN_SYSTEMD = 258


def run_args(text: str) -> tuple[list[str], list[str]]:
    """systemd-run's arguments for one unit's mount sandbox, and the directories to probe in it."""
    sections = parse_unit(text)
    args = ["systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--service-type=exec", "-p", "ExecPaths=/usr"]
    for section, keys in (("Unit", UNIT_KEYS), ("Service", SERVICE_KEYS)):
        for key in keys:
            args += [a for value in sections.get(section, {}).get(key, []) for a in ("-p", f"{key}={value}")]
    dirs = sorted(set(ALWAYS) | writable_mounts(sections.get("Service", {})))
    return args + ["/bin/sh", "-c", SCRIPT, "sh", *dirs], dirs


def probe(text: str) -> dict[str, str]:
    args, dirs = run_args(text)
    out = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    found = dict(line.rsplit(" ", 1) for line in out.stdout.splitlines() if " " in line)
    return {d: found.get(d, f"NO_RESULT rc={out.returncode} {out.stderr.strip()[:200]}") for d in dirs}


def systemd_version() -> int:
    out = subprocess.run(["systemctl", "--version"], capture_output=True, text=True, check=True).stdout
    return int(re.match(r"systemd (\d+)", out).group(1))


def main() -> int:
    version = systemd_version()
    print(f"systemd {version}")
    if version < MIN_SYSTEMD:
        print(f"FAIL systemd {version} is older than {MIN_SYSTEMD}")
        return 1
    failed = False
    for name, text in units().items():
        if name in EXECUTING:
            continue
        for d, result in probe(text).items():
            print(f"{'ok  ' if result == 'EXEC_DENIED' else 'FAIL'} {name} {d} {result}")
            failed |= result != "EXEC_DENIED"
    relay = units()["balistid-relay.service"]
    line = next(v for v in parse_unit(relay)["Service"]["NoExecPaths"])
    for label, changed, d in (
        ("parent only", relay.replace(f"NoExecPaths={line}", f"NoExecPaths={line.replace('/var/lib/balistid/relay', '/var/lib/balistid')}"), "/var/lib/balistid/relay"),
        ("no /var/tmp", relay.replace(f"NoExecPaths={line}", f"NoExecPaths={line.replace(' /var/tmp', '')}"), "/var/tmp"),
    ):
        result = probe(changed).get(d)
        print(f"{'ok  ' if result == 'EXEC_OK' else 'FAIL'} control {label}: {d} {result}")
        failed |= result != "EXEC_OK"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
