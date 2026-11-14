"""Root probe for T18 on a real systemd (probe.yml): every unit in deploy/ but the runner's runs as a transient
system unit with its own mount settings, and inside it the probe fails on
- any mount in /proc/self/mountinfo, other than a kernel pseudo filesystem, that is not noexec while its root is
  writable by the unit's uid or groups by its mode, read-only mount or not (another unit of the uid may write it),
  whatever the static model in test_units_noexec.py knows about;
- any place the model says the unit can write (/tmp, a private /var/tmp, /dev/shm, its writable mounts) where a
  copied binary runs, cannot be written, or fails to execute for another reason than EACCES.
Controls made from the relay, auditstat and the judge, each with one hole put back, must be caught, so a probe
that cannot see a hole fails as well.

ExecPaths gains /usr so the probe's python runs; the unit's own ExecPaths keep a "-" because its binary is not
installed here. The unit runs as its own User, Group and SupplementaryGroups, which probe.yml creates from
deploy/*/sysusers.conf. Needs systemd 258 or later.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))

from test_runner_deploy import parse_unit  # noqa: E402
from test_units_noexec import EXECUTING, private_var_tmp, read_only_mounts, units, writable_mounts  # noqa: E402

SERVICE_KEYS = ("User", "Group", "SupplementaryGroups", "PrivateTmp", "ProtectSystem", "ProtectHome", "PrivateDevices", "PrivateIPC", "DynamicUser",
                "NoExecPaths", "ExecPaths", "StateDirectory", "RuntimeDirectory", "CacheDirectory", "LogsDirectory",
                "ReadWritePaths", "ReadOnlyPaths", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem")
UNIT_KEYS = ("DefaultDependencies", "After", "RequiresMountsFor", "WantsMountsFor")
MIN_SYSTEMD = 258
# Runs inside the unit: argv[1:] are the places to try. One JSON finding per line, then {"done": true}.
INSIDE = r"""
import errno, json, os, shutil, subprocess, sys
PSEUDO = {"proc", "sysfs", "cgroup", "cgroup2", "securityfs", "bpf", "debugfs", "tracefs", "pstore", "configfs",
          "fusectl", "efivarfs", "binfmt_misc", "hugetlbfs", "mqueue", "devpts", "autofs", "nsfs", "ramfs"}
groups = set(os.getgroups()) | {os.getgid()}
def writable(p):
    st = os.stat(p)
    return bool(st.st_mode & 0o002 or (st.st_uid == os.getuid() and st.st_mode & 0o200)
                or (st.st_gid in groups and st.st_mode & 0o020))
for line in open("/proc/self/mountinfo"):
    left, _, right = line.partition(" - ")
    point, opts, fstype = left.split()[4], left.split()[5].split(","), right.split()[0]
    point = point.encode().decode("unicode_escape")
    if fstype in PSEUDO or "noexec" in opts:
        continue
    try:
        hole = writable(point)
    except OSError:
        continue
    if hole:
        print(json.dumps({"mount": point, "fstype": fstype, "opts": opts}))
for d in sys.argv[1:]:
    f = os.path.join(d, ".balistid-probe.%d" % os.getpid())
    try:
        shutil.copy("/usr/bin/true", f)
        os.chmod(f, 0o755)
    except OSError as e:
        print(json.dumps({"dir": d, "result": "WRITE_FAILED " + e.strerror}))
        continue
    try:
        subprocess.run([f], check=True)
        result = "EXEC_OK"
    except PermissionError as e:
        result = "EXEC_DENIED" if e.errno == errno.EACCES else "OTHER " + e.strerror
    except (OSError, subprocess.CalledProcessError) as e:
        result = "OTHER " + str(e)
    os.unlink(f)
    if result != "EXEC_DENIED":
        print(json.dumps({"dir": d, "result": result}))
print(json.dumps({"done": True}))
"""


def run_args(text: str) -> tuple[list[str], list[str]]:
    """systemd-run's arguments for one unit's mount sandbox, and the places the model says to try in it."""
    sections = parse_unit(text)
    service = sections.get("Service", {})
    args = ["systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--service-type=exec", "-p", "ExecPaths=/usr"]
    for section, keys in (("Unit", UNIT_KEYS), ("Service", SERVICE_KEYS)):
        for key in keys:
            for value in sections.get(section, {}).get(key, []):
                if key == "ExecPaths":
                    value = " ".join(w if w.startswith("-") else f"-{w}" for w in value.split())
                args += ["-p", f"{key}={value}"]
    tmp = {"/tmp", "/dev/shm"} | ({"/var/tmp"} if private_var_tmp(sections) else set())
    dirs = sorted(tmp | writable_mounts(service))
    return args + ["/usr/bin/python3", "-I", "-c", INSIDE, *dirs], dirs


def findings(text: str) -> list[dict]:
    """What the probe finds inside the unit; an empty list only when it ran to the end and found nothing."""
    out = subprocess.run(run_args(text)[0], capture_output=True, text=True, timeout=60, check=False)
    lines = [json.loads(line) for line in out.stdout.splitlines() if line.startswith("{")]
    if {"done": True} not in lines:
        return [{"no_result": out.returncode, "stderr": out.stderr.strip()[-300:]}]
    return [x for x in lines if x != {"done": True}]


def systemd_version() -> int:
    out = subprocess.run(["systemctl", "--version"], capture_output=True, text=True, check=True).stdout
    return int(re.match(r"systemd (\d+)", out).group(1))


def controls() -> list[tuple[str, str, str]]:
    """(label, unit text with one hole put back, the path the probe must name)."""
    u = units()
    relay, auditstat, judge = u["balistid-relay.service"], u["balistid-auditstat.service"], u["balistid-judge.service"]
    r = "NoExecPaths=/ /var/lib/balistid/relay /tmp /var/tmp -/dev/shm"
    out = [
        ("state dir via its parent", relay.replace(r, r.replace("/var/lib/balistid/relay", "/var/lib/balistid")),
         "/var/lib/balistid/relay"),
        ("private /var/tmp", relay.replace(r, r.replace(" /var/tmp", "")), "/var/tmp"),
        ("private /tmp", relay.replace(r, r.replace(" /tmp", "")), "/tmp"),
        ("/dev/shm", relay.replace(r, r.replace(" -/dev/shm", "")), "/dev/shm"),
        ("exec path in the state dir", relay.replace("ExecPaths=/usr/local/lib/balistid/balistid-relay",
                                                     "ExecPaths=/var/lib/balistid/relay"), "/var/lib/balistid/relay"),
        ("runtime dir", auditstat.replace(" /run/balistid-auditstat", ""), "/run/balistid-auditstat"),
        ("read-only store", judge.replace(" /var/lib/balistid/collector /tmp", " /tmp"), "/var/lib/balistid/collector"),
    ]
    for label, text, _ in out:
        if text in (relay, auditstat, judge):
            raise SystemExit(f"FAIL control {label}: the unit text did not change")
    return out


def main() -> int:
    # A read-only mount is another unit's directory of the same uid on the host (the judge reads the collector's
    # store), so it is made here owned by that uid, as there.
    for text in units().values():
        service = parse_unit(text).get("Service", {})
        for p in read_only_mounts(service):
            Path(p).mkdir(parents=True, exist_ok=True)
            shutil.chown(p, service["User"][-1], service["Group"][-1])
    version = systemd_version()
    print(f"systemd {version}")
    if version < MIN_SYSTEMD:
        print(f"FAIL systemd {version} is older than {MIN_SYSTEMD}")
        return 1
    failed = False
    for name, text in units().items():
        if name in EXECUTING:
            continue
        found = findings(text)
        print(f"{'FAIL' if found else 'ok  '} {name}")
        for f in found:
            print(f"     {json.dumps(f)}")
        failed |= bool(found)
    for label, text, want in controls():
        found = findings(text)
        caught = any(want in (f.get("mount"), f.get("dir")) for f in found)
        print(f"{'ok  ' if caught else 'FAIL'} control {label}: {want} {json.dumps(found)}")
        failed |= not caught
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
