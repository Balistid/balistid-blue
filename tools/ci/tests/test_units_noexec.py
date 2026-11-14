"""Tests for the no-exec rule across deploy/ (T18): every writable mount systemd adds for a unit is listed in
NoExecPaths by its own path, because the remount of / skips the unit's own mounts and everything under them
(namespace.c, apply_mounts): a private /tmp, a private /var/tmp, State/Runtime/Cache/Logs directories, writable
paths and binds. A parent path in the list does not cover them (probe 2026-11-14: a StateDirectory listed only
through its parent and an unlisted RuntimeDirectory both executed; listed exactly, neither did).

On systemd 258 and later, PrivateTmp=disconnected with DefaultDependencies=no and no mount dependency on /var
leaves the host's /var/tmp in place (systemd.exec(5), table "Summary for PrivateTmp=disconnected"); that one is
under the noexec of /.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from test_runner_deploy import parse_unit

REPO = Path(__file__).resolve().parents[3]
OFF = {"", "no", "false", "off", "0"}
# The runner executes bwrap and QEMU and has no NoExecPaths at all (ADR 0011).
EXECUTING = {"balistid-runner-build.service", "balistid-runner-tick.service"}
# Early-boot units: no private /var/tmp, see above.
HOST_VAR_TMP = {"balistid-collector.service", "balistid-ledger.service", "balistid-net.service"}
DIRECTORIES = {"StateDirectory": "/var/lib", "RuntimeDirectory": "/run", "CacheDirectory": "/var/cache",
               "LogsDirectory": "/var/log"}


def last(section: dict[str, list[str]], key: str) -> str:
    return (section.get(key) or [""])[-1].strip().lower()


def words(section: dict[str, list[str]], key: str) -> list[str]:
    """All values of key in order, an empty assignment resetting the list as systemd does."""
    out: list[str] = []
    for value in section.get(key, []):
        out = [] if not value.strip() else out + value.split()
    return out


def path(word: str) -> str:
    return word.lstrip("-+").rstrip("/") or "/"


def private_tmp(sections: dict[str, dict[str, list[str]]]) -> str:
    service = sections.get("Service", {})
    value = last(service, "PrivateTmp")
    if value in OFF and last(service, "DynamicUser") not in OFF:
        return "disconnected"
    return "" if value in OFF else value


def private_var_tmp(sections: dict[str, dict[str, list[str]]]) -> bool:
    unit, service = sections.get("Unit", {}), sections.get("Service", {})
    mode = private_tmp(sections)
    if mode != "disconnected":
        return mode != ""
    waits = [p for k in ("RequiresMountsFor", "WantsMountsFor") for p in words(unit, k)]
    var_mount = any(p.startswith("/var") for p in waits) or "var.mount" in words(unit, "After")
    rooted = any(k in service for k in ("RootDirectory", "RootImage", "RootMStack"))
    return last(unit, "DefaultDependencies") != "no" or var_mount or rooted


def writable_mounts(service: dict[str, list[str]]) -> set[str]:
    mounts = {f"{base}/{w.split(':')[0]}" for key, base in DIRECTORIES.items() for w in words(service, key)}
    mounts |= {path(w) for w in words(service, "ReadWritePaths")}
    mounts |= {path(w.split(":")[1] if ":" in w else w) for w in words(service, "BindPaths")}
    mounts |= {path(w.split(":")[0]) for w in words(service, "TemporaryFileSystem")}
    return mounts


def noexec_problems(text: str) -> list[str]:
    sections = parse_unit(text)
    service = sections.get("Service", {})
    tmp = ({"/", "/tmp"} | ({"/var/tmp"} if private_var_tmp(sections) else set())) if private_tmp(sections) else set()
    want = tmp | writable_mounts(service)
    listed = {path(w) for w in words(service, "NoExecPaths")}
    return [f"NoExecPaths lacks {p}" for p in sorted(want - listed)]


def units() -> dict[str, str]:
    paths = sorted(REPO.glob("deploy/*/*.service"))
    assert len({p.name for p in paths}) == len(paths), "two units share a file name"
    return {p.name: p.read_text() for p in paths}


class UnitsNoExecTest(unittest.TestCase):
    def test_every_unit_keeps_its_writable_mounts_noexec(self):
        checked = {name: text for name, text in units().items() if name not in EXECUTING}
        self.assertGreater(len(checked), len(HOST_VAR_TMP))
        for name, text in checked.items():
            with self.subTest(unit=name):
                self.assertTrue(private_tmp(parse_unit(text)))
                self.assertEqual(noexec_problems(text), [])

    def test_only_the_early_boot_units_keep_the_hosts_var_tmp(self):
        host = {name for name, text in units().items() if private_tmp(parse_unit(text)) and not private_var_tmp(parse_unit(text))}
        self.assertEqual(host, HOST_VAR_TMP)

    def test_the_executing_units_are_the_ones_without_noexec_paths(self):
        bare = {name for name, text in units().items() if "NoExecPaths" not in parse_unit(text).get("Service", {})}
        self.assertEqual(bare, EXECUTING)

    def test_a_unit_missing_a_private_mount_fails(self):
        relay = units()["balistid-relay.service"]
        line = "NoExecPaths=/ /var/lib/balistid/relay /tmp /var/tmp -/dev/shm"
        self.assertIn(line, relay)
        for new, problem in (
            (line.replace(" /var/tmp", ""), "NoExecPaths lacks /var/tmp"),
            (line.replace(" /tmp /var/tmp", " /var/tmp"), "NoExecPaths lacks /tmp"),
            (line.replace("=/ ", "="), "NoExecPaths lacks /"),
            (line.replace("/var/lib/balistid/relay", "/var/lib/balistid"), "NoExecPaths lacks /var/lib/balistid/relay"),
        ):
            with self.subTest(new=new):
                self.assertEqual(noexec_problems(relay.replace(line, new)), [problem])
        reset = noexec_problems(relay.replace(line, line + "\nNoExecPaths="))
        self.assertEqual(reset, [f"NoExecPaths lacks {p}" for p in ("/", "/tmp", "/var/lib/balistid/relay", "/var/tmp")])
        for mode in ("yes", "true"):
            text = relay.replace(line, line.replace(" /var/tmp", "")).replace("PrivateTmp=disconnected", f"PrivateTmp={mode}")
            self.assertEqual(noexec_problems(text), ["NoExecPaths lacks /var/tmp"])

    def test_a_unit_without_a_private_tmp_still_lists_its_directories(self):
        auditstat = units()["balistid-auditstat.service"]
        text = auditstat.replace("PrivateTmp=disconnected", "PrivateTmp=no").replace(" /run/balistid-auditstat", "")
        self.assertEqual(noexec_problems(text), ["NoExecPaths lacks /run/balistid-auditstat"])

    def test_every_kind_of_writable_mount_must_be_listed(self):
        auditstat = units()["balistid-auditstat.service"]
        line = "NoExecPaths=/ /run/balistid-auditstat /tmp /var/tmp -/dev/shm"
        self.assertIn(line, auditstat)
        self.assertEqual(noexec_problems(auditstat.replace(line, line.replace(" /run/balistid-auditstat", ""))),
                         ["NoExecPaths lacks /run/balistid-auditstat"])
        for added, mount in (
            ("StateDirectory=balistid/a", "/var/lib/balistid/a"),
            ("CacheDirectory=b", "/var/cache/b"),
            ("LogsDirectory=c:d", "/var/log/c"),
            ("ReadWritePaths=-/srv/e/", "/srv/e"),
            ("BindPaths=/srv/f:/srv/g", "/srv/g"),
            ("TemporaryFileSystem=/srv/h:mode=0700", "/srv/h"),
        ):
            with self.subTest(added=added):
                self.assertEqual(noexec_problems(auditstat.replace(line, f"{line}\n{added}")), [f"NoExecPaths lacks {mount}"])

    def test_an_early_boot_unit_that_waits_for_var_needs_var_tmp(self):
        ledger = units()["balistid-ledger.service"]
        self.assertEqual(noexec_problems(ledger), [])
        for old, new in (
            ("DefaultDependencies=no\n", ""),
            ("DefaultDependencies=no", "DefaultDependencies=no\nRequiresMountsFor=/var"),
            ("DefaultDependencies=no", "DefaultDependencies=no\nWantsMountsFor=/var/tmp"),
            ("DefaultDependencies=no", "DefaultDependencies=no\nAfter=var.mount"),
        ):
            with self.subTest(new=new):
                self.assertIn(old, ledger)
                self.assertEqual(noexec_problems(ledger.replace(old, new)), ["NoExecPaths lacks /var/tmp"])


if __name__ == "__main__":
    unittest.main()
