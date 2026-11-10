#!/usr/bin/env python3
"""The systemd unit keeps its resource ceilings and a system call filter that never
narrows what the server's own seccomp filter allows (ADR-0499).

A SystemCallFilter narrower than the processes' own filters would make the server's
seccomp installation, or a later call, fail under systemd and nowhere else.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT = REPO_ROOT / "packaging" / "systemd" / "merovingian.service"
SECCOMP = REPO_ROOT / "src" / "platform" / "SeccompHardening.cpp"

# What the hardening installs itself with, which its own allow-lists need not name.
INSTALL_TIME_CALLS = {
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "prctl",
    "setrlimit",
    "prlimit64",
    "capset",
}


def unit_directives() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in UNIT.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result.setdefault(key, []).append(value)
    return result


def filter_names() -> set[str]:
    names: set[str] = set()
    for value in unit_directives().get("SystemCallFilter", []):
        names.update(value.split())
    return names


class SystemdUnitTest(unittest.TestCase):
    def test_resource_ceilings_are_set(self) -> None:
        directives = unit_directives()
        self.assertEqual(directives["LimitNOFILE"], ["65536"])
        self.assertEqual(directives["TasksMax"], ["4096"])
        self.assertEqual(directives["ProtectProc"], ["invisible"])

    def test_stop_timeout_exceeds_the_worker_shutdown_bound(self) -> None:
        # The supervisor waits request_timeout_seconds (default 120) twice for a stuck
        # federation worker before SIGKILL: 240 s. systemd must not kill sooner.
        (value,) = unit_directives()["TimeoutStopSec"]
        self.assertTrue(value.endswith("s"))
        self.assertGreater(int(value[:-1]), 2 * 120)

    def test_no_watchdog_without_sd_notify(self) -> None:
        # The server never calls sd_notify, so WatchdogSec would kill a healthy server.
        self.assertNotIn("WatchdogSec", unit_directives())
        sources = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in (REPO_ROOT / "src").rglob("*.cpp")
        )
        self.assertNotIn("sd_notify", sources)

    def test_system_call_filter_is_never_narrower_than_the_servers_own(self) -> None:
        names = filter_names()
        self.assertIn("@system-service", names)
        own = set(re.findall(r"__NR_([a-z0-9_]+)", SECCOMP.read_text(encoding="utf-8")))
        self.assertGreater(len(own), 100)
        missing = sorted((own | INSTALL_TIME_CALLS) - names)
        self.assertEqual(missing, [], f"unit SystemCallFilter lacks calls the server allows: {missing}")

    def test_system_call_filter_has_no_deny_list_entries(self) -> None:
        # A leading "~" would turn the list into a deny list and invert it.
        for name in filter_names():
            self.assertFalse(name.startswith("~"), name)


if __name__ == "__main__":
    unittest.main()
