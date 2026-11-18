#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FREEBSD_RC_SCRIPT = REPO_ROOT / "packaging" / "rc.d" / "merovingian"

# FreeBSD's `default` login class: 64 KiB, one 4 KiB page per secret, so 16 secrets.
DEFAULT_CLASS_LOCKED_BYTES = 64 * 1024
UNIT_BYTES = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def locked_memory_bytes(limits_arguments: str) -> int | None:
    """The `-l` (memorylocked) value of a limits(1) argument string, in bytes; None when it sets none."""
    match = re.search(r"(?:^|\s)-l\s+(\d+)([bkmgt]?)(?:\s|$)", limits_arguments)
    if match is None:
        return None
    return int(match.group(1)) * UNIT_BYTES[match.group(2) or "b"]


class FreeBsdLockedMemoryTests(unittest.TestCase):
    def test_the_freebsd_service_sets_its_own_locked_memory_limit(self) -> None:
        # GIVEN the rc.d script the FreeBSD package installs.
        script = FREEBSD_RC_SCRIPT.read_text(encoding="utf-8")

        # WHEN rc.subr reads the limits(1) arguments the script defaults to.
        default = re.search(r'^: "\$\{merovingian_limits:=([^}]*)\}"$', script, flags=re.MULTILINE)

        # THEN the script names a locked-memory limit itself, rather than taking the login class's.
        self.assertIsNotNone(default, "the rc.d script sets no default merovingian_limits")
        assert default is not None
        locked = locked_memory_bytes(default.group(1))
        self.assertIsNotNone(locked, "merovingian_limits sets no memorylocked (-l) value")
        assert locked is not None

        # AND it is far above the default class's 64 KiB, which holds only 16 secrets.
        self.assertGreaterEqual(locked, 1024 * DEFAULT_CLASS_LOCKED_BYTES)

    def test_the_default_is_set_after_rc_conf_is_read_so_an_operator_can_override_it(self) -> None:
        # GIVEN the rc.d script.
        script = FREEBSD_RC_SCRIPT.read_text(encoding="utf-8")

        # WHEN the order of its lines is read.
        load = script.find('load_rc_config "$name"')
        default = script.find(': "${merovingian_limits:=')
        run = script.find('run_rc_command "$1"')

        # THEN rc.conf is loaded first, the default fills only an unset value, and the command runs last.
        self.assertGreaterEqual(load, 0)
        self.assertLess(load, default)
        self.assertLess(default, run)

    def test_the_limit_reader_understands_limits_suffixes(self) -> None:
        # GIVEN limits(1) argument strings. WHEN their -l value is read. THEN the suffix scales it.
        self.assertEqual(locked_memory_bytes("-l 128m"), 128 * 1024**2)
        self.assertEqual(locked_memory_bytes("-n 4096 -l 64k"), 64 * 1024)
        self.assertEqual(locked_memory_bytes("-l 4096"), 4096)
        self.assertIsNone(locked_memory_bytes("-n 4096"))


if __name__ == "__main__":
    unittest.main()
