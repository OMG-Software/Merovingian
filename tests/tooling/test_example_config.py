#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "merovingian.conf.example"


class ExampleConfigTests(unittest.TestCase):
    def test_example_config_documents_each_operator_section(self) -> None:
        # GIVEN the checked-in operator starter config.
        self.assertTrue(EXAMPLE_CONFIG.is_file(), "example config is missing")
        config = EXAMPLE_CONFIG.read_text(encoding="utf-8")

        # WHEN operators read the file before editing values.
        # THEN each major section explains intent, safety defaults, or secret handling.
        for expected_comment in (
            "# Server identity",
            "# Listener exposure",
            "# Database connection",
            "# Public registration",
            "# Room encryption policy",
            "# Federation policy",
            "# Media safety policy",
            "# Logging redaction",
        ):
            self.assertIn(expected_comment, config)

        self.assertIn("# Keep database credentials out of this file.", config)
        self.assertIn("# Keep TLS disabled only on loopback binds.", config)


if __name__ == "__main__":
    unittest.main()
