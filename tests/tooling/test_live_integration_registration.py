#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MESON_OPTIONS = REPO_ROOT / "meson.options"
TESTS_MESON = REPO_ROOT / "tests" / "meson.build"
LIVE_TEST = REPO_ROOT / "tests" / "integration" / "test_live_synapse_federation.cpp"


class LiveIntegrationRegistrationTests(unittest.TestCase):
    def test_live_tests_are_opt_in_not_part_of_default_integration_target(self) -> None:
        # GIVEN the Meson test registration files.
        self.assertTrue(MESON_OPTIONS.is_file(), "meson.options is missing")
        self.assertTrue(TESTS_MESON.is_file(), "tests/meson.build is missing")
        options = MESON_OPTIONS.read_text(encoding="utf-8")
        meson = TESTS_MESON.read_text(encoding="utf-8")

        # WHEN live federation tests are registered.
        # THEN they are gated behind a dedicated false-by-default Meson option
        # and excluded from the default integration test executable.
        self.assertIn("option('build_live_tests', type: 'boolean', value: false", options)
        self.assertIn("if get_option('build_live_tests')", meson)
        self.assertIn("live_integration_tests = executable(", meson)
        self.assertIn("'integration/test_live_synapse_federation.cpp'", meson)

        integration_block_match = re.search(
            r"integration_tests = executable\((?P<body>.*?)\n\s*\)\n(?:\s*(?:#.*)?\n)*\s*test\('integration-tests', integration_tests[^\)]*\)",
            meson,
            re.DOTALL,
        )
        self.assertIsNotNone(integration_block_match, "default integration test target is missing")
        integration_block = integration_block_match.group("body")
        self.assertNotIn("'integration/test_live_synapse_federation.cpp'", integration_block)

    def test_live_address_pins_are_derived_from_sockaddr_payloads(self) -> None:
        # GIVEN the live federation integration test helper.
        self.assertTrue(LIVE_TEST.is_file(), "live federation integration test is missing")
        source = LIVE_TEST.read_text(encoding="utf-8")

        # WHEN host resolution is converted into pinned addresses.
        # THEN the helper uses the sockaddr family-specific address payloads
        # instead of passing the sockaddr wrapper itself to inet_ntop.
        self.assertIn("sockaddr_in const*", source)
        self.assertIn("sockaddr_in6 const*", source)
        self.assertIn("sin_addr", source)
        self.assertIn("sin6_addr", source)
        self.assertNotIn("inet_ntop(entry->ai_family, entry->ai_addr,", source)


if __name__ == "__main__":
    unittest.main()
