#!/usr/bin/env python3
"""The minimum-cost password hash reaches the three test binaries and nothing else (ADR-0510)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_BUILD = REPO_ROOT / "tests" / "meson.build"
WRAP = "--wrap=crypto_pwhash_str"
OVERRIDDEN = {"merovingian-unit-tests", "merovingian-conformance-tests", "merovingian-integration-tests"}


def executables() -> dict[str, str]:
    """Each test executable's name and its meson definition, up to the next test() or executable()."""
    text = TESTS_BUILD.read_text(encoding="utf-8")
    found = {}
    for match in re.finditer(r"executable\(\s*'([^']+)'", text):
        following = re.search(r"^\s*(?:test\(|[a-z_]+ = executable\()", text[match.end() :], flags=re.MULTILINE)
        found[match[1]] = text[match.end() : match.end() + following.start()] if following else text[match.end() :]
    return found


class TheOverride(unittest.TestCase):
    def test_given_the_three_large_binaries_when_they_link_then_they_wrap_the_hash_and_carry_its_definition(self) -> None:
        all_executables = executables()
        for name in OVERRIDDEN:
            with self.subTest(executable=name):
                self.assertIn("link_args: password_hash_cost_link_args", all_executables[name])
                self.assertIn("'support/RealPasswordHashCost.cpp'", all_executables[name])

    def test_given_any_other_test_binary_when_it_links_then_it_keeps_the_real_hash(self) -> None:
        for name, definition in executables().items():
            if name in OVERRIDDEN:
                continue
            with self.subTest(executable=name):
                self.assertNotIn("password_hash_cost", definition)

    def test_given_the_binary_that_pins_the_production_cost_when_it_is_defined_then_a_test_runs_it(self) -> None:
        all_executables = executables()
        self.assertIn("merovingian-password-cost-tests", all_executables)
        self.assertIn("password_cost/test_production_password_cost.cpp", all_executables["merovingian-password-cost-tests"])
        self.assertRegex(TESTS_BUILD.read_text(encoding="utf-8"), r"test\('password-cost-tests',")

    def test_given_the_shipped_programs_when_they_are_built_then_nothing_outside_tests_names_the_override(self) -> None:
        builds = [REPO_ROOT / "meson.build", *(REPO_ROOT / "src").rglob("meson.build")]
        for build in builds:
            with self.subTest(build=str(build.relative_to(REPO_ROOT))):
                text = build.read_text(encoding="utf-8")
                self.assertNotIn(WRAP, text)
                self.assertNotIn("password_hash_cost", text)
        self.assertEqual(TESTS_BUILD.read_text(encoding="utf-8").count(WRAP), 1, "defined once, in tests/meson.build")


if __name__ == "__main__":
    unittest.main()
