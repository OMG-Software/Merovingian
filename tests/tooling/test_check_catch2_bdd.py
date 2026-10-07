#!/usr/bin/env python3
"""Behaviour of scripts/check-catch2-bdd-tests.sh, the Catch2 BDD shape gate.

The gate must reject a unit test file that uses TEST_CASE, uses comment-only
Given/When/Then markers, or lacks any of SCENARIO/GIVEN/WHEN/THEN, and must
skip tests/unit/test_main.cpp. It runs on every platform's suite, including
slow BSD VMs, so it must not start processes per file.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-catch2-bdd-tests.sh"

GOOD = 'SCENARIO("x") { GIVEN("a") { WHEN("b") { THEN("c") { REQUIRE(true); } } } }\n'


class CheckCatch2BddTests(unittest.TestCase):
    def run_gate(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("POSIX sh is not available")
        root = Path(tempfile.mkdtemp(prefix="bdd-gate-"))
        self.addCleanup(shutil.rmtree, root, True)
        unit = root / "tests" / "unit"
        unit.mkdir(parents=True)
        for name, content in files.items():
            (unit / name).write_text(content, encoding="utf-8")
        return subprocess.run(
            [shell, str(SCRIPT), str(root)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_well_formed_files_pass(self) -> None:
        # GIVEN unit test files that use the BDD macros, and test_main.cpp without them
        files = {"test_a.cpp": GOOD, "test_b.cpp": GOOD, "test_main.cpp": "int main() {}\n"}

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN it passes silently
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_each_violation_is_reported_against_its_file(self) -> None:
        # GIVEN one file per violation next to a well-formed one
        files = {
            "test_good.cpp": GOOD,
            "test_plain.cpp": GOOD + "TEST_CASE(\"x\") {}\n",
            "test_comments.cpp": GOOD + "// Given a thing\n",
            "test_no_then.cpp": 'SCENARIO("x") { GIVEN("a") { WHEN("b") {} } }\n',
            "test_main.cpp": "TEST_CASE without anything else\n",
        }

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN it fails and names exactly the offending files, each with its reason
        self.assertEqual(result.returncode, 1)
        self.assertIn("tests/unit/test_plain.cpp uses TEST_CASE", result.stderr)
        self.assertIn("tests/unit/test_comments.cpp uses comment-only Given/When/Then markers", result.stderr)
        self.assertIn("tests/unit/test_no_then.cpp is missing Catch2 BDD macros", result.stderr)
        self.assertNotIn("test_good.cpp", result.stderr)
        self.assertNotIn("test_main.cpp", result.stderr)

    def test_a_single_file_is_still_attributed_by_name(self) -> None:
        # GIVEN exactly one unit test file, which lacks the BDD macros
        files = {"test_only.cpp": "int x;\n"}

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN the report still names the file
        self.assertEqual(result.returncode, 1)
        self.assertIn("tests/unit/test_only.cpp is missing Catch2 BDD macros", result.stderr)

    def test_the_gate_does_not_start_processes_per_file(self) -> None:
        # GIVEN the gate script
        script = SCRIPT.read_text(encoding="utf-8")

        # WHEN its file loop is inspected
        # THEN no grep runs inside a per-file loop (it timed out on the OpenBSD VM)
        self.assertNotIn('grep -q', script)


if __name__ == "__main__":
    unittest.main()
