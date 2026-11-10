#!/usr/bin/env python3
"""Behaviour of scripts/check-unit-test-isolation.sh, the unit test isolation gate (ADR-0593).

The gate must reject a unit test file that names a function which builds a
homeserver runtime or drives the client-server stack, report the file and line,
pass a tree without them, and fail closed when it cannot run: an empty
tests/unit/ is an error, not a pass.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-unit-test-isolation.sh"

CLEAN = 'SCENARIO("x") { GIVEN("a") { WHEN("b") { THEN("c") { REQUIRE(parse("1") == 1); } } } }\n'
FORBIDDEN = (
    "start_runtime",
    "start_client_server",
    "wire_federation_callbacks",
    "handle_client_server_request",
    "handle_client_server_http_request",
    "run_client_server_flow",
)


class CheckUnitTestIsolationTests(unittest.TestCase):
    def run_gate(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("POSIX sh is not available")
        root = Path(tempfile.mkdtemp(prefix="isolation-gate-"))
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

    def test_a_tree_without_forbidden_calls_passes(self) -> None:
        # GIVEN unit files that name only single-module functions, one with a longer identifier
        files = {"test_a.cpp": CLEAN, "test_b.cpp": "auto start_runtime_options = 1;\n"}

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN it passes silently
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_each_forbidden_function_is_reported_with_its_file_and_line(self) -> None:
        for name in FORBIDDEN:
            with self.subTest(function=name):
                # GIVEN a single unit file whose second line calls the function
                files = {"test_bad.cpp": CLEAN + f"auto started = {name}(config);\n"}

                # WHEN the gate runs
                result = self.run_gate(files)

                # THEN it fails and names the file and the line
                self.assertEqual(result.returncode, 1)
                self.assertIn("test_bad.cpp:2:", result.stderr)
                self.assertIn("ADR-0593", result.stderr)

    def test_a_forbidden_name_in_a_header_is_reported(self) -> None:
        # GIVEN a header under tests/unit/ beside a clean source
        files = {"test_a.cpp": CLEAN, "helpers.hpp": "inline auto f() { return start_client_server({}); }\n"}

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN the header is reported
        self.assertEqual(result.returncode, 1)
        self.assertIn("helpers.hpp:1:", result.stderr)

    def test_an_empty_unit_directory_fails_closed(self) -> None:
        # GIVEN no unit test sources at all
        files: dict[str, str] = {}

        # WHEN the gate runs
        result = self.run_gate(files)

        # THEN it refuses to pass
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to pass", result.stderr)

    def test_the_repository_passes(self) -> None:
        # GIVEN this checkout
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("POSIX sh is not available")

        # WHEN the gate runs over it
        result = subprocess.run([shell, str(SCRIPT), str(REPO_ROOT)], check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # THEN no unit test builds a runtime
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
