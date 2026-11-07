#!/usr/bin/env python3
"""A test binary writing its CI skip report still lets a test capture std::cout (ADR-0546).

CI sets MEROVINGIAN_CATCH_REPORT_DIR, and each Catch2 binary then adds an XML reporter. Catch2's stock XML reporter
redirects stdout around every test, which replaced the buffer the logger tests install with std::cout.rdbuf() and
failed them on every Linux and BSD job. Run with the unit-test binary's path as the only argument.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path

REPORT_DIRECTORY_VARIABLE = "MEROVINGIAN_CATCH_REPORT_DIR"
# The scenarios that read the console through a swapped std::cout buffer.
CONSOLE_CAPTURING_TAG = "[log_controls]"
UNIT_TEST_BINARY: Path | None = None


class TheReportedRun(unittest.TestCase):
    def test_given_a_report_directory_when_console_capturing_tests_run_then_they_pass_and_one_report_is_written(
        self,
    ) -> None:
        assert UNIT_TEST_BINARY is not None
        with tempfile.TemporaryDirectory() as directory:
            environment = {**os.environ, REPORT_DIRECTORY_VARIABLE: directory}
            completed = subprocess.run(
                [str(UNIT_TEST_BINARY), CONSOLE_CAPTURING_TAG],
                env=environment,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout[-4000:] + completed.stderr[-4000:])
            reports = sorted(Path(directory).glob("*.xml"))
            self.assertEqual(len(reports), 1, [report.name for report in reports])
            root = ElementTree.parse(reports[0]).getroot()
            totals = root.find("OverallResultsCases")
            self.assertIsNotNone(totals)
            assert totals is not None
            self.assertGreater(int(totals.get("successes", "0")), 0, "the tag must select test cases")
            self.assertEqual(totals.get("failures"), "0")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: test_catch_report_capture.py <merovingian-unit-tests>")
    UNIT_TEST_BINARY = Path(sys.argv.pop(1))
    unittest.main()
