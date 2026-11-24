#!/usr/bin/env python3
"""Behaviour of scripts/catch2-failure-report.sh, the CI failure report (ADR-0877).

The report must show every failed test's Catch2 output, however early the test ran and however much passing
output Meson wrote after it, with the runtime log lines removed; skip a passing or skipped (exit 77) test; cap
its size; and every workflow's failure report must use it rather than a tail of the whole log.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "catch2-failure-report.sh"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
LOG_LINE = "2026-11-24 10:00:00.123456 +0000  <{level}>  sync: a runtime line {index}"
CATCH2_FAILURE = """\
-------------------------------------------------------------------------------
Scenario: presence settles after two devices flip
      Given: two devices of one user
       When: both report online then offline
       Then: one presence change is federated
-------------------------------------------------------------------------------
/src/tests/integration/test_presence_flow.cpp:120
...............................................................................

/src/tests/integration/test_presence_flow.cpp:141: FAILED:
  REQUIRE( sent.size() == 1 )
with expansion:
  2 == 1

===============================================================================
test cases: 418 | 417 passed | 1 failed
assertions: 9000 | 8999 passed | 1 failed
"""


def banner(number: int, total: int) -> str:
    title = f" {number}/{total} "
    first = (78 - len(title)) // 2
    return "=" * first + title + "=" * (78 - first - len(title))


def section(number: int, total: int, name: str, result: str, output: str) -> str:
    stdout = "-" * 35 + " output " + "-" * 35
    return (
        f"{banner(number, total)}\n"
        f"test:         {name}\n"
        "start time:   10:00:00\n"
        "duration:     12.34s\n"
        f"result:       {result}\n"
        f"command:      MALLOC_PERTURB_=1 /build/tests/{name}\n"
        f"{stdout}\n{output}"
        f"{'=' * 78}\n\n"
    )


def runtime_lines(count: int) -> str:
    levels = ("INFO", "WARNING", "ERROR", "DEBUG", "CRITICAL")
    return "".join(LOG_LINE.format(level=levels[i % len(levels)], index=i) + "\n" for i in range(count))


@unittest.skipIf(shutil.which("sh") is None or shutil.which("awk") is None, "needs sh and awk")
class TheFailureReport(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.testlog = Path(self.directory.name) / "testlog.txt"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_report(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={**os.environ, **(env or {})},
        )

    def test_given_an_early_failure_followed_by_many_passing_tests_then_its_catch2_case_is_shown(self) -> None:
        # GIVEN integration shard 1 fails first, with its failure among runtime log lines, and 60 smoke tests
        # pass after it with hundreds of lines each, as in the asan-ubsan run whose failure no report showed.
        failing = runtime_lines(500) + CATCH2_FAILURE + runtime_lines(50)
        passing = "".join(
            section(n, 61, f"smoke-{n}", "exit status 0", f"line {n}\n" * 400) for n in range(2, 62)
        )
        self.testlog.write_text(
            "Log of Meson test suite run\n\n"
            + section(1, 61, "integration-tests-shard-1-of-4", "exit status 1", failing)
            + passing
            + "\nSummary of Failures:\n\n 1/61 integration-tests-shard-1-of-4 FAIL\n\nOk: 60\nFail: 1\n",
            encoding="utf-8",
        )

        # WHEN the report is printed
        completed = self.run_report(str(self.testlog))

        # THEN it shows the whole Catch2 case of the failed test and nothing of the runtime log or passing tests
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = completed.stdout
        self.assertIn("FAILED integration-tests-shard-1-of-4  (exit status 1, 12.34s)", report)
        for expected in (
            "Scenario: presence settles after two devices flip",
            "/src/tests/integration/test_presence_flow.cpp:120",
            "/src/tests/integration/test_presence_flow.cpp:141: FAILED:",
            "  REQUIRE( sent.size() == 1 )",
            "with expansion:",
            "  2 == 1",
            "test cases: 418 | 417 passed | 1 failed",
        ):
            self.assertIn(expected, report)
        self.assertNotIn("a runtime line", report)
        self.assertNotIn("smoke-", report)
        self.assertIn("1 failed test(s)", report)

    def test_given_a_skipped_test_and_a_crashed_test_then_only_the_crash_is_reported(self) -> None:
        # GIVEN a test Meson skipped (exit 77) and one killed by a signal
        self.testlog.write_text(
            section(1, 2, "postgresql-flow", "exit status 77", "SKIPPED: no PostgreSQL\n")
            + section(2, 2, "unit-tests", "killed by signal 6 SIGABRT", "==123==ERROR: AddressSanitizer\n"),
            encoding="utf-8",
        )

        # WHEN the report is printed
        report = self.run_report(str(self.testlog)).stdout

        # THEN the crash and its sanitizer output are shown and the skip is not
        self.assertIn("FAILED unit-tests  (killed by signal 6 SIGABRT", report)
        self.assertIn("==123==ERROR: AddressSanitizer", report)
        self.assertNotIn("postgresql-flow", report)

    def test_given_a_long_failed_output_then_its_head_and_tail_are_kept_within_the_caps(self) -> None:
        # GIVEN a failed test with 1000 lines of its own output, and a second failed test after it
        output = "".join(f"catch2 line {i}\n" for i in range(1000))
        self.testlog.write_text(
            section(1, 2, "first", "exit status 1", output) + section(2, 2, "second", "exit status 1", "x\n"),
            encoding="utf-8",
        )

        # WHEN the report runs with 10 head lines, 5 tail lines and a 20-line total
        report = self.run_report(
            str(self.testlog),
            env={
                "CATCH2_REPORT_HEAD_LINES": "10",
                "CATCH2_REPORT_TAIL_LINES": "5",
                "CATCH2_REPORT_TOTAL_LINES": "20",
            },
        ).stdout

        # THEN the first test shows its first and last lines with the gap counted, and the second is counted
        # but not shown, because the report had reached its cap
        self.assertIn("catch2 line 8\n", report)
        self.assertIn("catch2 line 999\n", report)
        self.assertNotIn("catch2 line 500\n", report)
        self.assertIn("lines omitted", report)
        self.assertNotIn("FAILED second", report)
        self.assertIn("2 failed test(s)", report)
        self.assertIn("1 of them not shown", report)

    def test_given_an_exclude_pattern_then_matching_lines_are_dropped(self) -> None:
        # GIVEN a failed test whose output holds NetBSD diagnostic markers
        self.testlog.write_text(
            section(1, 1, "unit-tests", "exit status 1", "[netbsd-diag] fd 3\nFAILED:\n"), encoding="utf-8"
        )

        # WHEN the report drops them
        report = self.run_report("--exclude", r"^\[netbsd-diag\]", str(self.testlog)).stdout

        # THEN only the Catch2 line is left
        self.assertIn("FAILED:", report)
        self.assertNotIn("netbsd-diag", report)

    def test_given_no_log_or_no_failed_test_then_it_says_so_and_succeeds(self) -> None:
        # GIVEN no log, then a log in which every test passed
        missing = self.run_report(str(self.testlog))
        self.testlog.write_text(section(1, 1, "unit-tests", "exit status 0", "ok\n"), encoding="utf-8")
        passed = self.run_report(str(self.testlog))

        # THEN each run says why there is nothing to show, and neither fails the step
        self.assertEqual((missing.returncode, passed.returncode), (0, 0))
        self.assertIn("No test log at", missing.stdout)
        self.assertIn("No failed test in", passed.stdout)

    def test_given_bad_arguments_then_it_refuses(self) -> None:
        self.assertEqual(self.run_report().returncode, 2)
        self.assertEqual(self.run_report("--exclude").returncode, 2)
        self.assertEqual(self.run_report("--bogus", str(self.testlog)).returncode, 2)


class TheWorkflows(unittest.TestCase):
    def test_every_catch2_failure_report_uses_the_script_and_none_tails_the_whole_log(self) -> None:
        # GIVEN every workflow
        reports = 0
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            # WHEN each Catch2 failure report in it is read
            for match in re.finditer(r"Catch2 failure report[^\n]*\n((?:.*\n){0,12})", text):
                reports += 1
                # THEN it runs the script and tails nothing, since a tail drops an early test's failure
                self.assertIn("scripts/catch2-failure-report.sh", match.group(1), workflow.name)
                self.assertNotIn("tail -n", match.group(1), workflow.name)
        self.assertGreaterEqual(reports, 12)

    def test_both_sanitizer_jobs_report_their_failures(self) -> None:
        workflow = (WORKFLOWS / "sanitizers.yml").read_text(encoding="utf-8")
        self.assertIn("sh scripts/catch2-failure-report.sh build/meson-logs/testlog.txt", workflow)
        self.assertIn("sh scripts/catch2-failure-report.sh build-tsan/meson-logs/testlog.txt", workflow)


if __name__ == "__main__":
    unittest.main()
