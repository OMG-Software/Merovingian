#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for scripts/check_expected_skips.py and the allow-list it reads (ADR-0546)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_expected_skips.py"
ALLOWLIST = REPO_ROOT / "tests" / "expected_skips.json"

FINISHED = '<OverallResults successes="1" failures="0" expectedFailures="0" skips="{skips}"/>'


def report(cases: list[tuple[str, list[str]]]) -> str:
    """A Catch2 XML report: each case is (name, skip messages)."""
    body = ""
    for name, messages in cases:
        skips = "".join(
            f'<Section name="s"><Skip filename="t.cpp" line="7">{message}</Skip></Section>' for message in messages
        )
        body += f'<TestCase name="{name}">{skips}<OverallResult success="true" skips="{len(messages)}"/></TestCase>'
    return f'<Catch2TestRun name="bin">{body}{FINISHED.format(skips=0)}</Catch2TestRun>'


ALLOW = {
    "groups": {
        "g": [{"test": "Landlock case", "message": "no Landlock", "reason": "kernel without Landlock"}],
        "h": [{"test": "Plain case", "reason": "any message"}],
    },
    "jobs": {"one": ["g"], "two": ["g", "h"], "none": []},
}


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.reports = self.dir / "reports"
        self.reports.mkdir()
        self.allow = self.dir / "allow.json"
        self.allow.write_text(json.dumps(ALLOW), encoding="utf-8")

    def run_gate(self, job: str = "one", *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(SCRIPT), "--job", job, "--reports", str(self.reports),
                "--allowlist", str(self.allow), *extra,
            ],
            capture_output=True, text=True, check=False,
        )

    def write(self, name: str, text: str) -> None:
        (self.reports / name).write_text(text, encoding="utf-8")

    def test_unexpected_skip_fails_and_names_test_and_message(self) -> None:
        # GIVEN a report where a test case that the job does not list skipped.
        self.write("a-1.xml", report([("Scenario: Surprise", ["runner lacks X"])]))
        # WHEN the gate runs.
        result = self.run_gate()
        # THEN it fails and prints the test name and the SKIP message.
        self.assertEqual(result.returncode, 1)
        self.assertIn("Surprise", result.stdout)
        self.assertIn("runner lacks X", result.stdout)

    def test_expected_skip_passes(self) -> None:
        # GIVEN a listed skip with a matching message (the Scenario: prefix is ignored).
        self.write("a-1.xml", report([("Scenario: Landlock case", ["kernel has no Landlock support"])]))
        # WHEN the gate runs, THEN it passes.
        self.assertEqual(self.run_gate().returncode, 0)

    def test_listed_test_skipping_for_another_reason_fails(self) -> None:
        # GIVEN a listed test that skips with a message the entry does not allow.
        self.write("a-1.xml", report([("Scenario: Landlock case", ["MEROVINGIAN_TEST_FEDERATION_WORKER is not defined"])]))
        # WHEN the gate runs, THEN it fails: the entry names the reason it accepts.
        self.assertEqual(self.run_gate().returncode, 1)

    def test_skip_listed_for_another_job_fails(self) -> None:
        # GIVEN a skip only job "two" lists.
        self.write("a-1.xml", report([("Plain case", ["whatever"])]))
        # THEN job one fails and job two passes.
        self.assertEqual(self.run_gate("one").returncode, 1)
        self.assertEqual(self.run_gate("two").returncode, 0)

    def test_no_skips_passes_and_a_stale_entry_only_warns(self) -> None:
        # GIVEN a run with no skips although the job lists one.
        self.write("a-1.xml", report([("Landlock case", [])]))
        # WHEN the gate runs, THEN it passes with a warning, and fails under --strict-stale.
        result = self.run_gate()
        self.assertEqual(result.returncode, 0)
        self.assertIn("did not happen", result.stderr)
        self.assertEqual(self.run_gate("one", "--strict-stale").returncode, 1)

    def test_skip_without_a_skip_element_still_counts(self) -> None:
        # GIVEN a case whose OverallResult says it skipped but which carries no Skip element.
        self.write(
            "a-1.xml",
            '<Catch2TestRun><TestCase name="Ghost"><OverallResult success="true" skips="1"/></TestCase>'
            f"{FINISHED.format(skips=1)}</Catch2TestRun>",
        )
        # THEN the gate fails.
        self.assertEqual(self.run_gate().returncode, 1)

    def test_every_report_in_the_directory_is_read(self) -> None:
        # GIVEN two binaries' reports, the second with an unexpected skip.
        self.write("a-1.xml", report([("Landlock case", ["no Landlock"])]))
        self.write("b-2.xml", report([("Surprise", ["x"])]))
        self.assertEqual(self.run_gate().returncode, 1)

    def test_missing_report_directory_fails_closed(self) -> None:
        # GIVEN no report directory at all.
        self.reports.rmdir()
        # THEN the gate refuses (exit 2), never passing for lack of data.
        self.assertEqual(self.run_gate().returncode, 2)

    def test_empty_report_directory_fails_closed(self) -> None:
        self.assertEqual(self.run_gate().returncode, 2)

    def test_malformed_report_fails_closed(self) -> None:
        self.write("a-1.xml", "<Catch2TestRun><TestCase name=")
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("a-1.xml", result.stderr)

    def test_report_of_a_run_that_did_not_finish_fails_closed(self) -> None:
        # GIVEN well-formed XML with no OverallResults (the binary died after the last test case closed).
        self.write(
            "a-1.xml",
            '<Catch2TestRun><TestCase name="x"><OverallResult success="true" skips="0"/></TestCase></Catch2TestRun>',
        )
        self.assertEqual(self.run_gate().returncode, 2)

    def test_foreign_xml_fails_closed(self) -> None:
        self.write("a-1.xml", "<testsuites/>")
        self.assertEqual(self.run_gate().returncode, 2)

    def test_unknown_job_and_bad_allowlist_fail_closed(self) -> None:
        self.write("a-1.xml", report([("x", [])]))
        self.assertEqual(self.run_gate("nope").returncode, 2)
        self.allow.write_text('{"groups": {"g": [{"test": "t"}]}, "jobs": {"one": ["g"]}}', encoding="utf-8")
        self.assertEqual(self.run_gate("one").returncode, 2, "an entry without a reason is refused")
        self.allow.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.run_gate("one").returncode, 2)


class AllowListTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(ALLOWLIST.read_text(encoding="utf-8"))

    def test_every_job_names_defined_groups_and_every_entry_has_a_reason(self) -> None:
        for job, groups in self.document["jobs"].items():
            for group in groups:
                self.assertIn(group, self.document["groups"], f"job {job}")
        for group, entries in self.document["groups"].items():
            for entry in entries:
                self.assertTrue(entry["test"].strip(), group)
                self.assertTrue(entry["reason"].strip(), f"{group}: {entry['test']}")

    def test_every_listed_test_exists_as_a_scenario(self) -> None:
        # A renamed test would leave its entry matching nothing, and the skip would then fail the job.
        names = set()
        for path in (REPO_ROOT / "tests").rglob("*.cpp"):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(r'(?:SCENARIO|TEST_CASE)\(\s*((?:"(?:[^"\\]|\\.)*"\s*)+)', text):
                names.add("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(1))))
        for group, entries in self.document["groups"].items():
            for entry in entries:
                self.assertIn(entry["test"], names, f"{group}: no test case is named '{entry['test']}'")

    def test_every_workflow_job_flag_names_a_known_job_and_every_job_is_used(self) -> None:
        used = set()
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            used.update(re.findall(r"--skip-job\s+([A-Za-z0-9_-]+)", text))
            used.update(re.findall(r"check_expected_skips\.py\s+--job\s+([A-Za-z0-9_-]+)", text))
            # A matrix job names its job in each leg (`skip_job: opensuse-leap`) and passes
            # `--skip-job ${{ matrix.skip_job }}` (ADR-0650); any other expression could not be read here.
            for expression in re.findall(r"--skip-job\s+(\$\{\{[^}]*\}\})", text):
                self.assertEqual(expression, "${{ matrix.skip_job }}", f"{path.name}: unreadable --skip-job")
            used.update(re.findall(r"^\s+skip_job:[ \t]+([A-Za-z0-9_-]+)[ \t]*$", text, re.MULTILINE))
        self.assertEqual(used, set(self.document["jobs"]))

    def test_workflows_that_run_catch2_through_the_build_scripts_pass_a_job(self) -> None:
        # Any build-linux.sh / build-bsd.sh call in a workflow that runs the tests must say which job it is.
        # A comment runs nothing, so the text after a `#` at the start of a line or after whitespace
        # is dropped first; `${VAR#prefix}` keeps its `#`.
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            for full_line in path.read_text(encoding="utf-8").splitlines():
                line = re.split(r"(?:^|\s)#", full_line, maxsplit=1)[0]
                if re.search(r"scripts/build-(linux|bsd)\.sh", line) and not re.search(
                    r"--(skip-job|no-tests|setup-only|compile-only)", line
                ):
                    self.fail(f"{path.name}: runs the tests without --skip-job: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
