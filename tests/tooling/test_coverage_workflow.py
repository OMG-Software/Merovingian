#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
COVERAGE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "coverage.yml"
CODECOV_CONFIG = REPO_ROOT / ".codecov.yml"


class CoverageWorkflowTests(unittest.TestCase):
    def test_coverage_upload_targets_project_headers_and_sources_only(self) -> None:
        # GIVEN the dedicated coverage workflow.
        self.assertTrue(COVERAGE_WORKFLOW.is_file(), "coverage workflow is missing")
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN gcovr is configured for the Codecov upload.
        # THEN only Merovingian production headers are counted, not every vendored
        # header staged under include/.
        self.assertIn("--filter 'src/'", workflow)
        self.assertIn("--filter 'include/merovingian/'", workflow)
        self.assertNotIn("--filter 'include/'", workflow)

    def test_gcov_never_reads_the_vendored_subprojects(self) -> None:
        # GIVEN the dedicated coverage workflow.
        self.assertTrue(COVERAGE_WORKFLOW.is_file(), "coverage workflow is missing")
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN gcovr searches the build directory for counter files.
        # THEN it skips the vendored subprojects (SQLite and the other wraps): their
        # coverage is filtered out of the report anyway, and a damaged counter file
        # there failed the whole job (PR #542, sqlite3.c.gcda, gcov exit 4).
        self.assertRegex(workflow, r"(?m)^[ \t]+--gcov-exclude-directories '\.\*/subprojects\$'[ \t]*\\[ \t]*$")

    def test_branch_coverage_counts_decisions_not_exception_edges(self) -> None:
        # GIVEN the dedicated coverage workflow.
        self.assertTrue(COVERAGE_WORKFLOW.is_file(), "coverage workflow is missing")
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN gcovr reports branch coverage for the Codecov upload.
        # THEN the compiler's exception edges are left out (ADR-0217): a call that
        # may throw gets an unwinding branch no test reaches without injecting
        # allocation failures, so counting it marks executed lines as partial.
        # Matched as an argument line of the gcovr call, so the explanatory
        # comment above it in the workflow cannot satisfy this on its own.
        self.assertRegex(workflow, r"(?m)^[ \t]+--exclude-throw-branches[ \t]*\\[ \t]*$")
        # AND the job builds with GCC and reads its data with the matching gcov:
        # llvm-cov gcov does not label exception edges, so under clang the flag
        # above silently excludes nothing.
        self.assertRegex(workflow, r"(?m)^[ \t]+CC: ccache gcc-14[ \t]*$")
        self.assertRegex(workflow, r"(?m)^[ \t]+CXX: ccache g\+\+-14[ \t]*$")
        self.assertRegex(workflow, r"(?m)^[ \t]+--gcov-executable gcov-14[ \t]*\\[ \t]*$")
        self.assertNotIn("llvm-cov gcov\" \\", workflow)

    def test_branch_coverage_leaves_out_branches_on_lines_without_code(self) -> None:
        # GIVEN the dedicated coverage workflow.
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN gcovr reports branch coverage.
        # THEN branches gcov attributes to lines with no code of ours, such as a
        # function's closing brace where the compiler runs the destructors of its
        # locals, are left out (ADR-0253). Matched as an argument line of the call.
        self.assertRegex(workflow, r"(?m)^[ \t]+--exclude-unreachable-branches[ \t]*\\[ \t]*$")

    def test_coverage_upload_excludes_the_real_server_entrypoint(self) -> None:
        # GIVEN the coverage workflow and the repository Codecov config.
        self.assertTrue(COVERAGE_WORKFLOW.is_file(), "coverage workflow is missing")
        self.assertTrue(CODECOV_CONFIG.is_file(), "Codecov config is missing")
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        codecov = CODECOV_CONFIG.read_text(encoding="utf-8")

        # WHEN the process entrypoint is excluded from line coverage.
        # THEN both configs agree on src/main.cpp, which is the real entrypoint in
        # this tree.
        self.assertIn("--exclude 'src/main.cpp'", workflow)
        self.assertIn('- "src/main.cpp"', codecov)
        self.assertNotIn("src/homeserver/main.cpp", workflow)
        self.assertNotIn("src/homeserver/main.cpp", codecov)

    def test_coverage_measures_the_postgresql_store(self) -> None:
        # GIVEN the coverage workflow.
        self.assertTrue(COVERAGE_WORKFLOW.is_file(), "coverage workflow is missing")
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the full suite runs for coverage.
        # THEN a live PostgreSQL is provided with the database and both roles
        # handed to the tests, so the [postgresql] scenarios run instead of
        # skipping and the PostgreSQL store is measured rather than reading as
        # entirely uncovered.
        self.assertIn("image: postgres:", workflow)
        self.assertIn("MEROVINGIAN_TEST_POSTGRESQL_URI:", workflow)
        self.assertIn("MEROVINGIAN_TEST_POSTGRESQL_MIGRATION_ROLE:", workflow)
        self.assertIn("MEROVINGIAN_TEST_POSTGRESQL_RUNTIME_ROLE:", workflow)
        self.assertIn("CREATE ROLE merovingian_migration", workflow)
        self.assertIn("CREATE ROLE merovingian_runtime", workflow)
        # AND hardening stays on, so the hardening paths remain measured.
        self.assertNotIn("MEROVINGIAN_TEST_DISABLE_HARDENING", workflow)

    def test_one_job_named_coverage_builds_and_tests_once(self) -> None:
        # GIVEN the coverage workflow, whose `coverage` job is a required check in the main ruleset.
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        job_ids = re.findall(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", workflow.split("\njobs:\n", 1)[1])

        # WHEN its jobs are listed.
        # THEN `coverage` builds, and Sonar's analysis is a step of it, not a second build; the only other job
        # uploads to Codecov from the report the build wrote.
        self.assertEqual(job_ids, ["coverage", "codecov"])
        self.assertRegex(workflow, r"(?m)^name: coverage$")
        self.assertFalse((COVERAGE_WORKFLOW.parent / "sonarcloud.yml").exists())
        # AND the build and the suites run once.
        self.assertEqual(workflow.count("run: sh scripts/build-linux.sh"), 1)

    def test_the_codecov_cli_never_shares_a_job_with_the_sonar_token(self) -> None:
        # GIVEN the coverage workflow. A step can read every secret its job uses from the runner's memory, and the
        # Codecov action runs a CLI whose signature check it skips (ADR-0250, ADR-0846).
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        coverage_job, codecov_job = workflow.split("\n  codecov:\n", 1)

        # THEN SONAR_TOKEN is in the coverage job only, and the Codecov action in the codecov job only.
        self.assertIn("secrets.SONAR_TOKEN", coverage_job)
        self.assertNotIn("codecov/codecov-action@", coverage_job)
        self.assertNotIn("SONAR_TOKEN", codecov_job)
        self.assertIn("codecov/codecov-action@", codecov_job)
        # AND the codecov job takes the report the coverage job uploaded, and builds nothing.
        self.assertIn("needs: coverage", codecov_job)
        self.assertIn("actions/download-artifact@", codecov_job)
        self.assertIn("name: coverage-${{ github.sha }}", codecov_job)
        self.assertNotIn("build-linux.sh", codecov_job)

    def test_one_gcovr_run_writes_the_codecov_and_the_sonarqube_reports(self) -> None:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN gcovr reads the one build directory.
        # THEN it writes the Cobertura report Codecov uploads, the HTML report and the SonarQube-format report the
        # scan reads, from the same counters, in one run.
        self.assertEqual(workflow.count("--root ."), 1)
        self.assertIn("--output coverage/coverage.xml", workflow)
        self.assertIn("--html coverage/index.html", workflow)
        self.assertIn("--sonarqube coverage/sonarqube.xml", workflow)
        self.assertRegex(workflow, r"(?m)^[ \t]+build-coverage$")
        # AND Codecov and the artifact take those reports.
        self.assertIn("flags: full-test-suite", workflow)
        self.assertIn("files: coverage/coverage.xml", workflow)
        self.assertIn("path: coverage", workflow)

    def test_only_the_sonar_scan_is_skipped_for_a_pull_request_from_a_fork(self) -> None:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        before_steps, steps = workflow.split("\n    steps:\n", 1)
        guard = "if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository"

        # THEN the fork guard is on the scan step and on no other step.
        guarded = [step for step in steps.split("\n      - ") if guard in step]
        self.assertEqual(len(guarded), 1)
        self.assertIn("SonarSource/sonarqube-scan-action@", guarded[0])
        # AND the job itself has no condition, so the build, reports and Codecov upload run for a fork.
        self.assertNotRegex(before_steps, r"(?m)^    if:")

    def test_the_workflow_runs_for_main_every_pull_request_the_merge_queue_and_by_hand(self) -> None:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        self.assertRegex(workflow, r"(?m)^on:\n  push:\n    branches: \[main\]\n")
        # A pull request of any base, as Sonar's was: no `branches:` under it.
        self.assertRegex(workflow, r"(?m)^  pull_request:[ \t]*\n  merge_group:[ \t]*\n  workflow_dispatch:[ \t]*\n")

    def test_a_new_push_to_a_pull_request_cancels_its_earlier_run_and_nothing_else_is_cancelled(self) -> None:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # THEN a pull request's runs share a group and cancel each other; every other run has a group of its own,
        # so a run on main or in the merge queue is never cancelled (a cancelled required check shows as a failure).
        self.assertIn(
            "group: coverage-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number)"
            " || github.run_id }}",
            workflow,
        )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", workflow)

    def test_compiler_output_is_cached_with_ccache_that_main_alone_saves(self) -> None:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")

        # THEN ccache is installed by the package manager before the action runs (ADR-0650).
        install = workflow[workflow.index("sudo apt-get install") : workflow.index("- name: Cache compiler output with ccache")]
        self.assertRegex(install, r"(?m)^\s+ccache \\$")
        # AND the pinned action restores the newest cache and saves only on main.
        self.assertIn("uses: hendrikmuhs/ccache-action@f09c25b45002a07be2955cbe52e8cee55643f89d # v1.2.24", workflow)
        self.assertIn("key: ccache-coverage-${{ github.run_id }}", workflow)
        self.assertIn("restore-keys: ccache-coverage-", workflow)
        self.assertIn("max-size: 1G", workflow)
        self.assertIn("save: ${{ github.ref == 'refs/heads/main' }}", workflow)
        # AND the cache step precedes the build.
        self.assertLess(workflow.index("ccache-action@"), workflow.index("run: sh scripts/build-linux.sh"))
        # AND both compilers run through ccache: Meson adds it only when it picks the compiler itself, and
        # build-linux.sh passes CC and CXX explicitly (ADR-0843).
        self.assertRegex(workflow, r"(?m)^[ \t]+CC: ccache gcc-14[ \t]*$")
        self.assertRegex(workflow, r"(?m)^[ \t]+CXX: ccache g\+\+-14[ \t]*$")

    def run_launcher_strip(self, entries: list[dict[str, object]]) -> tuple[subprocess.CompletedProcess[str], object]:
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        script = textwrap.dedent(re.search(r"<<'PY'\n(?P<body>.*?)\n[ \t]+PY\n", workflow, re.DOTALL).group("body"))
        directory = Path(tempfile.mkdtemp(prefix="compile-db-"))
        self.addCleanup(shutil.rmtree, directory, True)
        database = directory / "compile_commands.json"
        database.write_text(json.dumps(entries), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-c", script, str(database)], check=False, text=True, capture_output=True
        )
        return result, json.loads(database.read_text(encoding="utf-8"))

    def test_the_scan_reads_a_compilation_database_without_the_ccache_launcher(self) -> None:
        # GIVEN Meson's compilation database for CC="ccache gcc-14", in both of the forms the format allows.
        entries = [
            {"directory": "b", "file": "a.cpp", "command": "ccache g++-14 -Iinclude -c a.cpp"},
            {"directory": "b", "file": "b.c", "arguments": ["ccache", "gcc-14", "-c", "b.c"]},
            {"directory": "b", "file": "c.cpp", "command": "g++-14 -c c.cpp"},
        ]

        # WHEN the workflow's step rewrites it.
        result, rewritten = self.run_launcher_strip(entries)

        # THEN each command starts with the compiler, which is how the scan identifies it, and nothing else changes.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rewritten[0]["command"], "g++-14 -Iinclude -c a.cpp")
        self.assertEqual(rewritten[1]["arguments"], ["gcc-14", "-c", "b.c"])
        self.assertEqual(rewritten[2]["command"], "g++-14 -c c.cpp")
        # AND the step runs after the build and before the scan.
        workflow = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
        step = workflow.index("- name: Remove the ccache launcher from the compilation database")
        self.assertLess(workflow.index("run: sh scripts/build-linux.sh"), step)
        self.assertLess(step, workflow.index("SonarSource/sonarqube-scan-action@"))

    def test_a_database_with_no_launcher_fails_the_step(self) -> None:
        # GIVEN a database in which no command starts with ccache, as after CC stopped naming it.
        result, _ = self.run_launcher_strip([{"directory": "b", "file": "a.c", "command": "gcc-14 -c a.c"}])

        # THEN the step fails, so the step and the CC it depends on cannot drift apart unnoticed.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no entry starts with ccache", result.stderr)


if __name__ == "__main__":
    unittest.main()
