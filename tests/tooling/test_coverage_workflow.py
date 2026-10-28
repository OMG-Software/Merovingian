#!/usr/bin/env python3
from __future__ import annotations

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
        self.assertRegex(workflow, r"(?m)^[ \t]+--gcov-exclude-directories '\.\*/subprojects/'[ \t]*\\[ \t]*$")

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
        self.assertRegex(workflow, r"(?m)^[ \t]+CC: gcc-14[ \t]*$")
        self.assertRegex(workflow, r"(?m)^[ \t]+CXX: g\+\+-14[ \t]*$")
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


if __name__ == "__main__":
    unittest.main()
