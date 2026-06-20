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


if __name__ == "__main__":
    unittest.main()
