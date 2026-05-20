#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "packages.yml"


class PackagesWorkflowTests(unittest.TestCase):
    def test_publish_latest_retargets_the_release_in_repository_scope(self) -> None:
        # GIVEN the rolling package publication workflow.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the main branch replaces the rolling latest release.
        # THEN the workflow resolves, deletes, and recreates that release against
        # the current repository explicitly instead of relying on checkout state.
        self.assertIn("publish-latest:", workflow)
        self.assertIn("gh release view latest --repo", workflow)
        self.assertIn("gh release delete latest \\", workflow)
        self.assertIn('--repo "${{ github.repository }}"', workflow)
        self.assertIn("gh release create latest \\", workflow)


if __name__ == "__main__":
    unittest.main()
