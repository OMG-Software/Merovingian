#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_alpha_tags_trigger_release_publication(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN alpha tags are pushed.
        # THEN the workflow triggers on the alpha tag pattern.
        self.assertIn("tags:", workflow)
        self.assertIn("- 'v*-alpha*'", workflow)

    def test_hardened_linux_and_freebsd_packages_are_built(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN alpha assets are built.
        # THEN both supported package jobs use the hardened profile.
        self.assertIn(
            "sh scripts/build-linux.sh --builddir build-linux-release --profile hardened",
            workflow,
        )
        self.assertIn(
            "sh scripts/build-bsd.sh --builddir build-freebsd-release --profile hardened",
            workflow,
        )
        self.assertIn("sh scripts/check-release-readiness.sh", workflow)

    def test_alpha_release_publishes_prerelease_assets_and_checksums(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN alpha packages are published.
        # THEN the workflow generates checksums and uploads a GitHub prerelease.
        self.assertIn("sha256sum", workflow)
        self.assertIn("sha256 -q", workflow)
        self.assertIn("softprops/action-gh-release@v2", workflow)
        self.assertIn("prerelease: true", workflow)


if __name__ == "__main__":
    unittest.main()
