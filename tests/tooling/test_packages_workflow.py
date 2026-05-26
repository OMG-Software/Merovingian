#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "packages.yml"


def project_version() -> str:
    meson_build = (REPO_ROOT / "meson.build").read_text(encoding="utf-8")
    match = re.search(r"version:\s*'([^']+)'", meson_build)
    if match is None:
        raise AssertionError("meson project version is missing")
    return match.group(1)


class PackagesWorkflowTests(unittest.TestCase):
    def test_static_linux_fallback_binary_is_packaged(self) -> None:
        # GIVEN the package publication workflow.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN operators need a fallback binary for older Linux distributions.
        # THEN CI builds an Alpine/musl static tarball and includes it in latest.
        self.assertIn("static-linux-fallback:", workflow)
        self.assertIn("container: alpine:latest", workflow)
        self.assertIn("libpq-dev", workflow)
        self.assertIn("openssl-libs-static", workflow)
        self.assertIn("sh scripts/build-static-linux.sh", workflow)
        self.assertIn("name: static-linux-fallback-package", workflow)
        self.assertIn("needs: [deb, static-linux-fallback, rpm, freebsd-pkg]", workflow)
        self.assertIn("merovingian-*-linux-static-x86_64.tar.gz", workflow)

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

    def test_package_scripts_use_the_project_version(self) -> None:
        # GIVEN the Meson project version is the canonical release version.
        version = project_version()

        # WHEN package helper scripts build release artifacts.
        # THEN each script uses the same version so source archive names match
        # the package metadata consumed by downstream packaging tools.
        expected_versions = {
            "scripts/build-deb.sh": f'VERSION="{version}"',
            "scripts/build-rpm.sh": f'VERSION="{version}"',
            "scripts/build-freebsd-pkg.sh": f'VERSION="{version}"',
            "scripts/build-static-linux.sh": f'VERSION="${{MEROVINGIAN_VERSION:-{version}}}"',
        }
        for script, expected in expected_versions.items():
            with self.subTest(script=script):
                content = (REPO_ROOT / script).read_text(encoding="utf-8")
                self.assertIn(expected, content)


if __name__ == "__main__":
    unittest.main()
