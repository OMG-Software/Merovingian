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
    def test_release_metadata_files_are_utf8_without_bom(self) -> None:
        # GIVEN release packaging metadata and helper scripts are parsed by
        # FreeBSD pkg(8), POSIX shells, and the C++ toolchain directly.
        files = (
            "packaging/freebsd/+MANIFEST",
            "scripts/build-deb.sh",
            "scripts/build-freebsd-pkg.sh",
            "scripts/build-openbsd-pkg.sh",
            "scripts/build-netbsd-pkg.sh",
            "scripts/build-rpm.sh",
            "scripts/build-static-linux.sh",
            "src/db_migrate.cpp",
            "src/main.cpp",
        )

        # WHEN packaging automation reads those files byte-for-byte.
        # THEN they must start with plain UTF-8 text rather than a BOM prefix
        # that breaks FreeBSD's UCL manifest parser and some Unix shebang consumers.
        for relative_path in files:
            with self.subTest(path=relative_path):
                content = (REPO_ROOT / relative_path).read_bytes()
                self.assertFalse(
                    content.startswith(b"\xef\xbb\xbf"),
                    f"{relative_path} must be UTF-8 without BOM",
                )

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
        self.assertIn(
            "needs: [deb, static-linux-fallback, rpm, freebsd-pkg, openbsd-pkg, netbsd-pkg]",
            workflow,
        )
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
            "scripts/build-openbsd-pkg.sh": f'VERSION="{version}"',
            "scripts/build-netbsd-pkg.sh": f'VERSION="{version}"',
            "scripts/build-static-linux.sh": f'VERSION="${{MEROVINGIAN_VERSION:-{version}}}"',
        }
        for script, expected in expected_versions.items():
            with self.subTest(script=script):
                content = (REPO_ROOT / script).read_text(encoding="utf-8")
                self.assertIn(expected, content)

    def test_versioned_binaries_and_package_metadata_use_the_project_version(self) -> None:
        # GIVEN the Meson project version is the canonical release version.
        version = project_version()

        # WHEN release artifacts and operators inspect binary/package version
        # metadata across the repository.
        # THEN every required location from the versioning policy reports the
        # same version string.
        expected_versions = {
            "src/main.cpp": f'constexpr auto version = std::string_view{{"{version}"}};',
            "src/db_migrate.cpp": f'constexpr auto version = std::string_view{{"{version}"}};',
            "packaging/freebsd/+MANIFEST": f'version: "{version}"',
            "packaging/rpm/merovingian.spec": f"Version:        {version}",
            "packaging/netbsd/Makefile": f"merovingian-{version}",
        }
        for path, expected in expected_versions.items():
            with self.subTest(path=path):
                content = (REPO_ROOT / path).read_text(encoding="utf-8")
                self.assertIn(expected, content)

    def test_all_bsd_platforms_have_package_build_jobs(self) -> None:
        # GIVEN the package publication workflow.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Tier 1 BSD platforms must ship installable, attested packages.
        # THEN FreeBSD, OpenBSD, and NetBSD each have a package build job on their
        # VM running the matching build script, and the artifacts are published.
        for job in ("freebsd-pkg:", "openbsd-pkg:", "netbsd-pkg:"):
            self.assertIn(job, workflow)
        self.assertIn("sh scripts/build-openbsd-pkg.sh", workflow)
        self.assertIn("sh scripts/build-netbsd-pkg.sh", workflow)
        self.assertIn("vmactions/openbsd-vm", workflow)
        self.assertIn("vmactions/netbsd-vm", workflow)
        self.assertIn("name: openbsd-package", workflow)
        self.assertIn("name: netbsd-package", workflow)

    def test_freebsd_packages_workflow_uses_the_supported_dependency_set(self) -> None:
        # GIVEN the FreeBSD packaging job in the packages workflow.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the VM provisions build dependencies before invoking the repo's
        # FreeBSD packaging script.
        # THEN it uses the repository's supported pkg set, including python3,
        # and does not introduce extra packages that the other FreeBSD flows do
        # not rely on.
        self.assertIn("pkg install -y meson ninja llvm catch2 pkgconf git perl5 bison flex \\", workflow)
        self.assertIn("gmake openssl libsodium postgresql17-client python3", workflow)
        self.assertNotIn("postgresql17-client curl sqlite3 catch2", workflow)


if __name__ == "__main__":
    unittest.main()
