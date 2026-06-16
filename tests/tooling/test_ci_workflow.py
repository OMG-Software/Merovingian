#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class CiWorkflowTests(unittest.TestCase):
    def test_fedora_container_build_covers_red_hat_family(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Linux distro compatibility is checked.
        # THEN CI builds inside a Fedora container using dnf-provided packages.
        self.assertIn("fedora-build-and-test:", workflow)
        self.assertIn("container:", workflow)
        self.assertIn("image: fedora:latest", workflow)
        self.assertIn("dnf install -y", workflow)
        self.assertIn("openssl-devel", workflow)
        self.assertIn("libsodium-devel", workflow)
        self.assertIn("libpq-devel", workflow)
        self.assertIn("sh scripts/build-linux.sh --builddir build-fedora", workflow)

    def test_ci_installs_os_supplied_dynamic_libraries_on_primary_platforms(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Linux and FreeBSD jobs build with OS-supplied shared libraries.
        # THEN the required development/runtime packages are installed explicitly.
        self.assertIn("libsodium-dev", workflow)
        self.assertIn("libpq-dev", workflow)
        self.assertIn("libsodium postgresql17-client", workflow)

    def test_tier_one_bsd_platforms_have_build_and_test_jobs(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the Tier 1 platform matrix is checked.
        # THEN FreeBSD, OpenBSD, and NetBSD each have a dedicated job that builds
        # and runs the test suite on the platform VM, so platform-specific
        # runtime behaviour (e.g. hardening self-checks) is exercised per PR.
        for job in (
            "freebsd-build-and-test:",
            "openbsd-build-and-test:",
            "netbsd-build-and-test:",
        ):
            self.assertIn(job, workflow)
        for vm in (
            "vmactions/freebsd-vm",
            "vmactions/openbsd-vm",
            "vmactions/netbsd-vm",
        ):
            self.assertIn(vm, workflow)
        # THEN each BSD job builds through the shared BSD wrapper, which runs the
        # full meson test suite on the platform.
        self.assertGreaterEqual(workflow.count("sh scripts/build-bsd.sh --builddir build"), 3)

    def test_tier_one_linux_distro_platforms_have_build_and_test_jobs(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the Tier 1 Linux distro matrix is checked.
        # THEN Debian trixie, RHEL-compatible (AlmaLinux 10), and OpenSUSE
        # Tumbleweed each have a dedicated container job that builds and runs the
        # full test suite, covering distro-specific package names and glibc versions.
        for job in (
            "debian-build-and-test:",
            "rhel-build-and-test:",
            "opensuse-build-and-test:",
        ):
            self.assertIn(job, workflow)
        for image in ("debian:trixie", "almalinux:10", "opensuse/tumbleweed"):
            self.assertIn(image, workflow)
        # THEN each job installs distro-specific library packages.
        self.assertIn("libopenssl-devel", workflow)   # OpenSUSE OpenSSL
        self.assertIn("libjpeg8-devel", workflow)  # OpenSUSE libjpeg-turbo (Tumbleweed package name)
        self.assertIn("findutils", workflow)           # OpenSUSE: find(1) for test-registration check
        self.assertIn("epel-release", workflow)        # RHEL EPEL bootstrap
        self.assertIn("zypper --non-interactive install", workflow)  # OpenSUSE pkg mgr
        # THEN each job runs the same Linux build wrapper used by Ubuntu and Fedora.
        self.assertIn("sh scripts/build-linux.sh --builddir build-debian", workflow)
        self.assertIn("sh scripts/build-linux.sh --builddir build-rhel", workflow)
        self.assertIn("sh scripts/build-linux.sh --builddir build-opensuse", workflow)

    def test_conformance_and_packaging_capability_gates_are_present(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Matrix conformance and packaging consistency must pass before merge.
        # THEN both are represented as explicitly named gate steps in CI so
        # failures surface as distinct job steps rather than being buried inside
        # the generic build-and-test step.
        self.assertIn("Conformance gate", workflow)
        self.assertIn("check-conformance-gate.sh", workflow)
        self.assertIn("Packaging sanity gate", workflow)
        self.assertIn("packages-workflow-tooling", workflow)


if __name__ == "__main__":
    unittest.main()
