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
        self.assertIn("sh scripts/build-linux.sh --builddir build-fedora", workflow)


if __name__ == "__main__":
    unittest.main()
