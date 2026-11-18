#!/usr/bin/env python3
"""The NetBSD jobs download their packages on the host, cache them, and install them in the VM
from the synced directory before the mirrors (scripts/fetch-netbsd-packages.py)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
JOBS = (("ci.yml", "netbsd-build-and-test"), ("packages.yml", "netbsd-pkg"))
CACHE_PIN = re.compile(r"uses: actions/cache/(restore|save)@[0-9a-f]{40} # v\d+\.\d+\.\d+")


def job_text(workflow: str, job: str) -> str:
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    match = re.search(r"^  " + job + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.MULTILINE | re.DOTALL)
    assert match, job
    return match.group(1)


class NetbsdPackageCacheWorkflowTests(unittest.TestCase):
    def test_each_job_fetches_on_the_host_before_the_vm_starts(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                # GIVEN the job's text. THEN the fetch (resolve, then download) precedes the VM step.
                self.assertEqual(text.count("scripts/fetch-netbsd-packages.py"), 2)
                self.assertLess(text.index("scripts/fetch-netbsd-packages.py"), text.index("uses: vmactions/netbsd-vm@"))
                self.assertIn("--resolve-only", text)
                # AND the package list is passed to the script and the VM from one definition.
                self.assertEqual(text.count("NETBSD_PACKAGES="), 1)
                self.assertIn("envs: 'NETBSD_RELEASE NETBSD_ARCH NETBSD_PACKAGES'", text)
                self.assertIn("release: ${{ env.NETBSD_RELEASE }}", text)

    def test_cache_actions_are_pinned_and_keyed_on_the_lockfile(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                self.assertEqual(len(CACHE_PIN.findall(text)), 2)
                self.assertIn("hashFiles('netbsd-packages.lock')", text)
                self.assertIn("restore-keys: netbsd-packages-${{ env.NETBSD_RELEASE }}-${{ env.NETBSD_ARCH }}-", text)
                # The cache is saved before the VM runs, so removing the directory in the guest cannot empty it.
                self.assertLess(text.index("actions/cache/save@"), text.index("uses: vmactions/netbsd-vm@"))
                # AND only main writes it, as with ccache (ADR-0843, ADR-0844): the repository publishes no package
                # checksums, so a restored file is checked for size and a whole stream only, and no other ref may
                # write an entry that main or the merge queue would restore.
                self.assertIn(
                    "if: github.ref == 'refs/heads/main' && steps.netbsd-cache.outputs.cache-hit != 'true'", text
                )

    def test_the_vm_reads_the_local_directory_first_and_keeps_the_mirrors(self) -> None:
        for workflow, job in JOBS:
            text = job_text(workflow, job)
            with self.subTest(job=job):
                self.assertIn('export PKG_PATH="${local_packages}https://${mirror}/${package_path}"', text)
                self.assertIn('local_packages="$base/netbsd-packages;"', text)
                self.assertIn('= "$NETBSD_RELEASE" ]', text)
                self.assertIn("cdn.netbsd.org ftp.netbsd.org", text)
                self.assertIn("rm -rf netbsd-packages", text)

    def test_the_script_is_https_only_and_never_shell_interpolated(self) -> None:
        script = (Path(__file__).resolve().parents[2] / "scripts" / "fetch-netbsd-packages.py").read_text(encoding="utf-8")
        self.assertIn('urllib.parse.urlsplit(url).scheme != "https"', script)
        for forbidden in ("subprocess", "os.system", "shell=True"):
            self.assertNotIn(forbidden, script)


if __name__ == "__main__":
    unittest.main()
