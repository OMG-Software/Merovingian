#!/usr/bin/env python3
"""scripts/stage-release-tarball.sh ships every executable `meson install` installs and refuses a release without its workers (ADR-0597)."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "stage-release-tarball.sh"
SH = shutil.which("sh")

# The files the script copies from the checkout besides the binaries.
CHECKOUT_FILES = (
    "config/merovingian.conf.example", "LICENSE", "README.md",
    "docs/user-manual.md", "docs/release-process.md", "docs/security-review-checklist.md",
    "packaging/systemd/merovingian.service", "packaging/openrc/merovingian", "packaging/rc.d/merovingian",
    "packaging/deb/control", "packaging/rpm/merovingian.spec", "packaging/freebsd/+MANIFEST",
    "packaging/openbsd/DESCR", "packaging/openbsd/PLIST", "packaging/netbsd/Makefile",
)

INSTALLED = (
    "bin/merovingian-server",
    "bin/merovingian-db-migrate",
    "libexec/merovingian/merovingian-fed-worker",
    "libexec/merovingian/merovingian-thumbnail-worker",
)

# Stands in for `meson install -C BUILD --destdir DIR --skip-subprojects`:
# installs every path in FAKE_MESON_INSTALL under DIR/usr/local.
FAKE_MESON = """#!/bin/sh
set -eu
destdir=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --destdir) destdir=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$destdir" ] || exit 64
for path in $FAKE_MESON_INSTALL; do
    mkdir -p "$(dirname "$destdir/usr/local/$path")"
    printf 'binary %s\\n' "$path" > "$destdir/usr/local/$path"
    chmod 0755 "$destdir/usr/local/$path"
done
"""


@unittest.skipUnless(SH, "needs a POSIX sh")
class StageReleaseTarballTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        for relative in CHECKOUT_FILES:
            target = self.work / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / relative, target)
        (self.work / "build").mkdir()
        tools = self.work / "tools"
        tools.mkdir()
        meson = tools / "meson"
        meson.write_text(FAKE_MESON, encoding="utf-8", newline="\n")
        meson.chmod(0o755)
        self.path = f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"

    def stage(self, installed: tuple[str, ...], package_root: str = "pkg") -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PATH=self.path, FAKE_MESON_INSTALL=" ".join(installed))
        return subprocess.run([SH, str(SCRIPT), "build", package_root], cwd=self.work, env=env,
                              capture_output=True, text=True, check=False)

    def test_every_installed_executable_ships_with_the_install_prefix(self) -> None:
        # GIVEN a build that installs the four release executables and one more.
        installed = INSTALLED + ("bin/merovingian-future-tool",)

        # WHEN the tarball directory is staged.
        result = self.stage(installed)

        # THEN all of them ship under bin/ and libexec/merovingian/, the build's
        # install prefix is recorded, the checkout's docs and packaging
        # scaffolds are copied, and the staging tree is gone.
        self.assertEqual(result.returncode, 0, result.stderr)
        root = self.work / "pkg"
        for path in installed:
            with self.subTest(path=path):
                self.assertTrue((root / path).is_file())
        self.assertEqual((root / "INSTALL-PREFIX").read_text(encoding="utf-8"), "/usr/local\n")
        for relative in ("config/merovingian.conf.example", "LICENSE", "docs/user-manual.md",
                         "packaging/deb/control", "packaging/netbsd/Makefile"):
            self.assertTrue((root / relative).is_file(), relative)
        self.assertFalse((self.work / "pkg.staging").exists())

    def test_a_build_without_the_thumbnail_worker_is_refused(self) -> None:
        # GIVEN a build that did not install the thumbnail worker (no image codecs found).
        installed = tuple(path for path in INSTALLED if "thumbnail" not in path)

        # WHEN the tarball directory is staged.
        result = self.stage(installed)

        # THEN staging fails and names the missing worker.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("merovingian-thumbnail-worker", result.stderr)

    def test_a_build_without_the_federation_worker_is_refused(self) -> None:
        # GIVEN a build that did not install the federation worker.
        installed = tuple(path for path in INSTALLED if "fed-worker" not in path)

        # WHEN the tarball directory is staged.
        result = self.stage(installed)

        # THEN staging fails and names the missing worker.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("merovingian-fed-worker", result.stderr)

    def test_an_existing_package_root_is_not_overwritten(self) -> None:
        # GIVEN a package directory left from an earlier run.
        (self.work / "pkg").mkdir()
        (self.work / "pkg" / "keep").write_text("earlier", encoding="utf-8")

        # WHEN the tarball directory is staged again.
        result = self.stage(INSTALLED)

        # THEN staging refuses and leaves it as it was.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertEqual((self.work / "pkg" / "keep").read_text(encoding="utf-8"), "earlier")


if __name__ == "__main__":
    unittest.main()
