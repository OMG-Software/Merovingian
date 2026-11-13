#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
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
        self.assertIn("dnf install -y", workflow)
        self.assertIn("openssl-devel", workflow)
        self.assertIn("libsodium-devel", workflow)
        self.assertIn("libpq-devel", workflow)
        self.assertIn("sh scripts/build-linux.sh --builddir build-fedora", workflow)

    def test_every_fedora_release_with_a_published_rpm_runs_the_suite(self) -> None:
        # GIVEN the packages workflow publishes an RPM for Fedora 44 and for Fedora 45, and
        # each links against its own release's libraries (Fedora 44 has OpenSSL 3, Fedora 45
        # has OpenSSL 4).
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        job = workflow.split("  fedora-suite:")[1].split("\n  fedora-build-and-test:")[0]

        # WHEN the Fedora build-and-test job's matrix is read
        # THEN the full suite runs on both, and a failure on one still reports the other.
        self.assertIn("image: ${{ matrix.image }}", job)
        # AND each is pinned by release, never fedora:latest, so the release CI tests is the
        # one packages.yml ships (ADR-0742).
        self.assertRegex(job, r"image: \[\s*fedora:44,\s*fedora:45\s*\]")
        self.assertNotIn("fedora:latest", workflow)
        self.assertIn("fail-fast: false", job)

        # AND the two builds keep separate compiler caches.
        self.assertIn("key: ccache-fedora-ci-${{ matrix.image }}-${{ github.run_id }}", job)
        self.assertIn("restore-keys: ccache-fedora-ci-${{ matrix.image }}-", job)

    def test_the_required_fedora_check_covers_every_image(self) -> None:
        # GIVEN the main ruleset requires a check called fedora-build-and-test, and a matrix
        # job reports one check per image, none of them with that name.
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the job reporting the required name runs
        job = workflow.split("\n  fedora-build-and-test:")[1].split("\n  # ── Debian")[0]

        # THEN it reports under that name, even when a leg failed, and passes only when
        # every leg succeeded.
        self.assertIn("needs: fedora-suite", job)
        self.assertIn("if: always()", job)
        self.assertIn("${{ needs.fedora-suite.result }}", job)
        self.assertIn('test "${RESULT}" = success', job)

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

    def test_every_bsd_build_and_test_job_is_required(self) -> None:
        # GIVEN the repository CI workflow.
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN each BSD job's text is read, up to the next top-level job.
        for job in ("freebsd-build-and-test", "openbsd-build-and-test", "netbsd-build-and-test"):
            pattern = r"^  " + job + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
            match = re.search(pattern, workflow, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, f"{job} is missing")
            text = match.group(1)

            # THEN it does not carry a job-level continue-on-error: a BSD failure
            # must fail the run and block the merge (ADR-0502).
            self.assertIsNone(
                re.search(r"^    continue-on-error:", text, re.MULTILINE),
                f"{job}: continue-on-error would let a failing BSD suite pass",
            )

    def test_every_bsd_job_drops_its_build_tree_before_the_vm_copies_back(self) -> None:
        # GIVEN the repository CI workflow.
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN each BSD job's text is read, up to the next top-level job.
        for job, platform in (
            ("freebsd-build-and-test", "freebsd"),
            ("openbsd-build-and-test", "openbsd"),
            ("netbsd-build-and-test", "netbsd"),
        ):
            pattern = r"^  " + job + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
            match = re.search(pattern, workflow, re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(match, f"{job} is missing")
            text = match.group(1)

            # THEN the build tree is removed once the artifact tarball exists: the VM
            # action copies the whole workspace back over one connection, and a dropped
            # connection during that copy fails a job whose tests passed.
            tarball = text.find(f"-czf merovingian-{platform}-artifacts.tar.gz")
            removal = text.find("rm -rf build\n", tarball)
            self.assertGreater(tarball, -1, f"{job}: no artifact tarball")
            self.assertGreater(removal, tarball, f"{job}: build tree still copied back")

    def test_tier_one_linux_distro_platforms_have_build_and_test_jobs(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the Tier 1 Linux distro matrix is checked.
        # THEN Debian trixie, RHEL-compatible (AlmaLinux 10), the Ubuntu interim
        # release (26.10), and OpenSUSE Tumbleweed and Leap 16.0 each have a container job
        # that builds and runs the full test suite, covering distro-specific
        # package names and glibc versions (ADR-0650).
        for job in (
            "debian-build-and-test:",
            "rhel-build-and-test:",
            "ubuntu-interim-build-and-test:",
            "opensuse-build-and-test:",
        ):
            self.assertIn(job, workflow)
        for image in ("debian:trixie", "almalinux:10", "ubuntu:26.10", "opensuse/tumbleweed", "opensuse/leap:16.0"):
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
        self.assertIn("sh scripts/build-linux.sh --builddir build-ubuntu-interim --skip-job ubuntu-interim", workflow)
        # AND the interim release is pinned and its check names the release (ADR-0742).
        self.assertNotIn("image: ubuntu:rolling", workflow)
        self.assertIn("    name: ubuntu-26.10-build-and-test\n", workflow)
        opensuse = workflow.split("\n  opensuse-build-and-test:")[1].split("\n  freebsd-build-and-test:")[0]
        self.assertIn('sh scripts/build-linux.sh --builddir "${BUILDDIR}" --skip-job ${{ matrix.skip_job }}', opensuse)
        self.assertIn("builddir: build-opensuse\n", opensuse)
        self.assertIn("builddir: build-opensuse-leap\n", opensuse)

    def test_every_ubuntu_apt_refresh_falls_back_to_public_dns(self) -> None:
        # GIVEN on 2026-11-11 the resolver GitHub's runners use answered nothing for *.ubuntu.com
        # for hours, on host runners and in Ubuntu containers alike, while plain `apt-get update`
        # exited 0 and the install then failed with no cause shown.
        script = (REPO_ROOT / "scripts" / "ci-apt-update.sh").read_text(encoding="utf-8")
        nameservers = re.search(r"printf '(nameserver [^']+)'", script)
        self.assertIsNotNone(nameservers)
        checked = 0
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            section = path.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
            headers = list(re.finditer(r"^  ([A-Za-z0-9_-]+):\n", section, re.MULTILINE))
            for index, header in enumerate(headers):
                job = section[header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(section)]
                commands = "\n".join(line for line in job.splitlines() if not line.lstrip().startswith("#"))
                if "apt-get update" not in commands and "ci-apt-update.sh" not in commands:
                    continue
                if re.search(r"(?m)^\s+(container|image): debian:", job):
                    continue  # deb.debian.org, not the Ubuntu archive
                checked += 1
                with self.subTest(workflow=path.name, job=header.group(1)):
                    # WHEN the job's package-index refresh is read
                    install = commands.split("apt-get install", 1)[0]
                    # THEN no refresh can pass having reached nothing
                    self.assertNotRegex(commands, r"(?m)^\s*(sudo )?apt-get update\s*$")
                    if "sh scripts/ci-apt-update.sh" in install:
                        # AND the shared script runs from the checkout, after it
                        self.assertIn("actions/checkout@", install.split("sh scripts/ci-apt-update.sh")[0])
                    else:
                        # AND a job that must refresh before its checkout carries the script's
                        # fallback with the same resolvers.
                        self.assertIn("apt-get update --error-on=any", install)
                        self.assertIn(f"printf '{nameservers.group(1)}' > /etc/resolv.conf", install)
        self.assertGreaterEqual(checked, 13)

    def _run_apt_update(self, failures: int, resolv_is_link: bool) -> tuple[subprocess.CompletedProcess[str], Path]:
        # A fake apt-get fails its first `failures` calls and logs the resolver each call saw;
        # a fake sudo runs its arguments, so the script behaves the same as root or not.
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        (bin_dir / "sudo").write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
        (bin_dir / "apt-get").write_text(
            "#!/bin/sh\n"
            'calls=$(($(cat "$FAKE_DIR/calls" 2>/dev/null || echo 0) + 1))\n'
            'echo "$calls" > "$FAKE_DIR/calls"\n'
            'echo "$* | $(head -n 1 "$FAKE_RESOLV")" >> "$FAKE_DIR/log"\n'
            '[ "$calls" -gt "$FAKE_FAILURES" ]\n',
            encoding="utf-8",
        )
        for tool in bin_dir.iterdir():
            tool.chmod(0o755)
        stub = work / "stub-resolv.conf"
        stub.write_text("nameserver 127.0.0.53\n", encoding="utf-8")
        resolv = work / "resolv.conf"
        if resolv_is_link:
            resolv.symlink_to(stub)
        else:
            resolv.write_text("nameserver 168.63.129.16\n", encoding="utf-8")
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_DIR": str(work),
            "FAKE_FAILURES": str(failures),
            "FAKE_RESOLV": str(resolv),
            "MEROVINGIAN_RESOLV_CONF": str(resolv),
            "MEROVINGIAN_APT_RETRY_DELAY": "0",
        }
        result = subprocess.run(
            ["sh", str(REPO_ROOT / "scripts" / "ci-apt-update.sh")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, work

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_apt_refresh_keeps_the_runners_resolver_when_it_works(self) -> None:
        # GIVEN a refresh that succeeds through the runner's own resolver
        # WHEN ci-apt-update.sh runs
        result, work = self._run_apt_update(failures=0, resolv_is_link=False)
        # THEN it refreshes once, with apt failing on any fetch error, and leaves DNS alone.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((work / "log").read_text(encoding="utf-8"), "update --error-on=any | nameserver 168.63.129.16\n")
        self.assertEqual((work / "resolv.conf").read_text(encoding="utf-8"), "nameserver 168.63.129.16\n")

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_apt_refresh_retries_through_public_dns_after_a_failure(self) -> None:
        for resolv_is_link in (True, False):
            with self.subTest(host_runner_symlink=resolv_is_link):
                # GIVEN the runner's resolver fails the first refresh, and /etc/resolv.conf is
                # systemd-resolved's symlink (host runner) or a plain file (container bind mount)
                # WHEN ci-apt-update.sh runs
                result, work = self._run_apt_update(failures=1, resolv_is_link=resolv_is_link)
                # THEN it warns, points DNS at the public resolvers, and the retry succeeds
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("::warning::apt-get update failed", result.stdout)
                calls = (work / "log").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[1], "update --error-on=any | nameserver 1.1.1.1")
                resolv = work / "resolv.conf"
                self.assertFalse(resolv.is_symlink())
                self.assertTrue(resolv.read_text(encoding="utf-8").startswith("nameserver 1.1.1.1\n"))
                # AND systemd-resolved's own stub file is never written through the link.
                self.assertEqual((work / "stub-resolv.conf").read_text(encoding="utf-8"), "nameserver 127.0.0.53\n")

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_apt_refresh_fails_when_public_dns_cannot_reach_the_archive_either(self) -> None:
        # GIVEN every refresh fails
        # WHEN ci-apt-update.sh runs
        result, work = self._run_apt_update(failures=99, resolv_is_link=False)
        # THEN it stops after three tries through the public resolvers and fails the step.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed through the public DNS resolvers too", result.stderr)
        self.assertEqual(len((work / "log").read_text(encoding="utf-8").splitlines()), 4)

    def test_every_openbsd_package_install_checks_what_it_installed(self) -> None:
        # GIVEN OpenBSD's pkg_add exits 0 having installed nothing: on 2026-11-11 the CDN's TLS
        # handshake failed, every package came back "Can't find", and the job only failed at
        # "meson: not found" in its build step.
        checked = 0
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for job in re.split(r"(?m)^  (?=[A-Za-z0-9_-]+:\n)", text.split("\njobs:\n", 1)[1]):
                if "vmactions/openbsd-vm@" not in job:
                    continue
                checked += 1
                with self.subTest(workflow=path.name, job=job.split(":", 1)[0]):
                    # WHEN the job's prepare script is read
                    commands = [line.strip() for line in job.splitlines() if not line.lstrip().startswith("#")]
                    # THEN no bare pkg_add runs, and the shared script installs with a check
                    self.assertFalse([line for line in commands if line.startswith("pkg_add")])
                    self.assertIn('sh scripts/ci-openbsd-pkg-add.sh --require "meson ninja git bison gmake curl" \\', commands)
                    # AND the libraries the thumbnail worker needs are checked too, under OpenBSD's
                    # package names: `jpeg` is its libjpeg-turbo, and base supplies pkg-config, flex
                    # and LibreSSL, so asking for those packages only printed "Can't find".
                    modules_line = '--require-pkg-config "libsodium libpng16 libturbojpeg" \\'
                    self.assertIn(modules_line, commands)
                    packages = commands[commands.index(modules_line) + 1].split()
                    self.assertIn("jpeg", packages)
                    for absent in ("jpeg-turbo", "pkgconf", "flex", "openssl"):
                        self.assertNotIn(absent, packages)
        self.assertGreaterEqual(checked, 2)

    def _run_openbsd_pkg_add(
        self, installs_on_call: int, modules_present: bool = True
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        # A fake pkg_add logs the PKG_PATH of each call and "installs" the fake command
        # fake-meson on call `installs_on_call`, exiting 0 every time, as OpenBSD's does.
        # A fake pkg-config knows the module fake-jpeg only when `modules_present`.
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        (bin_dir / "uname").write_text('#!/bin/sh\n[ "$1" = -r ] && echo 8.0 || echo amd64\n', encoding="utf-8")
        (bin_dir / "pkg_add").write_text(
            "#!/bin/sh\n"
            'calls=$(($(cat "$FAKE_DIR/calls" 2>/dev/null || echo 0) + 1))\n'
            'echo "$calls" > "$FAKE_DIR/calls"\n'
            'echo "$PKG_PATH $*" >> "$FAKE_DIR/log"\n'
            'if [ "$calls" -eq "$FAKE_INSTALLS_ON_CALL" ]; then\n'
            "    printf '#!/bin/sh\\n' > \"$FAKE_DIR/bin/fake-meson\"\n"
            '    chmod 755 "$FAKE_DIR/bin/fake-meson"\n'
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        (bin_dir / "pkg-config").write_text(
            f'#!/bin/sh\n[ "$1" = --exists ] && [ "$2" = fake-jpeg ] && [ {int(modules_present)} -eq 1 ]\n',
            encoding="utf-8",
        )
        for tool in bin_dir.iterdir():
            tool.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_DIR": str(work),
            "FAKE_INSTALLS_ON_CALL": str(installs_on_call),
            "MEROVINGIAN_PKG_RETRY_DELAY": "0",
        }
        result = subprocess.run(
            [
                "sh",
                str(REPO_ROOT / "scripts" / "ci-openbsd-pkg-add.sh"),
                "--require",
                "fake-meson",
                "--require-pkg-config",
                "fake-jpeg",
                "meson",
                "ninja",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, work

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_openbsd_package_install_stops_once_the_commands_exist(self) -> None:
        # GIVEN the first pkg_add through the CDN installs what the build needs
        # WHEN ci-openbsd-pkg-add.sh runs
        result, work = self._run_openbsd_pkg_add(installs_on_call=1)
        # THEN it installs once, from the release's package directory on the CDN.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (work / "log").read_text(encoding="utf-8"),
            "https://cdn.openbsd.org/pub/OpenBSD/8.0/packages/amd64/ -I meson ninja\n",
        )

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_openbsd_package_install_falls_back_to_the_origin_mirror(self) -> None:
        # GIVEN three pkg_add runs through the CDN that exit 0 having installed nothing
        # WHEN ci-openbsd-pkg-add.sh runs
        result, work = self._run_openbsd_pkg_add(installs_on_call=4)
        # THEN it warns about each, and the fourth run goes through ftp.openbsd.org and succeeds.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("::warning::pkg_add through cdn.openbsd.org"), 3)
        calls = (work / "log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 4)
        self.assertTrue(calls[3].startswith("https://ftp.openbsd.org/pub/OpenBSD/8.0/packages/amd64/ "))

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_openbsd_package_install_fails_when_no_mirror_installs_the_commands(self) -> None:
        # GIVEN pkg_add never installs anything, though it always exits 0
        # WHEN ci-openbsd-pkg-add.sh runs
        result, work = self._run_openbsd_pkg_add(installs_on_call=99)
        # THEN it fails the step after three tries per mirror, naming what is missing.
        self.assertEqual(result.returncode, 1)
        self.assertIn("still missing: fake-meson", result.stderr)
        self.assertEqual(len((work / "log").read_text(encoding="utf-8").splitlines()), 6)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_openbsd_package_install_fails_when_a_library_is_missing(self) -> None:
        # GIVEN every command installs but a required pkg-config module never appears, as when
        # the JPEG package was asked for under a name OpenBSD does not have
        # WHEN ci-openbsd-pkg-add.sh runs
        result, _ = self._run_openbsd_pkg_add(installs_on_call=1, modules_present=False)
        # THEN it fails the step naming the module, rather than letting meson skip the worker.
        self.assertEqual(result.returncode, 1)
        self.assertIn("still missing: pkg-config:fake-jpeg", result.stderr)

    def test_ccache_is_installed_before_the_ccache_action_runs(self) -> None:
        # GIVEN ccache-action v1.2.24 installs a missing ccache without refreshing the package
        # index, which fails on a GitHub host runner (PR #584: "Failed to install ccache via
        # package manager", exit code 100), and GitHub's Ubuntu images do not ship ccache.
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            section = path.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
            headers = list(re.finditer(r"^  ([A-Za-z0-9_-]+):\n", section, re.MULTILINE))
            for index, header in enumerate(headers):
                job = section[header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(section)]
                action = job.find("uses: hendrikmuhs/ccache-action@")
                if action < 0:
                    continue
                with self.subTest(workflow=path.name, job=header.group(1)):
                    # WHEN the steps before the action's own step are read, comments left out
                    before = job[: job.rfind("\n      - ", 0, action)]
                    commands = "\n".join(
                        line for line in before.splitlines() if not line.lstrip().startswith("#")
                    )
                    # THEN an earlier step installs ccache with the package manager, so the action
                    # finds it and installs nothing.
                    self.assertRegex(commands, r"\b(apt-get|dnf|zypper|apk)\b[^\n]*\b(install|add)\b")
                    self.assertRegex(commands, r"(?m)(^|\s)ccache(\s*\\?$|\s)")

    def test_each_supported_ubuntu_and_opensuse_release_reports_its_own_check(self) -> None:
        # GIVEN the main ruleset requires checks by exact name, and a matrix job with no
        # `name` reports "<job> (<values>)" for each leg, which matches none of them.
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        ubuntu = workflow.split("\n  ubuntu-build-and-test:")[1].split("\n  ubuntu-interim-build-and-test:")[0]
        opensuse = workflow.split("\n  opensuse-build-and-test:")[1].split("\n  freebsd-build-and-test:")[0]

        # WHEN the Ubuntu and OpenSUSE matrices are read
        # THEN each leg reports the check its matrix names, one leg keeping the required name.
        for job in (ubuntu, opensuse):
            self.assertIn("    name: ${{ matrix.check }}\n", job)
            self.assertIn("fail-fast: false", job)
        # AND Ubuntu runs on each LTS runner image by its release, never on ubuntu-latest,
        # so a label migration cannot drop a release unnoticed (ADR-0650). 26.04 is the only
        # LTS built and tested; 24.04 is packaged only (ADR-0742).
        self.assertIn("runs-on: ${{ matrix.runner }}", ubuntu)
        self.assertNotIn("ubuntu-latest", ubuntu)
        self.assertIn("- check: ubuntu-build-and-test\n            runner: ubuntu-26.04\n", ubuntu)
        self.assertNotIn("ubuntu-24.04", ubuntu)
        # AND each leg keeps its own compiler cache and artifact.
        self.assertIn("key: ccache-linux-ci-${{ matrix.release }}-${{ github.run_id }}", ubuntu)
        self.assertIn("name: merovingian-linux-ubuntu${{ matrix.release }}-${{ github.sha }}", ubuntu)
        # AND OpenSUSE runs Tumbleweed under the required name and Leap 16.0 beside it, Leap
        # taking maintenance updates rather than a distribution upgrade.
        self.assertIn("- check: opensuse-build-and-test\n            image: opensuse/tumbleweed\n", opensuse)
        self.assertIn("- check: opensuse-leap-build-and-test\n            image: opensuse/leap:16.0\n", opensuse)
        self.assertIn("zypper --non-interactive ${{ matrix.sync }}", opensuse)
        self.assertIn('if [ "${attempt}" = 3 ]; then', opensuse)

    def test_build_and_test_runs_on_exactly_the_supported_platforms(self) -> None:
        # GIVEN the owner's build-and-test list (ADR-0742): RHEL 10, openSUSE Leap 16 and
        # Tumbleweed, Fedora 44 and 45, Ubuntu 26.04 and 26.10, Debian 13, FreeBSD 15,
        # OpenBSD and NetBSD.
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the container images, runner images and VM releases the jobs build on are read
        images = set(re.findall(r"(?m)^\s+image: ([a-z][^\s$]*)$", workflow))
        images |= {f"fedora:{release}" for release in re.findall(r"fedora:([0-9]+)", workflow)}
        runners = set(re.findall(r"(?m)^\s+runner: (ubuntu-[0-9.]+)$", workflow))

        # THEN they are exactly that list, and no job builds on a moving tag
        self.assertEqual(
            images,
            {
                "ubuntu:26.10",
                "fedora:44",
                "fedora:45",
                "debian:trixie",
                "almalinux:10",
                "opensuse/tumbleweed",
                "opensuse/leap:16.0",
            },
        )
        self.assertEqual(runners, {"ubuntu-26.04"})
        for moving in ("ubuntu:rolling", "fedora:latest", "debian:latest", "debian:stable"):
            self.assertNotIn(f"image: {moving}", workflow)
        self.assertNotIn("fedora:latest", workflow)
        # AND FreeBSD is pinned to its 15.x line, beside the OpenBSD and NetBSD VM jobs.
        freebsd = workflow.split("\n  freebsd-build-and-test:")[1].split("\n  openbsd-build-and-test:")[0]
        self.assertIn("release: '15'\n", freebsd)
        for job in ("openbsd-build-and-test:", "netbsd-build-and-test:"):
            self.assertIn(f"\n  {job}\n", workflow)

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

    def test_real_listener_coverage_job_enforces_link_time_hardening_and_live_request_serving(self) -> None:
        # GIVEN the repository CI workflow.
        self.assertTrue(CI_WORKFLOW.is_file(), "CI workflow is missing")
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        # WHEN production-milestone.md's "real listener coverage in CI" and
        # "platform-specific hardening enforcement" gates are checked.
        # THEN a dedicated job builds the hardened release profile, statically
        # enforces link-time hardening on every shipped binary (a check that
        # needs no live process, so it runs regardless of root/capability
        # constraints), grants the capability the runtime hardening self-check
        # needs to run non-root, and then actually executes the scenario that
        # spawns the real merovingian-server binary, serves a live HTTP
        # request over a real socket, and confirms clean shutdown on SIGTERM —
        # rather than merely building the binary and never proving it serves.
        self.assertIn("ubuntu-hardened-listener-coverage:", workflow)
        self.assertIn("--profile hardened", workflow)
        self.assertIn("check-elf-hardening.sh", workflow)
        self.assertIn("setcap cap_setpcap+ep", workflow)
        self.assertIn('"[startup][binary]" --success', workflow)


    def test_netbsd_jobs_link_the_base_openssl_that_curl_and_libpq_use(self) -> None:
        # GIVEN the CI and packages workflows and the NetBSD pkgsrc scaffold.
        packages = (REPO_ROOT / ".github" / "workflows" / "packages.yml").read_text(encoding="utf-8")
        makefile = (REPO_ROOT / "packaging" / "netbsd" / "Makefile").read_text(encoding="utf-8")
        workflows = {"ci.yml": CI_WORKFLOW.read_text(encoding="utf-8"), "packages.yml": packages}

        # WHEN the NetBSD package installs are inspected.
        # THEN none installs pkgsrc's openssl, and each removes it if the image
        # has it: pkgsrc's curl and postgresql17-client link NetBSD's base
        # OpenSSL (libssl.so.16), so building against pkgsrc's (libssl.so.3)
        # loads two OpenSSLs in one process, which werror's --fatal-warnings
        # link rightly refuses.
        for name, workflow in workflows.items():
            installs = [line for line in workflow.splitlines() if "install_packages clang" in line]
            self.assertTrue(installs, f"{name}: no NetBSD package install found")
            for line in installs:
                self.assertNotIn(" openssl ", f" {line.strip()} ", f"{name}: {line.strip()}")
            self.assertEqual(
                workflow.count("pkg_delete openssl"),
                len(installs),
                f"{name}: every NetBSD job must remove a preinstalled pkgsrc openssl",
            )
        # AND the pkgsrc scaffold leaves the OpenSSL choice to buildlink3
        # rather than forcing the pkgsrc package.
        self.assertNotIn("DEPENDS+=       openssl", makefile)
        self.assertIn('.include "../../security/openssl/buildlink3.mk"', makefile)
        # AND the developer bootstrap does not install it on NetBSD either.
        setup = (REPO_ROOT / "scripts" / "setup-dev-env.sh").read_text(encoding="utf-8")
        pkgin_packages = setup.split("        pkgin)")[1].split(";;")[0]
        self.assertNotIn(" openssl ", pkgin_packages)

    def test_rhel_job_retries_broken_mirror_metadata(self) -> None:
        # GIVEN the AlmaLinux 10 build-and-test job, whose mirrors sometimes answer with
        # broken repository metadata ("repomd.xml parser error"), failing the job before
        # anything is built (PR #545: AppStream, then BaseOS).
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        job = workflow.split("  rhel-build-and-test:")[1].split("\n  opensuse-build-and-test:")[0]
        install = job.split("- name: Install EPEL and build dependencies")[1].split("- uses: actions/checkout")[0]

        # WHEN its dependency step runs
        # THEN dnf is retried with the cached metadata cleared, as the RPM package job
        # does, and the step still fails once the attempts run out.
        self.assertIn("for attempt in 1 2 3; do", install)
        self.assertIn("dnf clean metadata", install)
        self.assertIn('if [ "${attempt}" = 3 ]; then', install)
        self.assertIn("exit 1", install)

if __name__ == "__main__":
    unittest.main()
