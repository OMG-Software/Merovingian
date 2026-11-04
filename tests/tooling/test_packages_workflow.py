#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "packages.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"
GATE_SCRIPT = "scripts/check-startup-hardening-gate.sh"

# Every script that builds a shipped artifact with a bare `meson setup`. The RPM
# specs are not listed: the distribution `%meson` macro pins its own buildtype
# and supplies optimisation and FORTIFY flags through `%optflags`.
PACKAGING_SCRIPTS = (
    "scripts/build-deb.sh",
    "scripts/build-freebsd-pkg.sh",
    "scripts/build-netbsd-pkg.sh",
    "scripts/build-openbsd-pkg.sh",
    "scripts/build-static-linux.sh",
)


def job_text(workflow: str, job: str) -> str:
    """Return one top-level job's text, from its key to the next top-level job."""
    pattern = r"^  " + re.escape(job) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
    match = re.search(pattern, workflow, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"job {job} is missing from the packages workflow")
    return match.group(1)


def meson_setup_commands(text: str) -> list[str]:
    """Return each `meson setup` invocation with its continuation lines joined."""
    joined = re.sub(r"\\\r?\n", " ", text)
    return [line for line in joined.splitlines() if "meson setup" in line]


def dockerfile_stages(text: str) -> list[str]:
    """Split a Dockerfile into its build stages, one string per FROM."""
    stages = re.split(r"(?m)^(?=FROM\s)", text)
    return [stage for stage in stages if stage.startswith("FROM")]


def workflow_job(workflow: str, job: str) -> str:
    """Return the text of one top-level job in a workflow file."""
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    if match is None:
        raise AssertionError(f"workflow job {job} is missing")
    return match.group(1)


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
            "scripts/build-rhel-rpm.sh",
            "scripts/build-opensuse-rpm.sh",
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
            "needs: [deb, static-linux-fallback, rpm, freebsd-pkg, openbsd-pkg, netbsd-pkg, netbsd-pkg-retry, debian-pkg, rhel-rpm, opensuse-rpm]",
            workflow,
        )
        # The retry runs on netbsd-pkg's real result. It can read .result because
        # no BSD job masks its failure with continue-on-error any more (ADR-0502).
        self.assertIn(
            "if: always() && needs.netbsd-pkg.result == 'failure'",
            workflow,
        )
        self.assertNotIn("build_succeeded", workflow)
        self.assertIn("merovingian-*-linux-static-x86_64.tar.gz", workflow)

    def test_every_bsd_package_job_is_required_and_cannot_fail_quietly(self) -> None:
        # GIVEN the package workflow and the jobs that build the BSD packages.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN each job's own text is read (up to the next top-level job).
        for job in ("freebsd-pkg", "openbsd-pkg", "netbsd-pkg", "netbsd-pkg-retry"):
            text = job_text(workflow, job)

            # THEN no job-level continue-on-error masks its failure. A step-level
            # one is indented deeper and is not matched here.
            self.assertIsNone(
                re.search(r"^    continue-on-error:", text, re.MULTILINE),
                f"{job}: continue-on-error would let a failed BSD package pass (ADR-0502)",
            )

        # AND the staged NetBSD package is required: a missing artifact stops staging
        # rather than publishing a release without it.
        stage = job_text(workflow, "stage-package-assets")
        netbsd_download = stage.split("name: netbsd-package", 1)[0].rsplit("- uses:", 1)[1]
        self.assertNotIn("continue-on-error", netbsd_download)
        self.assertNotIn('[ -f "$f" ] && mv', stage)

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
            "scripts/build-rhel-rpm.sh": f'VERSION="{version}"',
            "scripts/build-opensuse-rpm.sh": f'VERSION="{version}"',
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
            "packaging/rhel/merovingian.spec": f"Version:        {version}",
            "packaging/opensuse/merovingian.spec": f"Version:        {version}",
            "packaging/netbsd/Makefile": f"merovingian-{version}",
        }
        for path, expected in expected_versions.items():
            with self.subTest(path=path):
                content = (REPO_ROOT / path).read_text(encoding="utf-8")
                self.assertIn(expected, content)
                if path.endswith(".spec"):
                    # THEN a spec carries exactly one Version tag: rpm uses the last one, so a
                    # stale second tag (left by a merge) silently builds the wrong version.
                    tags = [line for line in content.splitlines() if line.startswith("Version:")]
                    self.assertEqual(len(tags), 1, f"{path} has Version tags {tags}")

    def test_linux_distro_package_jobs_exist(self) -> None:
        # GIVEN the package publication workflow.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Debian, RHEL-compatible, and OpenSUSE ship installable packages.
        # THEN each has a dedicated packaging job with SLSA attestation, and the
        # new artifacts are included in the rolling-latest publish step.
        for job in ("debian-pkg:", "rhel-rpm:", "opensuse-rpm:"):
            self.assertIn(job, workflow)
        self.assertIn("sh scripts/build-deb.sh", workflow)
        self.assertIn("sh scripts/build-rhel-rpm.sh", workflow)
        self.assertIn("sh scripts/build-opensuse-rpm.sh", workflow)
        self.assertIn("name: debian-package", workflow)
        self.assertIn("name: rhel-rpm-package", workflow)
        self.assertIn("name: opensuse-rpm-package", workflow)
        # THEN OpenSUSE-specific package names appear in the install step.
        self.assertIn("libopenssl-devel", workflow)
        self.assertIn("libjpeg8-devel", workflow)
        # THEN EPEL is bootstrapped before the RHEL job installs its packages.
        self.assertIn("epel-release", workflow)

    def test_rhel_dependency_install_retries_a_bad_mirror_answer(self) -> None:
        # GIVEN the RHEL-compatible packaging job.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "rhel-rpm")

        # WHEN its dnf install meets a broken mirror answer (PR #542: "Failed to download
        # metadata for repo 'extras': repomd.xml parser error").
        # THEN the install is retried with the cached repository metadata cleared, and the
        # step still fails once the attempts run out rather than going on to the build.
        self.assertRegex(job, r"for attempt in 1 2 3; do")
        self.assertIn("dnf clean metadata", job)
        self.assertRegex(job, r'if \[ "\$\{?attempt\}?" = 3 \]; then\s+exit 1')

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

    def test_bsds_the_self_check_can_pass_request_full_relro(self):
        # The self-check requires BIND_NOW, and the packaging scripts pass only
        # -pie, so without this a FreeBSD or OpenBSD server refuses to start.
        meson_build = (REPO_ROOT / "meson.build").read_text(encoding="utf-8")
        self.assertIn(
            "if host_machine.system() in ['linux', 'freebsd', 'openbsd']\n"
            "  hardening_link_flags += relro_now_flags",
            meson_build,
        )

    def test_freebsd_package_lists_the_files_it_ships(self) -> None:
        # GIVEN pkg-create(8) packages only what a plist or manifest lists, so a package
        # built from a staged tree with neither is a valid archive holding no files: every
        # FreeBSD package up to 0.12.67 was about 1 KB, and CI passed each of them.
        script = (REPO_ROOT / "scripts" / "build-freebsd-pkg.sh").read_text(encoding="utf-8")
        create = script.split("pkg create")[1].split("\n\n")[0]

        # WHEN the script creates the package
        # THEN it passes a plist generated from the staged tree, in the --metadata form:
        # pkg-create(8) documents --plist only there, not alongside --manifest. Paths
        # resolve from the staging root because pkg appends the manifest's /usr/local
        # prefix itself.
        self.assertIn('--metadata "${METADATA}"', create)
        self.assertNotIn("--manifest", create)
        self.assertIn('"${METADATA}/+MANIFEST"', script)
        self.assertIn('--plist "${PLIST}"', create)
        self.assertIn('--root-dir "${PWD}/${STAGING}"', create)
        self.assertNotIn('/usr/local"', create)
        self.assertRegex(script, r"find \. -type f")

        # AND each file is owned by root whoever ran the build, since an entry with no
        # owner keeps the build user's.
        self.assertIn("@(root,wheel,", script)

        # AND the script fails when the built package lacks anything an install needs.
        self.assertIn('pkg info -l -F "${PACKAGE}"', script)
        for path in (
            "/usr/local/bin/merovingian-server",
            "/usr/local/bin/merovingian-db-migrate",
            "/usr/local/libexec/merovingian/merovingian-fed-worker",
            "/usr/local/libexec/merovingian/merovingian-thumbnail-worker",
            "/usr/local/etc/rc.d/merovingian",
            "/usr/local/etc/merovingian/merovingian.conf.sample",
        ):
            with self.subTest(path=path):
                self.assertIn(path, script)

    def test_freebsd_package_is_installed_and_booted_before_it_is_published(self) -> None:
        # GIVEN the FreeBSD packaging job, whose package nothing has ever installed.
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "freebsd-pkg")
        steps = job.split("- name: Attest FreeBSD package")[0]

        # WHEN the VM has built the package
        # THEN it installs that package as an operator would and boots the installed server
        # through the startup hardening gate as an unprivileged user, before attesting it.
        self.assertIn("set -e", steps)
        self.assertIn("pkg add ./merovingian-*.pkg", steps)
        self.assertIn(GATE_SCRIPT.rsplit("/", maxsplit=1)[-1], steps)
        self.assertRegex(steps, r"su -m nobody -c .*/usr/local/bin/merovingian-server")

    def test_fedora_rpm_is_built_for_each_supported_release(self) -> None:
        # GIVEN an RPM installs only on the Fedora release it was built on, because its
        # sonames come from that release: when fedora:latest moved to Fedora 45 and OpenSSL
        # 4, the only RPM published stopped installing on Fedora 44 ("nothing provides
        # libcrypto.so.4").
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        job = workflow_job(workflow, "rpm")

        # WHEN the job's matrix is read
        # THEN it builds on a pinned Fedora 44 and on whatever fedora:latest is now.
        self.assertIn("container: ${{ matrix.image }}", job)
        self.assertIn("image: fedora:44", job)
        self.assertIn("image: fedora:latest", job)

        # AND one bad release does not cancel the other's build.
        self.assertIn("fail-fast: false", job)

        # AND the two builds keep separate compiler caches and separate artifacts.
        self.assertIn("key: ccache-rpm-${{ matrix.artifact }}-${{ github.run_id }}", job)
        self.assertIn("name: ${{ matrix.artifact }}", job)

        # AND both reach the published assets, under distinct dist-tagged file names.
        stage = workflow_job(workflow, "stage-package-assets")
        for artifact in ("rpm-package-fc44", "rpm-package-latest"):
            with self.subTest(artifact=artifact):
                self.assertIn(f"artifact: {artifact}", job)
                self.assertIn(f"name: {artifact}", stage)

    def test_each_fedora_rpm_is_installed_and_booted_before_it_is_attested(self) -> None:
        # GIVEN each Fedora RPM is built in the release it is published for.
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "rpm")
        before_attest = job.split("- name: Attest RPM package")[0]

        # WHEN the build has finished
        # THEN the job installs the RPM as an operator would and boots the installed server
        # through the startup hardening gate, as the Debian package jobs do.
        self.assertIn("dnf install -y ./merovingian-*.rpm", before_attest)
        self.assertIn("--bounding-set=-all", before_attest)
        self.assertIn(f"{GATE_SCRIPT} /usr/bin/merovingian-server", before_attest)

    def test_the_required_fedora_rpm_check_covers_every_image(self) -> None:
        # GIVEN the main ruleset requires a check called "Fedora RPM package", and a matrix
        # job reports one check per image, none of them with that name.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: Fedora RPM package (${{ matrix.image }})", workflow_job(workflow, "rpm"))

        # WHEN the job reporting the required name runs
        job = workflow_job(workflow, "rpm-all-images")

        # THEN it reports under that name, even when a leg failed, and passes only when
        # every leg succeeded.
        self.assertIn("name: Fedora RPM package\n", job)
        self.assertIn("needs: rpm", job)
        self.assertIn("if: always()", job)
        self.assertIn("${{ needs.rpm.result }}", job)
        self.assertIn('test "${RESULT}" = success', job)

    def test_every_packaging_script_configures_a_release_buildtype(self) -> None:
        # GIVEN Meson builds `debug` (-O0) when no buildtype is given, and
        # glibc only honours _FORTIFY_SOURCE when optimising, so a debug
        # binary fails the FORTIFY_SOURCE startup check and refuses to start.
        for script in PACKAGING_SCRIPTS:
            with self.subTest(script=script):
                content = (REPO_ROOT / script).read_text(encoding="utf-8")

                # WHEN the script configures the build that it packages.
                commands = meson_setup_commands(content)

                # THEN every configure step asks for a release buildtype.
                self.assertTrue(commands, f"{script} has no meson setup step")
                for command in commands:
                    self.assertIn("--buildtype=release", command)

    def test_docker_base_images_are_pinned_by_digest(self) -> None:
        # GIVEN the published container recipe.
        self.assertTrue(DOCKERFILE.is_file(), "Dockerfile is missing")
        stages = dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))

        # WHEN a stage names its base image.
        # THEN the image is pinned to an immutable digest, not a mutable tag.
        self.assertGreaterEqual(len(stages), 2, "Dockerfile must build in a separate stage")
        for stage in stages:
            from_line = stage.splitlines()[0]
            with self.subTest(from_line=from_line):
                self.assertRegex(from_line, r"^FROM \S+@sha256:[0-9a-f]{64}(\s|$)")

    def test_docker_build_stage_configures_a_hardened_release_build(self) -> None:
        # GIVEN the Dockerfile build stage.
        build_stage = dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))[0]

        # WHEN it configures Meson.
        commands = meson_setup_commands(build_stage)

        # THEN the build is a hardened release build without test targets, so
        # the shipped server passes its own startup hardening gate.
        self.assertEqual(len(commands), 1, "build stage must configure Meson exactly once")
        for flag in ("--buildtype=release", "-Dhardening=true", "-Dbuild_tests=false"):
            with self.subTest(flag=flag):
                self.assertIn(flag, commands[0])

    def test_docker_build_stage_installs_every_linked_library(self) -> None:
        # GIVEN the server links libpq and OpenSSL, and the thumbnail worker is
        # only built when libpng and libturbojpeg are found.
        build_stage = dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))[0]

        # WHEN the build stage installs its development packages.
        # THEN every library the shipped binaries link is present.
        for package in (
            "libpq-dev",
            "libssl-dev",
            "libsodium-dev",
            "libcurl4-openssl-dev",
            "libpng-dev",
            "libturbojpeg0-dev",
        ):
            with self.subTest(package=package):
                self.assertRegex(build_stage, rf"(?m)^\s+{re.escape(package)}\b")

    def test_docker_runtime_stage_ships_both_workers_and_their_libraries(self) -> None:
        # GIVEN the Dockerfile runtime stage.
        runtime_stage = dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))[-1]

        # WHEN it copies binaries out of the build stage.
        # THEN the server, the federation worker it spawns by default, and the
        # thumbnail worker are all shipped at their libexec paths.
        for binary in (
            "/usr/bin/merovingian-server",
            "/usr/libexec/merovingian/merovingian-fed-worker",
            "/usr/libexec/merovingian/merovingian-thumbnail-worker",
        ):
            with self.subTest(binary=binary):
                self.assertRegex(runtime_stage, rf"(?m)^COPY --from=build \S*{re.escape(binary)} {re.escape(binary)}$")

        # THEN the runtime libraries those binaries link are installed.
        for package in ("libpq5", "libturbojpeg0", "libsodium23"):
            with self.subTest(package=package):
                self.assertRegex(runtime_stage, rf"\b{re.escape(package)}\b")

        # THEN the image build fails if any shipped binary has an unresolved
        # shared library, rather than shipping a binary that cannot start.
        self.assertIn("ldd", runtime_stage)
        self.assertIn("not found", runtime_stage)

    def test_docker_runtime_stage_creates_its_user_with_tools_the_base_image_ships(self) -> None:
        # GIVEN the Dockerfile runtime stage, built on debian:trixie-slim, which
        # ships passwd (groupadd/useradd) but not the adduser package.
        runtime_stage = dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))[-1]

        # WHEN it creates the unprivileged service account.
        # THEN it uses groupadd/useradd, never addgroup/adduser, which would
        # exit 127 and fail the image build.
        self.assertRegex(runtime_stage, r"\bgroupadd --system merovingian\b")
        self.assertRegex(runtime_stage, r"\buseradd --system\b")
        self.assertNotRegex(runtime_stage, r"\b(addgroup|adduser)\b")

    def test_deb_conffiles_name_only_files_the_package_installs(self) -> None:
        # GIVEN the Debian conffiles list and the script that stages the package.
        conffiles = [
            line.strip()
            for line in (REPO_ROOT / "packaging" / "deb" / "conffiles").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        build_script = (REPO_ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")

        # WHEN dpkg unpacks each conffile as `<path>.dpkg-new`.
        # THEN every entry is a file the script installs, not a directory:
        # a directory entry is unpacked as `/etc/merovingian.dpkg-new`, so the
        # files inside it have no parent and the install fails.
        self.assertTrue(conffiles, "conffiles is empty")
        for path in conffiles:
            with self.subTest(path=path):
                self.assertRegex(path, r"^/etc/merovingian/[^/]+$")
                self.assertIn(f'"${{STAGING}}{path}"', build_script)

    def test_deb_depends_on_the_tools_its_maintainer_scripts_run(self) -> None:
        # GIVEN the Debian maintainer scripts and the control file the build writes.
        postinst = (REPO_ROOT / "packaging" / "deb" / "postinst").read_text(encoding="utf-8")
        build_script = (REPO_ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        depends = re.search(r"(?m)^Depends: (.*)$", build_script)
        self.assertIsNotNone(depends, "build-deb.sh writes no Depends line")
        packages = {entry.strip().split(" ")[0] for entry in depends.group(1).split(",")}

        # WHEN postinst creates the service account with adduser, which is not
        # essential and is absent from container base images.
        uses_adduser = re.search(r"(?m)^\s*adduser\b", postinst) is not None

        # THEN the package depends on adduser, so installing it pulls adduser in.
        self.assertTrue(uses_adduser, "postinst no longer uses adduser; update this test")
        self.assertIn("adduser", packages)

    def test_deb_does_not_ship_vendored_subproject_files(self) -> None:
        # GIVEN the Debian package build script.
        build_script = (REPO_ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")

        # WHEN it installs the build into the staging tree.
        installs = re.findall(r"(?m)^meson install .*$", build_script)

        # THEN the vendored sqlite3 archive and headers are skipped.
        self.assertEqual(len(installs), 1)
        self.assertIn("--skip-subprojects", installs[0])

    def test_packaged_server_startup_gate_runs_in_ci(self) -> None:
        # GIVEN the startup hardening gate script.
        self.assertTrue((REPO_ROOT / GATE_SCRIPT).is_file(), f"{GATE_SCRIPT} is missing")
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN CI builds the Debian packages.
        # THEN each job installs the package and runs the gate against the
        # installed binary as an unprivileged user with no bounding set.
        for job in ("deb", "debian-pkg"):
            with self.subTest(job=job):
                body = workflow_job(workflow, job)
                self.assertIn("apt-get install -y --no-install-recommends ./merovingian_", body)
                self.assertIn("--bounding-set=-all", body)
                self.assertIn(f"{GATE_SCRIPT} /usr/bin/merovingian-server", body)

        # WHEN CI builds the Docker image.
        # THEN it runs the gate inside the image with every capability dropped,
        # as the image's own unprivileged user.
        body = workflow_job(workflow, "docker-image")
        self.assertIn("docker build", body)
        self.assertIn("--cap-drop=ALL", body)
        self.assertIn("--security-opt=no-new-privileges", body)
        self.assertIn("check-startup-hardening-gate.sh", body)
        self.assertIn("/usr/bin/merovingian-server", body)


if __name__ == "__main__":
    unittest.main()
