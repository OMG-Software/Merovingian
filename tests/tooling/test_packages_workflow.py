#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
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


def publish_latest_script() -> str:
    """Return the publish-latest step's run script, ready for bash.

    The one expression GitHub would substitute, the run's commit in the release
    notes, is replaced with `$GITHUB_SHA`; any other is an error, so a new one
    cannot reach bash as a literal `${{`.
    """
    job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "publish-latest")
    match = re.search(
        r"(?m)^      - name: Publish rolling latest release\n(?:^        (?!run:).*\n)*^        run: \|\n"
        r"((?:^          .*\n|^\s*\n)+)",
        job,
    )
    if match is None:
        raise AssertionError("publish-latest has no 'Publish rolling latest release' run step")
    script = textwrap.dedent(match.group(1)).replace("${{ github.sha }}", "${GITHUB_SHA}")
    if "${{" in script:
        raise AssertionError("the publish script uses an expression this test does not substitute")
    return script


def write_fake_gh(path: Path) -> None:
    """Write a fake `gh` that logs each call and answers from FAKE_* variables."""
    path.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$GH_LOG"\n'
        'case "$1 $2" in\n'
        '  "release delete") exit 0 ;;\n'
        '  "release create") [ "$FAKE_CREATE" != FAIL ] || exit 1 ;;\n'
        '  "api -X")\n'
        '    case "$3 $4" in\n'
        '      "PATCH repos/owner/repo/git/refs/tags/latest"|"POST repos/owner/repo/git/refs") ;;\n'
        "      *) exit 98 ;;\n"
        "    esac ;;\n"
        '  "api repos/"*/releases/tags/latest)\n'
        '    case "$FAKE_RELEASE" in\n'
        "      1) echo 42 ;;\n"
        '      0) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;\n'
        '      *) echo "gh: Bad Gateway (HTTP 502)" >&2; exit 1 ;;\n'
        "    esac ;;\n"
        '  "api repos/"*/git/matching-refs/tags/latest)\n'
        '    [ "$FAKE_TAG" = FAIL ] && exit 1\n'
        '    printf \'%s\\n\' "$FAKE_TAG" ;;\n'
        '  "api repos/"*/commits/latest)\n'
        '    [ "$FAKE_COMMIT" = FAIL ] && exit 1\n'
        '    printf \'%s\\n\' "$FAKE_COMMIT" ;;\n'
        '  "api repos/"*/compare/"$GITHUB_SHA"...main) printf \'%s\\n\' "$FAKE_BUILD_ON_MAIN" ;;\n'
        '  "api repos/"*/compare/*...main) printf \'%s\\n\' "$FAKE_ON_MAIN" ;;\n'
        '  "api repos/"*/compare/*) printf \'%s\\n\' "$FAKE_STATUS" ;;\n'
        "  *) echo \"unexpected gh call: $*\" >&2; exit 99 ;;\n"
        "esac\n",
        encoding="utf-8",
        newline="\n",
    )
    path.chmod(0o755)


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
            "needs: [deb, static-linux-fallback, rpm, freebsd-pkg, openbsd-pkg, netbsd-pkg, debian-pkg, rhel-rpm, opensuse-rpm]",
            workflow,
        )
        # No job retries netbsd-pkg: nothing could make a failed first build pass (ADR-0502).
        self.assertNotIn("netbsd-pkg-retry", workflow)
        self.assertNotIn("build_succeeded", workflow)
        self.assertIn("merovingian-*-linux-static-x86_64.tar.gz", workflow)

    def test_every_bsd_package_job_is_required_and_cannot_fail_quietly(self) -> None:
        # GIVEN the package workflow and the jobs that build the BSD packages.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN each job's own text is read (up to the next top-level job).
        for job in ("freebsd-pkg", "openbsd-pkg", "netbsd-pkg"):
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
        # GIVEN the rolling package publication job.
        self.assertTrue(PACKAGES_WORKFLOW.is_file(), "packages workflow is missing")
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "publish-latest")

        # WHEN the main branch replaces the rolling latest release.
        # THEN every gh call names the repository explicitly instead of relying on
        # checkout state, and the release is tagged at the commit it was built from.
        self.assertIn("REPOSITORY: ${{ github.repository }}", job)
        commands = re.sub(r"\\\n\s*", " ", job)
        for verb in ("delete", "create"):
            self.assertRegex(commands, rf'gh release {verb} latest[^\n]*--repo "\$\{{REPOSITORY\}}"')
        api_paths = re.findall(r'gh api (?:-X [A-Z]+ )?"([^"]*)"', commands)
        self.assertTrue(api_paths, "the publish step makes no gh api call")
        for path in api_paths:
            self.assertTrue(path.startswith("repos/${REPOSITORY}/"), path)
        self.assertRegex(commands, r'gh release create latest[^\n]*--target "\$\{GITHUB_SHA\}"')

    def test_every_publish_of_latest_waits_for_the_one_before_it(self) -> None:
        # GIVEN the rolling package publication job.
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "publish-latest")

        # WHEN two pushes to main reach it at once.
        # THEN one fixed group holds them in turn, and a publish already deleting
        # the old release is never cancelled before it creates the new one (ADR-0850).
        concurrency = re.search(r"(?m)^    concurrency:\n((?:^      .*\n)+)", job)
        self.assertIsNotNone(concurrency, "publish-latest has no job-level concurrency group")
        self.assertIn("group: packages-publish-latest\n", concurrency.group(1))
        self.assertIn("cancel-in-progress: false\n", concurrency.group(1))
        self.assertNotIn("${{", concurrency.group(1), "the group must be one name for every run")

    def test_publish_latest_never_replaces_a_release_built_from_a_newer_commit(self) -> None:
        # GIVEN the publish step's own script and a fake gh that records each call.
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        run = publish_latest_script()
        this_commit = "b" * 40
        published = "a" * 40
        # Each case: whether main holds this run's commit, release ("1" exists, "0" a 404, "ERR" another
        # failure), tag ("1", "0" or "FAIL"), the commit the tag names ("FAIL" a failed call), its comparison with
        # this run and with main, then the exit status and what the step may do: publish, delete the release, and
        # move the tag to this run's commit or make it. The tag is never deleted.
        cases = (
            ("nothing published yet", "ahead", "0", "0", "", "", "", 0, "publish make-tag"),
            ("this run is newer", "ahead", "1", "1", published, "ahead", "", 0, "publish delete-release move-tag"),
            ("this run is main's tip", "identical", "1", "1", published, "ahead", "", 0, "publish delete-release move-tag"),
            ("a re-run of the same commit", "ahead", "1", "1", published, "identical", "", 0, "publish delete-release move-tag"),
            ("this run is older, main holds the newer", "ahead", "1", "1", published, "behind", "ahead", 0, ""),
            ("this run is older, main is at the newer", "ahead", "1", "1", published, "behind", "identical", 0, ""),
            ("main was reset behind the published commit", "ahead", "1", "1", published, "behind", "behind", 1, ""),
            ("histories diverged", "ahead", "1", "1", published, "diverged", "", 1, ""),
            ("published commit unreadable", "ahead", "1", "1", "", "ahead", "", 1, ""),
            ("published commit lookup fails", "ahead", "1", "1", "FAIL", "ahead", "", 1, ""),
            ("a leftover tag, this run newer", "ahead", "0", "1", published, "ahead", "", 0, "publish move-tag"),
            ("a leftover tag, this run older", "ahead", "0", "1", published, "behind", "ahead", 1, ""),
            ("a release without its tag", "ahead", "1", "0", "", "", "", 1, ""),
            ("release lookup fails", "ahead", "ERR", "0", "", "", "", 1, ""),
            ("tag lookup fails", "ahead", "1", "FAIL", published, "ahead", "", 1, ""),
            ("main was reset behind this run", "behind", "1", "1", published, "ahead", "", 1, ""),
            ("this run's history was discarded", "diverged", "1", "1", published, "ahead", "", 1, ""),
            ("this run's history was discarded, nothing published", "diverged", "0", "0", "", "", "", 1, ""),
            ("main's answer about this run is unreadable", "", "1", "1", published, "ahead", "", 1, ""),
            # The release is gone and the tag already moved when creating the new one fails: the job fails, and the
            # tag left at this run's commit is what stops an older run (the leftover-tag case above).
            ("the new release cannot be created", "ahead", "1", "1", published, "ahead", "", 1, "publish delete-release move-tag"),
        )
        create_fails = {"the new release cannot be created"}
        for name, build_on_main, release, tag, commit, status, on_main, want_exit, want in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                log = tmp_path / "gh.log"
                write_fake_gh(tmp_path / "gh")
                env = {
                    "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}",
                    "GITHUB_SHA": this_commit,
                    "GITHUB_REF_NAME": "main",
                    "REPOSITORY": "owner/repo",
                    "GH_LOG": str(log),
                    "FAKE_RELEASE": release,
                    "FAKE_TAG": tag,
                    "FAKE_COMMIT": commit,
                    "FAKE_STATUS": status,
                    "FAKE_ON_MAIN": on_main,
                    "FAKE_BUILD_ON_MAIN": build_on_main,
                    "FAKE_CREATE": "FAIL" if name in create_fails else "",
                }

                # WHEN the step runs.
                result = subprocess.run(
                    [bash, "-c", run], cwd=tmp, env=env, capture_output=True, text=True, check=False
                )

                # THEN it publishes only over a tag at the same commit or an ancestor whose
                # build main still holds, and anything it cannot prove stops the job before
                # anything is deleted.
                calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
                self.assertEqual(result.returncode, want_exit, result.stdout + result.stderr)
                created = [call for call in calls if call.startswith("release create latest")]
                done = set()
                if created:
                    done.add("publish")
                    self.assertIn(f"--target {this_commit}", created[0])
                    self.assertIn("--verify-tag", created[0])
                deleted = [call for call in calls if call.startswith("release delete latest")]
                if deleted:
                    done.add("delete-release")
                    self.assertNotIn("--cleanup-tag", deleted[0])
                moved = f"api -X PATCH repos/owner/repo/git/refs/tags/latest -f sha={this_commit} -F force=true --silent"
                made = f"api -X POST repos/owner/repo/git/refs -f ref=refs/tags/latest -f sha={this_commit} --silent"
                if moved in calls:
                    done.add("move-tag")
                if made in calls:
                    done.add("make-tag")
                self.assertFalse([call for call in calls if call.startswith("api -X DELETE")], calls)
                self.assertEqual(done, set(want.split()), calls)
                # The release goes first, then the tag moves, then the release is created on it.
                order = [call for call in calls if call in (moved, made) or call in deleted or call in created]
                self.assertEqual(order, deleted + [call for call in calls if call in (moved, made)] + created, calls)
                # The first call is the check that main holds this run's commit.
                self.assertEqual(calls[:1], [f"api repos/owner/repo/compare/{this_commit}...main --jq .status"])
                if build_on_main in ("ahead", "identical") and tag == "1" and commit not in ("", "FAIL"):
                    self.assertIn(
                        f"api repos/owner/repo/compare/{published}...{this_commit} --jq .status", calls
                    )

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

    def test_openbsd_package_refuses_a_build_without_a_worker(self) -> None:
        # GIVEN build-openbsd-pkg.sh packs whatever the install staged, and meson skips the
        # thumbnail worker without libpng16 and libturbojpeg: asked for as `jpeg-turbo`, a name
        # OpenBSD has no package by, the JPEG library was never installed, and every OpenBSD
        # package shipped without the worker its PLIST lists.
        script = (REPO_ROOT / "scripts" / "build-openbsd-pkg.sh").read_text(encoding="utf-8")
        # WHEN the script's steps between the install and the packing list are read
        check = script.split("--skip-subprojects\n", 1)[1].split("# 2. Stage", 1)[0]
        # THEN it fails unless every binary and both workers were staged, as FreeBSD and NetBSD do.
        for binary in (
            "bin/merovingian-server",
            "bin/merovingian-db-migrate",
            "libexec/merovingian/merovingian-fed-worker",
            "libexec/merovingian/merovingian-thumbnail-worker",
        ):
            self.assertIn(binary, check)
        self.assertIn('if [ ! -x "${STAGE}${PREFIX}/${binary}" ]; then', check)
        self.assertIn("exit 1", check)

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

    def test_bsds_the_self_check_can_pass_request_full_relro_and_pie(self):
        # GIVEN the self-check requires BIND_NOW and PIE, and FreeBSD's clang
        # links neither without being asked, so a FreeBSD or OpenBSD server
        # built without them refuses to start (ADR-0757).
        meson_build = (REPO_ROOT / "meson.build").read_text(encoding="utf-8")
        opening = "if host_machine.system() in ['linux', 'freebsd', 'openbsd']\n"

        # WHEN the hardened link flags for those platforms are read
        self.assertIn(opening, meson_build)
        block = meson_build.split(opening, 1)[1].split("\nendif", 1)[0]

        # THEN they request both -pie and full RELRO
        self.assertIn("hardening_link_flags += ['-pie']", block)
        self.assertIn("hardening_link_flags += relro_now_flags", block)

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

    def test_freebsd_manifest_patch_sets_only_the_package_version(self) -> None:
        # GIVEN the manifest, whose dependencies each carry a minimum version on a line
        # of their own, and the sed expression the build script patches it with. An
        # unanchored expression replaced the first version on every line, so every
        # dependency's minimum became the package's own version.
        sed = shutil.which("sed")
        if sed is None:
            self.skipTest("sed is not available")
        script = (REPO_ROOT / "scripts" / "build-freebsd-pkg.sh").read_text(encoding="utf-8")
        match = re.search(r'^sed "([^"\n]*(?:\\"[^"\n]*)*)" \\\n\s+packaging/freebsd/\+MANIFEST', script, re.MULTILINE)
        self.assertIsNotNone(match, "the manifest patch is not where the test expects it")
        expression = match.group(1).replace('\\"', '"').replace("${VERSION}", "9.8.7")
        manifest = (REPO_ROOT / "packaging" / "freebsd" / "+MANIFEST").read_text(encoding="utf-8")

        # WHEN the script's expression is applied to the manifest.
        patched = subprocess.run(
            [sed, expression], input=manifest, capture_output=True, text=True, check=True
        ).stdout

        # THEN the top-level version is the package's, and every other line, the
        # dependency minimums included, is unchanged.
        self.assertRegex(patched, r'(?m)^version: "9\.8\.7"$')
        original_lines = [line for line in manifest.splitlines() if not line.startswith("version:")]
        patched_lines = [line for line in patched.splitlines() if not line.startswith("version:")]
        self.assertEqual(patched_lines, original_lines)
        self.assertIn('openssl: {origin: security/openssl, version: "3.0.0"}', patched)

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
        # THEN it builds on Fedora 44 and Fedora 45, each pinned by release, so the release
        # CI tests is the one the package is for (ADR-0742).
        self.assertIn("container: ${{ matrix.image }}", job)
        self.assertIn("image: fedora:44", job)
        self.assertIn("image: fedora:45", job)
        self.assertNotIn("fedora:latest", job)

        # AND one bad release does not cancel the other's build.
        self.assertIn("fail-fast: false", job)

        # AND the two builds keep separate compiler caches and separate artifacts.
        self.assertIn("key: ccache-rpm-${{ matrix.artifact }}-${{ github.run_id }}", job)
        self.assertIn("name: ${{ matrix.artifact }}", job)

        # AND both reach the published assets, under distinct dist-tagged file names.
        stage = workflow_job(workflow, "stage-package-assets")
        for artifact in ("rpm-package-fc44", "rpm-package-fc45"):
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

    def test_each_fedora_rpm_leaves_the_livekit_unit_disabled_under_an_enable_everything_preset(self) -> None:
        # GIVEN each Fedora RPM job, whose image has no systemd unless the job installs it.
        job = workflow_job(PACKAGES_WORKFLOW.read_text(encoding="utf-8"), "rpm")
        install_deps = job.split("- name: Install build dependencies")[1].split("- uses:")[0]
        before_attest = job.split("- name: Attest RPM package")[0]

        # WHEN the RPM is installed (ADR-0860)
        # THEN systemd is present, so %systemd_post applies the preset policy; "enable *" is in
        # force for the install; the server's unit coming out enabled proves the policy ran, and
        # the LiveKit unit must still come out disabled.
        self.assertRegex(install_deps, r"(?m)\ssystemd$")
        preset = "printf 'enable *\\n' > /usr/lib/systemd/system-preset/00-merovingian-ci.preset"
        install = "dnf install -y ./merovingian-*.rpm"
        self.assertIn(preset, before_attest)
        self.assertLess(before_attest.index(preset), before_attest.index(install))
        self.assertIn('test "$(systemctl is-enabled merovingian.service)" = enabled', before_attest)
        self.assertIn('test "$(systemctl is-enabled merovingian-livekit.service || true)" = disabled', before_attest)

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
        self.assertIn("if: ${{ always() && github.event_name != 'pull_request' }}", job)
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

    def test_deb_library_dependencies_come_from_the_release_it_was_built_on(self) -> None:
        # GIVEN one build-deb.sh builds the Ubuntu 24.04, 26.04 and rolling packages and the
        # Debian trixie one, and their library package names differ: PR #584's 24.04 package
        # failed to install on "libturbojpeg0", and the rolling one on "libssl3" (ADR-0650).
        build_script = (REPO_ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        depends = re.search(r"(?m)^Depends: (.*)$", build_script)
        self.assertIsNotNone(depends, "build-deb.sh writes no Depends line")

        # WHEN the control file's Depends line is read
        # THEN it names no library package itself: dpkg-shlibdeps derives them from the shipped
        # binaries on the release building the package.
        self.assertEqual(depends.group(1), "adduser, ${SHLIBS_DEPENDS}")
        self.assertRegex(build_script, r"dpkg-shlibdeps -O \$\{ELF_FILES\}")
        # AND an empty result fails the build instead of shipping a package with no library dependencies.
        self.assertIn('if [ -z "${SHLIBS_DEPENDS}" ]; then', build_script)

        # AND every job that runs build-deb.sh installs dpkg-shlibdeps' package.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        for job in ("deb", "debian-pkg"):
            with self.subTest(job=job):
                body = workflow_job(workflow, job)
                self.assertIn("sh scripts/build-deb.sh", body)
                self.assertRegex(body.split("sh scripts/build-deb.sh")[0], r"\bdpkg-dev\b")

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

    def test_each_supported_ubuntu_release_gets_its_own_named_package(self) -> None:
        # GIVEN a .deb installs only on the release whose sonames it was built against
        # (ADR-0650), and the main ruleset requires a check called "Debian package".
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        job = workflow_job(workflow, "deb")

        # WHEN the Ubuntu package matrix is read
        # THEN it builds in each LTS image and the 26.10 interim release, each pinned by
        # release (ADR-0742), one failure not cancelling the others.
        self.assertNotIn("ubuntu:rolling", job)
        for release, image in (("'24.04'", "ubuntu:24.04"), ("'26.04'", "ubuntu:26.04"), ("'26.10'", "ubuntu:26.10")):
            with self.subTest(release=release):
                self.assertIn(f"- release: {release}\n            image: {image}\n", job)
        self.assertIn("container: ${{ matrix.image }}", job)
        self.assertIn("fail-fast: false", job)
        self.assertIn("name: Ubuntu ${{ matrix.release }} package", job)

        # AND the package is named after the release read from the image, after the
        # installed package has booted and before it is attested and uploaded.
        rename = job.index('mv "$f" "${f%.deb}-ubuntu${VERSION_ID}.deb"')
        self.assertLess(job.index("--bounding-set=-all"), rename)
        self.assertLess(rename, job.index("- name: Attest Ubuntu package"))
        self.assertIn(". /etc/os-release", job)
        self.assertIn("name: ubuntu-deb-package-${{ matrix.release }}", job)
        self.assertIn("key: ccache-deb-${{ matrix.release }}-${{ github.run_id }}", job)

        # AND the required check reports under its old name and passes only when every
        # release built.
        aggregate = workflow_job(workflow, "deb-all-releases")
        self.assertIn("name: Debian package\n", aggregate)
        self.assertIn("needs: deb", aggregate)
        self.assertIn("if: ${{ always() && github.event_name != 'pull_request' }}", aggregate)
        self.assertIn("${{ needs.deb.result }}", aggregate)
        self.assertIn('test "${RESULT}" = success', aggregate)

        # AND every release's package is staged for latest.
        stage = workflow_job(workflow, "stage-package-assets")
        for release in ("24.04", "26.04", "26.10"):
            with self.subTest(staged=release):
                self.assertIn(f"name: ubuntu-deb-package-{release}\n", stage)

    def test_opensuse_tumbleweed_and_leap_each_get_their_own_rpm(self) -> None:
        # GIVEN Leap and Tumbleweed ship different library versions (ADR-0650).
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        job = workflow_job(workflow, "opensuse-rpm")

        # WHEN the OpenSUSE package matrix is read
        # THEN Tumbleweed keeps the required check name and its dist tag, Leap 16.0 gets
        # its own, and each leg keeps its own cache and artifact.
        self.assertIn("name: OpenSUSE ${{ matrix.flavour }} RPM package", job)
        # AND the check the ruleset requires comes from an aggregate: a matrix job that a
        # job-level `if` skips reports its unexpanded name, which matches nothing.
        aggregate = workflow_job(workflow, "opensuse-rpm-all-flavours")
        self.assertIn("name: OpenSUSE Tumbleweed RPM\n", aggregate)
        self.assertIn("needs: opensuse-rpm", aggregate)
        self.assertIn("- flavour: Tumbleweed\n            image: opensuse/tumbleweed\n", job)
        self.assertIn("- flavour: Leap 16.0\n            image: opensuse/leap:16.0\n", job)
        self.assertIn("dist: .tumbleweed\n", job)
        self.assertIn("dist: .leap16\n", job)
        self.assertIn("MEROVINGIAN_RPM_DIST: ${{ matrix.dist }}", job)
        self.assertIn("key: ccache-opensuse-rpm-${{ matrix.artifact }}-${{ github.run_id }}", job)
        self.assertIn("name: ${{ matrix.artifact }}", job)
        # AND the dependency step fails once its attempts run out, rather than going on
        # to a build that fails for want of a package.
        self.assertIn('if [ "${attempt}" = 3 ]; then', job)

        # AND both RPMs are staged for latest.
        stage = workflow_job(workflow, "stage-package-assets")
        for artifact in ("opensuse-rpm-package", "opensuse-leap-rpm-package"):
            with self.subTest(artifact=artifact):
                self.assertIn(f"name: {artifact}\n", stage)

        # AND the build script takes the dist tag only in a form rpmbuild cannot misread.
        script = (REPO_ROOT / "scripts" / "build-opensuse-rpm.sh").read_text(encoding="utf-8")
        self.assertIn('DIST="${MEROVINGIAN_RPM_DIST:-.tumbleweed}"', script)
        self.assertIn("*[!a-z0-9.]*)", script)
        self.assertIn('--define "dist ${DIST}"', script)

    def test_a_tagged_release_ships_each_distribution_package(self) -> None:
        # GIVEN a release is published from a v* tag by release.yml (ADR-0597).
        release = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        packages = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the release workflow runs
        # THEN it builds the packages with packages.yml's own jobs, after the tag check.
        self.assertRegex(packages, r"(?m)^  workflow_call:")
        calling = workflow_job(release, "distro-packages")
        self.assertIn("uses: ./.github/workflows/packages.yml", calling)
        self.assertIn("needs: check-tag", calling)

        # AND it passes the secrets on, so packages.yml's signing job can sign for the tag.
        self.assertIn("secrets: inherit", calling)

        # AND it stages nothing of its own: packages.yml stages and signs for a v* tag as
        # for main, so a tag ships exactly what `latest` ships (ADR-0742).
        stage = workflow_job(packages, "stage-package-assets")
        self.assertIn("github.ref == 'refs/heads/main'", stage)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", stage)
        self.assertNotIn("stage-release-assets", release)
        self.assertNotIn("sign-release-assets", release)
        publish = workflow_job(release, "publish-release")
        self.assertIn("- distro-packages", publish)
        self.assertIn("name: signed-packages\n", publish)
        self.assertIn("release-assets/SHA256SUMS", publish)

        # AND publishing latest stays on pushes to main, so a tag never replaces the
        # rolling release.
        self.assertIn("github.ref == 'refs/heads/main'", workflow_job(packages, "publish-latest"))

    def test_latest_and_a_tag_stage_exactly_the_supported_packages(self) -> None:
        # GIVEN the owner's package list (ADR-0742), every package x86_64: RHEL 10, openSUSE
        # Leap 16 and Tumbleweed, Fedora 44 and 45, Ubuntu 24.04, 26.04 and 26.10, Debian
        # 13, static Linux, FreeBSD 15 (.pkg), OpenBSD and NetBSD.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        stage = workflow_job(workflow, "stage-package-assets")

        # WHEN the artifacts staging downloads are read
        downloads = re.findall(
            r"uses: actions/download-artifact@v8\n        with:\n          name: ([A-Za-z0-9._-]+)\n          path: (.+)\n",
            stage,
        )
        staged = {name for name, _ in downloads}

        # THEN they are exactly one per supported platform release
        self.assertEqual(
            staged,
            {
                "rhel-rpm-package",
                "opensuse-leap-rpm-package",
                "opensuse-rpm-package",
                "rpm-package-fc44",
                "rpm-package-fc45",
                "ubuntu-deb-package-24.04",
                "ubuntu-deb-package-26.04",
                "ubuntu-deb-package-26.10",
                "debian-package",
                "static-linux-fallback-package",
                "freebsd-package",
                "openbsd-package",
                "netbsd-package",
            },
        )
        # AND every one lands under its own platform-named file, so nothing is renamed at
        # staging time and no two collide.
        self.assertEqual({path for _, path in downloads}, {"packages/"})
        self.assertNotIn("mv ", stage)
        # AND no package is built on a moving tag, and Debian 12 is not packaged (ADR-0742).
        for moving in ("ubuntu:rolling", "fedora:latest", "debian:bookworm", "debian:12"):
            self.assertNotIn(moving, workflow)

    def test_every_package_file_names_the_platform_it_installs_on(self) -> None:
        # GIVEN every published package must show which platform it is for (ADR-0742).
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN each package job's naming is read
        # THEN the .deb, .pkg and BSD .tgz jobs rename the file after the release they ran on,
        renames = {
            "deb": 'mv "$f" "${f%.deb}-ubuntu${VERSION_ID}.deb"',
            "debian-pkg": 'mv "$f" "${f%.deb}-debian${VERSION_ID}.deb"',
            "freebsd-pkg": 'mv "$f" "${f%.pkg}-freebsd${major}.pkg"',
            "openbsd-pkg": 'mv "$f" "${f%.tgz}-openbsd${release}.tgz"',
            "netbsd-pkg": 'mv "$f" "${f%.tgz}-netbsd${release}.tgz"',
        }
        for job_id, rename in renames.items():
            with self.subTest(job=job_id):
                job = workflow_job(workflow, job_id)
                self.assertIn(rename, job)
                # before the package is attested, so the attested name is the published one.
                self.assertLess(job.index(rename), job.index("uses: actions/attest-build-provenance"))
        self.assertIn('major="$(freebsd-version -u | cut -d. -f1)"', workflow_job(workflow, "freebsd-pkg"))
        # AND every RPM carries a dist tag naming its release.
        self.assertIn("dist: .tumbleweed\n", workflow_job(workflow, "opensuse-rpm"))
        self.assertIn("dist: .leap16\n", workflow_job(workflow, "opensuse-rpm"))
        # AND the FreeBSD package job builds on the 15.x line.
        self.assertIn("release: '15'\n", workflow_job(workflow, "freebsd-pkg"))

    def test_every_package_is_built_with_the_hardened_profile(self) -> None:
        # GIVEN latest and every tagged release ship hardened-profile packages (ADR-0742):
        # the hardened profile is a release build with -Dhardening=true, as
        # scripts/build-linux.sh --profile hardened configures it.
        sources = [
            REPO_ROOT / "scripts" / name
            for name in (
                "build-deb.sh",
                "build-static-linux.sh",
                "build-freebsd-pkg.sh",
                "build-openbsd-pkg.sh",
                "build-netbsd-pkg.sh",
            )
        ] + [REPO_ROOT / "packaging" / name / "merovingian.spec" for name in ("rpm", "rhel", "opensuse")]

        for source in sources:
            with self.subTest(source=source.relative_to(REPO_ROOT).as_posix()):
                # WHEN its Meson configuration is read
                text = source.read_text(encoding="utf-8")
                setup = text[text.index("%meson \\" if source.suffix == ".spec" else "meson setup") :]
                setup = setup[: setup.index("\n\n")]

                # THEN it is a release build with hardening on.
                self.assertIn("--buildtype=release", setup)
                self.assertIn("-Dhardening=true", setup)
                self.assertNotIn("-Dhardening=false", text)


if __name__ == "__main__":
    unittest.main()
