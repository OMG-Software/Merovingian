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
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
SIGN_WORKFLOW = WORKFLOWS_DIR / "sign-artifacts.yml"
PACKAGES_WORKFLOW = WORKFLOWS_DIR / "packages.yml"


def job_text(workflow: str, job: str) -> str:
    """The text of one job, from its key to the next top-level job key."""
    lines = workflow.splitlines(keepends=True)
    start = lines.index(f"  {job}:\n")
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith("  ") and not lines[index].startswith("   ")
                and lines[index].rstrip().endswith(":")), len(lines))
    return "".join(lines[start:end])


def check_tag_script(workflow: str, step_name: str = "Compare the tag with meson.build") -> str:
    """The shell that one step of the check-tag job runs."""
    step = job_text(workflow, "check-tag").split(f"- name: {step_name}", 1)[1]
    body = step.split("run: |\n", 1)[1]
    kept = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        kept.append(line[10:])
    return "\n".join(kept) + "\n"


def installed_packages(job: str) -> set[str]:
    """The package arguments of a job's apt-get install and pkg install commands.

    Only those commands count, so a package named in a comment, a commented-out install
    command, or a `curl` call in another step does not. Backslash continuations are joined,
    then each line loses its comment (a `#` at the start or after whitespace, which keeps
    `${VAR#prefix}`) before the install command is looked for."""
    packages: set[str] = set()
    for line in re.sub(r"\\\n", " ", job).splitlines():
        command = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]
        match = re.search(r"(?:\bapt-get|\bpkg) install\b(.*)", command)
        if match is not None:
            packages.update(word for word in match.group(1).split() if not word.startswith("-"))
    return packages


class ReleaseWorkflowTests(unittest.TestCase):
    def test_release_notes_say_where_the_complement_evidence_is(self) -> None:
        # GIVEN the repository release workflow.
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN its release notes are written.
        # THEN they have a Complement section naming the signed evidence files
        # and how to verify them, and saying what their absence means.
        self.assertIn("## Complement", workflow)
        self.assertIn("complement-results-", workflow)
        self.assertIn("gpg --verify complement-results-", workflow)
        self.assertIn("not been tested against Complement", workflow)

    def test_release_notes_name_the_complement_files_by_this_versions_number(self) -> None:
        # GIVEN the step that writes the release notes, whose heredoc is quoted
        # so `$` and backticks in the notes stay literal.
        workflow = WORKFLOW.read_text(encoding="utf-8")
        step = workflow.split("- name: Write release notes", 1)[1].split("- name:", 1)[0]
        heredoc_end = step.index("\n          EOF\n")

        # WHEN the step is read past the heredoc.
        after = step[heredoc_end:]

        # THEN it reads the version from meson.build, refuses to go on without
        # one, and replaces every <version> placeholder before anything else is
        # appended, so the notes name the real evidence files.
        self.assertIn("meson.build", after)
        self.assertIn('if [ -z "$version" ]', after)
        replace = after.index('sed -i "s/<version>/${version}/g" release-notes.md')
        self.assertLess(replace, after.index(">> release-notes.md"))

    def test_every_v_tag_triggers_release_publication(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN a release tag is pushed.
        # THEN every v* tag triggers it, with no alpha suffix required.
        self.assertIn("tags:\n      - 'v*'\n", workflow)
        self.assertNotIn("alpha", workflow)

    @unittest.skipUnless(shutil.which("sh"), "needs a POSIX sh")
    def test_check_tag_accepts_only_the_meson_version_and_marks_0x_prereleases(self) -> None:
        # GIVEN the shell of the check-tag step, and a checkout whose meson.build
        # names a version.
        script = check_tag_script(WORKFLOW.read_text(encoding="utf-8"))

        def run(version: str, tag: str) -> tuple[int, str]:
            with tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                (work / "meson.build").write_text(
                    f"project(\n  'merovingian',\n  'cpp',\n  version: '{version}',\n)\n",
                    encoding="utf-8", newline="\n")
                (work / "step.sh").write_text(script, encoding="utf-8", newline="\n")
                output = work / "output"
                output.write_text("", encoding="utf-8")
                env = dict(os.environ, GITHUB_REF_NAME=tag, GITHUB_OUTPUT=str(output))
                result = subprocess.run([shutil.which("sh"), "-e", "step.sh"], cwd=work, env=env,
                                        capture_output=True, text=True, check=False)
                return result.returncode, output.read_text(encoding="utf-8")

        # WHEN tags are checked against it.
        accepted_0x = run("0.12.90", "v0.12.90")
        accepted_1x = run("1.0.0", "v1.0.0")
        other_version = run("0.12.90", "v0.12.89")
        suffixed = run("0.12.90", "v0.12.90-alpha.1")
        bare = run("0.12.90", "0.12.90")

        # THEN only v<version> passes; a 0.x version is a prerelease and 1.0.0 is not.
        self.assertEqual(accepted_0x, (0, "version=0.12.90\nprerelease=true\n"))
        self.assertEqual(accepted_1x, (0, "version=1.0.0\nprerelease=false\n"))
        for refused in (other_version, suffixed, bare):
            self.assertNotEqual(refused[0], 0)
            self.assertEqual(refused[1], "")

    def test_check_tag_fetches_the_history_that_makes_the_ancestor_check_real(self) -> None:
        # GIVEN the check-tag job (ADR-0614).
        job = job_text(WORKFLOW.read_text(encoding="utf-8"), "check-tag")

        # WHEN its checkout is read.
        # THEN it fetches all history, without which origin/main does not exist
        # on a tag build, and the check comes before the version comparison.
        self.assertIn("fetch-depth: 0", job)
        self.assertLess(job.index("- name: Refuse a tag that is not on main"),
                        job.index("- name: Compare the tag with meson.build"))

    @unittest.skipUnless(shutil.which("sh") and shutil.which("git"), "needs a POSIX sh and git")
    def test_check_tag_refuses_a_commit_that_is_not_on_main(self) -> None:
        # GIVEN the shell of the ancestor step, and a repository whose
        # origin/main holds one commit, with a side commit that main does not.
        script = check_tag_script(WORKFLOW.read_text(encoding="utf-8"), "Refuse a tag that is not on main")
        identity = ["-c", "user.name=test", "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false"]

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)

            def git(*args: str) -> str:
                return subprocess.run(["git", *identity, *args], cwd=work, capture_output=True, text=True,
                                      check=True).stdout.strip()

            git("init", "-q")
            git("commit", "-q", "--allow-empty", "-m", "first")
            first = git("rev-parse", "HEAD")
            git("commit", "-q", "--allow-empty", "-m", "on main")
            on_main = git("rev-parse", "HEAD")
            git("checkout", "-q", "--detach", first)
            git("commit", "-q", "--allow-empty", "-m", "on a branch")
            off_main = git("rev-parse", "HEAD")
            (work / "step.sh").write_text(script, encoding="utf-8", newline="\n")

            def run(sha: str) -> int:
                env = dict(os.environ, GITHUB_SHA=sha, GITHUB_REF_NAME="v1.0.0")
                return subprocess.run([shutil.which("sh"), "-e", "step.sh"], cwd=work, env=env, capture_output=True,
                                      text=True, check=False).returncode

            # WHEN origin/main is missing, as in a shallow checkout.
            without_main = run(on_main)
            git("update-ref", "refs/remotes/origin/main", on_main)

            # AND WHEN tags at each commit are checked.
            tip, ancestor, branch = run(on_main), run(first), run(off_main)

        # THEN only a commit on main passes, and a missing main refuses.
        self.assertNotEqual(without_main, 0)
        self.assertEqual(tip, 0)
        self.assertEqual(ancestor, 0)
        self.assertNotEqual(branch, 0)

    def test_the_signing_key_is_read_only_by_the_job_in_the_release_environment(self) -> None:
        # GIVEN every workflow in the repository (ADR-0614).
        sign = SIGN_WORKFLOW.read_text(encoding="utf-8")
        job = job_text(sign, "sign")

        # WHEN the job that imports the key is read.
        # THEN it declares the release environment, which is what scopes the secret.
        self.assertIn("    environment: release\n", job)
        self.assertIn("secrets.GPG_PRIVATE_KEY", job)
        self.assertIn("secrets.GPG_PASSPHRASE", job)

        # AND no other workflow names the key, and each caller passes secrets
        # through, since a job calling a reusable workflow cannot declare an environment.
        for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
            if path == SIGN_WORKFLOW:
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertNotIn("secrets.GPG_", text)
                if "uses: ./.github/workflows/sign-artifacts.yml" in text:
                    call = text.split("uses: ./.github/workflows/sign-artifacts.yml", 1)[1]
                    self.assertIn("    secrets: inherit\n", call)

    def test_every_job_waits_for_the_tag_check_and_prerelease_follows_it(self) -> None:
        # GIVEN the repository release workflow.
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN the release gates, the packages and the publish job are read.
        # THEN each build needs check-tag, publishing waits for all of them, and the
        # published release's prerelease flag is check-tag's output rather than a constant.
        for job in ("linux-release-evidence", "freebsd-release-evidence", "distro-packages"):
            with self.subTest(job=job):
                self.assertIn("needs: check-tag", job_text(workflow, job))
        publish = job_text(workflow, "publish-release")
        for job in ("check-tag", "linux-release-evidence", "freebsd-release-evidence", "distro-packages"):
            with self.subTest(publish_needs=job):
                self.assertIn(f"      - {job}\n", publish)
        self.assertIn("prerelease: ${{ needs.check-tag.outputs.prerelease == 'true' }}", publish)
        self.assertNotIn("prerelease: true", workflow)

    def test_hardened_linux_and_freebsd_builds_gate_the_release(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN the release gates run.
        # THEN both platforms build and test with the hardened profile, FreeBSD on its
        # 15.x line, and the readiness gate runs.
        self.assertIn(
            "sh scripts/build-linux.sh --builddir build-linux-release --profile hardened",
            workflow,
        )
        self.assertIn(
            "sh scripts/build-bsd.sh --builddir build-freebsd-release --profile hardened",
            workflow,
        )
        self.assertIn("release: '15'\n", job_text(workflow, "freebsd-release-evidence"))
        self.assertIn("sh scripts/check-release-readiness.sh", workflow)
        # AND the Linux gate installs the image codecs the thumbnail worker is built from.
        linux = job_text(workflow, "linux-release-evidence")
        self.assertIn("libpng-dev", linux)
        self.assertIn("libturbojpeg0-dev", linux)
        self.assertIn("png libjpeg-turbo", job_text(workflow, "freebsd-release-evidence"))

    def test_a_tag_ships_the_packages_latest_ships_and_no_build_of_its_own(self) -> None:
        # GIVEN the release workflow, and packages.yml, which builds `latest` (ADR-0652).
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN its assets are read.
        # THEN it publishes only what packages.yml signed in this run: no glibc or
        # FreeBSD tarball of its own build, no staging or signing of its own.
        self.assertNotIn("stage-release-tarball.sh", workflow)
        self.assertNotIn(".tar.gz", workflow.split("cat > release-notes.md")[0])
        self.assertNotIn("uses: ./.github/workflows/sign-artifacts.yml", workflow)
        publish = job_text(workflow, "publish-release")
        self.assertIn("name: signed-packages\n", publish)
        self.assertIn("release-assets/*", publish)
        # AND the packages are called with the secrets packages.yml's signing job needs.
        self.assertIn("    secrets: inherit\n", job_text(workflow, "distro-packages"))

    def test_sbom_and_licence_summary_are_staged_before_signing(self) -> None:
        # GIVEN packages.yml, which stages both `latest` and every tagged release.
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN the package assets are staged.
        stage = job_text(workflow, "stage-package-assets")

        # THEN the SBOM (both formats) and the licence summary are generated
        # into the unsigned assets before they are uploaded for signing, so
        # each is published with a detached signature.
        self.assertIn("python scripts/generate_sbom.py", stage)
        self.assertIn("--spdx packages/merovingian.spdx.json", stage)
        self.assertIn("--cyclonedx packages/merovingian.cdx.json", stage)
        self.assertIn('--commit "${{ github.sha }}"', stage)
        self.assertIn("generate-license-summary.py packages/merovingian.licenses.json", stage)
        self.assertLess(stage.index("generate_sbom.py"), stage.index("name: unsigned-packages"))
        self.assertNotIn("generate-license-summary", job_text(WORKFLOW.read_text(encoding="utf-8"), "publish-release"))

    def test_release_publishes_assets_and_checksums(self) -> None:
        # GIVEN the repository release workflow and packages.yml.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        packages = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN release packages are published.
        # THEN staging writes SHA256SUMS over every asset before signing, the notes list
        # it, and the workflow uploads a GitHub release.
        stage = job_text(packages, "stage-package-assets")
        self.assertIn("sha256sum packages/* > packages/SHA256SUMS", stage)
        self.assertLess(stage.index("SHA256SUMS"), stage.index("name: unsigned-packages"))
        self.assertIn("done < release-assets/SHA256SUMS", workflow)
        self.assertIn("softprops/action-gh-release@", workflow)

    def test_release_attaches_slsa_provenance_attestation(self) -> None:
        # GIVEN the repository release workflow and packages.yml.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        packages = PACKAGES_WORKFLOW.read_text(encoding="utf-8")

        # WHEN release packages are published.
        # THEN each package carries a SLSA provenance attestation generated by
        # actions/attest-build-provenance in the job that built it, and the release
        # workflow grants the called jobs the permissions the action requires.
        calling = job_text(workflow, "distro-packages")
        self.assertIn("attestations: write", calling)
        self.assertIn("id-token: write", calling)
        for job in ("deb", "debian-pkg", "static-linux-fallback", "rpm", "rhel-rpm", "opensuse-rpm",
                    "freebsd-pkg", "openbsd-pkg", "netbsd-pkg"):
            with self.subTest(job=job):
                self.assertIn("uses: actions/attest-build-provenance@", job_text(packages, job))

    def test_release_notes_record_compiler_dependency_and_test_evidence(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN a release is published.
        # THEN each hardened platform build collects release evidence (compiler
        # version, link-time hardening confirmation, pinned dependency
        # versions, test log summary, fuzz target names) via the shared
        # scripts/collect-release-evidence.sh helper, uploads it as its own
        # artifact, and the publish job downloads and folds every platform's
        # evidence into the published release notes alongside the package
        # checksums — closing production-milestone.md's "Record compiler
        # version, linker flags, dependency versions, test logs, sanitizer
        # logs, fuzz target names, package checksums, and GPG signatures in
        # release notes" bullet.
        self.assertIn("scripts/collect-release-evidence.sh", workflow)
        self.assertIn("release-evidence-linux-", workflow)
        self.assertIn("release-evidence-freebsd-", workflow)
        self.assertIn("## Package checksums", workflow)
        self.assertIn("## Release evidence", workflow)

    def test_only_active_install_command_arguments_count_as_installed(self) -> None:
        # GIVEN a job that names packages in comments, in a commented-out install command and
        # in a curl call, beside one real apt-get install and one real pkg install.
        job = (
            "      # libcurl4-openssl-dev is named here only\n"
            "      - run: curl -fsSL https://example.invalid\n"
            "          # apt-get install -y libcurl4-openssl-dev\n"
            "          #pkg install curl\n"
            "          sudo apt-get install -y \\\n"
            "            bison \\\n"
            "            flex  # libpq-dev\n"
            "          pkg install -y meson ${PKG#prefix}  # libsodium\n"
        )

        # WHEN its installed packages are read.
        installed = installed_packages(job)

        # THEN only the active commands' package arguments count.
        self.assertEqual({"bison", "flex", "meson", "${PKG#prefix}"}, installed)

    def test_each_release_build_installs_every_module_its_build_script_checks(self) -> None:
        # GIVEN the release workflow and the pkg-config modules each build script refuses to
        # build without. These jobs run only for a v* tag, so nothing else exercises their
        # install lists: v1.0.0's first run failed on "missing pkg-config module: libcurl"
        # (ADR-0651).
        workflow = WORKFLOW.read_text(encoding="utf-8")
        builds = [
            # (job, build script, the package that provides each module on that runner)
            ("linux-release-evidence", "build-linux.sh",
             {"libsodium": "libsodium-dev", "openssl": "libssl-dev", "libpq": "libpq-dev",
              "libcurl": "libcurl4-openssl-dev"}),
            ("freebsd-release-evidence", "build-bsd.sh",
             {"libsodium": "libsodium", "openssl": "openssl", "libpq": "postgresql17-client",
              "libcurl": "curl"}),
        ]

        for job, script, packages in builds:
            with self.subTest(job=job):
                checked = re.findall(r"^check_pkg_config_module (\S+)$",
                                     (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8"),
                                     re.MULTILINE)
                installed = installed_packages(job_text(workflow, job))

                # WHEN the job's install step is compared with the script's checks.
                missing = [module for module in checked if packages.get(module) not in installed]

                # THEN the script checks something, every module it checks has a known package,
                # and the job installs that package.
                self.assertTrue(checked, f"no check_pkg_config_module lines found in {script}")
                self.assertEqual([], [m for m in checked if m not in packages],
                                 f"{script} checks a module this test has no {job} package for")
                self.assertEqual([], missing, f"{job} does not install the package for these modules")


if __name__ == "__main__":
    unittest.main()
