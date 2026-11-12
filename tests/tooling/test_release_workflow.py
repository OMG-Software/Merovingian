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
STAGE_SCRIPT = REPO_ROOT / "scripts" / "stage-release-tarball.sh"


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

        # WHEN the packages are built and published.
        # THEN both builds need check-tag, and the published release's
        # prerelease flag is check-tag's output rather than a constant.
        self.assertIn("needs: check-tag", job_text(workflow, "linux-release-package"))
        self.assertIn("needs: check-tag", job_text(workflow, "freebsd-release-package"))
        publish = job_text(workflow, "publish-release")
        self.assertIn("- check-tag", publish)
        self.assertIn("prerelease: ${{ needs.check-tag.outputs.prerelease == 'true' }}", publish)
        self.assertNotIn("prerelease: true", workflow)

    def test_hardened_linux_and_freebsd_packages_are_built(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN release assets are built.
        # THEN both supported package jobs use the hardened profile.
        self.assertIn(
            "sh scripts/build-linux.sh --builddir build-linux-release --profile hardened",
            workflow,
        )
        self.assertIn(
            "sh scripts/build-bsd.sh --builddir build-freebsd-release --profile hardened",
            workflow,
        )
        self.assertIn("sh scripts/check-release-readiness.sh", workflow)

    def test_release_tarballs_are_staged_from_meson_install_with_both_workers(self) -> None:
        # GIVEN the repository release workflow and its staging script.
        workflow = WORKFLOW.read_text(encoding="utf-8")
        script = STAGE_SCRIPT.read_text(encoding="utf-8")

        # WHEN release assets are staged.
        # THEN both platforms stage through the script, which installs with
        # Meson and requires both workers, and the Linux job installs the image
        # codecs the thumbnail worker is built from.
        self.assertIn('sh scripts/stage-release-tarball.sh build-linux-release "${package_root}"', workflow)
        self.assertIn('sh scripts/stage-release-tarball.sh build-freebsd-release "${package_root}"', workflow)
        self.assertNotIn("cp build-", workflow)
        self.assertIn("meson install", script)
        self.assertIn("libexec/merovingian/merovingian-fed-worker", script)
        self.assertIn("libexec/merovingian/merovingian-thumbnail-worker", script)
        linux = job_text(workflow, "linux-release-package")
        self.assertIn("libpng-dev", linux)
        self.assertIn("libturbojpeg0-dev", linux)
        self.assertIn("png libjpeg-turbo", job_text(workflow, "freebsd-release-package"))

    def test_release_packages_include_system_package_scaffolds(self) -> None:
        # GIVEN the repository release workflow and its staging script.
        workflow = WORKFLOW.read_text(encoding="utf-8")
        script = STAGE_SCRIPT.read_text(encoding="utf-8")

        # WHEN release assets are staged.
        # THEN Debian, RPM, and BSD package scaffolds are copied into the release tarballs.
        self.assertIn("packaging/deb", script)
        self.assertIn("packaging/rpm", script)
        self.assertIn("packaging/freebsd", script)
        self.assertIn("packaging/openbsd", script)
        self.assertIn("packaging/netbsd", script)
        self.assertIn("libsodium-dev", workflow)
        self.assertIn("libpq-dev", workflow)
        self.assertIn("libsodium postgresql17-client", workflow)

    def test_sbom_and_licence_summary_are_staged_before_signing(self) -> None:
        # GIVEN the repository release workflow.
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN the release assets are staged.
        stage = job_text(workflow, "stage-release-assets")

        # THEN the SBOM (both formats) and the licence summary are generated
        # into the unsigned assets before they are uploaded for signing, so
        # each is published with a detached signature.
        self.assertIn("python scripts/generate_sbom.py", stage)
        self.assertIn("--spdx release-assets/merovingian.spdx.json", stage)
        self.assertIn("--cyclonedx release-assets/merovingian.cdx.json", stage)
        self.assertIn('--commit "${{ github.sha }}"', stage)
        self.assertIn("generate-license-summary.py release-assets/merovingian.licenses.json", stage)
        self.assertLess(stage.index("generate_sbom.py"), stage.index("name: unsigned-release-assets"))
        self.assertNotIn("generate-license-summary", job_text(workflow, "publish-release"))

    def test_release_publishes_assets_and_checksums(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN release packages are published.
        # THEN the workflow generates checksums and uploads a GitHub release.
        self.assertIn("sha256sum", workflow)
        self.assertIn("sha256 -q", workflow)
        self.assertIn("softprops/action-gh-release@", workflow)

    def test_release_attaches_slsa_provenance_attestation(self) -> None:
        # GIVEN the repository release workflow.
        self.assertTrue(WORKFLOW.is_file(), "release workflow is missing")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        # WHEN release packages are published.
        # THEN each artifact carries a SLSA provenance attestation generated by
        # actions/attest-build-provenance and verifiable with `gh attestation verify`.
        # The job must also declare the `attestations: write` permission that the
        # action requires to publish to the repository attestation store.
        self.assertIn("attest-build-provenance", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id-token: write", workflow)

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


# Run-3 audit, supply-chain.release-verification.attestation-recipe-accepts-any-workflow-and-ref (ADR-0732). With
# `--repo` alone, `gh attestation verify` accepts an attestation made by any workflow on any ref of the repository,
# and packages.yml attests on every branch it runs on. Every published recipe therefore names the signing workflow
# and the ref, as scripts/run_complement.py does.
REPOSITORY = "OMG-Software/Merovingian"
RECIPE = re.compile(r"gh attestation verify (?P<arguments>[^`\n]+)")
SIGNER = re.compile(r"--signer-workflow " + re.escape(REPOSITORY) + r"/\.github/workflows/(?P<workflow>release|packages)\.yml(?:\s|$)")
SOURCE_REF = re.compile(r"--source-ref refs/(?:tags/v<version>|heads/main)(?:\s|$)")
# Not scanned: history that records what was published then (ADRs, changelogs) and the vendored Matrix spec.
SKIPPED_DIRECTORIES = {".git", ".worktrees", "subprojects", "node_modules", "adr", "matrix-v1.19-spec"}


def recipe_texts() -> dict[Path, str]:
    """Every Markdown and workflow file a reader is pointed to, with shell line continuations joined."""
    texts = {}
    for directory, subdirectories, files in os.walk(REPO_ROOT):
        subdirectories[:] = [name for name in subdirectories
                             if name not in SKIPPED_DIRECTORIES and not name.startswith("build")]
        for name in files:
            if not name.endswith((".md", ".yml", ".yaml")) or name.startswith("CHANGELOG"):
                continue
            path = Path(directory) / name
            texts[path] = re.sub(r"\\\n\s*", " ", path.read_text(encoding="utf-8"))
    return texts


def recipe_problems(arguments: str) -> list[str]:
    """What one recipe's arguments lack for the check to bind a release workflow and ref."""
    problems = []
    if f"--repo {REPOSITORY}" not in arguments:
        problems.append("names no --repo")
    signer = SIGNER.search(arguments)
    if signer is None:
        problems.append("does not pin --signer-workflow to release.yml or packages.yml")
    if SOURCE_REF.search(arguments) is None:
        problems.append("does not pin --source-ref to refs/tags/v<version> or refs/heads/main")
    if signer is not None:
        subject = arguments.split(" ", 1)[0]
        if "tarball" in subject and signer.group("workflow") != "release":
            problems.append("a release tarball is attested by release.yml")
        if "package" in subject and signer.group("workflow") != "packages":
            problems.append("a package is attested by packages.yml")
    return problems


class AttestationRecipeTests(unittest.TestCase):
    def test_every_published_attestation_recipe_pins_the_signer_workflow_and_ref(self) -> None:
        # GIVEN every document and workflow an operator reads.
        texts = recipe_texts()

        # WHEN each `gh attestation verify` command in them is read.
        recipes = [(path, match.group("arguments").strip())
                   for path, text in texts.items() for match in RECIPE.finditer(text)]

        # THEN each names the repository, the workflow that signs that kind of file, and a release ref.
        for path, arguments in recipes:
            with self.subTest(file=str(path.relative_to(REPO_ROOT)), recipe=arguments):
                self.assertEqual(recipe_problems(arguments), [])
        # AND the release notes and the release guide are among them, so the check is not vacuous.
        files = {path.relative_to(REPO_ROOT).as_posix() for path, _ in recipes}
        self.assertIn(".github/workflows/release.yml", files)
        self.assertIn("docs/release-process.md", files)
        self.assertGreaterEqual(len(recipes), 5)

    def test_the_recipe_check_refuses_an_unpinned_or_mismatched_recipe(self) -> None:
        # GIVEN recipes that the published check must never take.
        unpinned = f"<tarball> --repo {REPOSITORY}"
        no_ref = f"<tarball> --repo {REPOSITORY} --signer-workflow {REPOSITORY}/.github/workflows/release.yml"
        wrong_signer = (f"<package-file> --repo {REPOSITORY} --signer-workflow "
                        f"{REPOSITORY}/.github/workflows/release.yml --source-ref refs/tags/v<version>")
        any_branch = (f"<tarball> --repo {REPOSITORY} --signer-workflow {REPOSITORY}/.github/workflows/release.yml "
                      "--source-ref refs/heads/codex/x")
        pinned = (f"<tarball> --repo {REPOSITORY} --signer-workflow {REPOSITORY}/.github/workflows/release.yml "
                  "--source-ref refs/tags/v<version>")

        # WHEN each is judged THEN only the pinned one passes.
        self.assertNotEqual(recipe_problems(unpinned), [])
        self.assertNotEqual(recipe_problems(no_ref), [])
        self.assertNotEqual(recipe_problems(wrong_signer), [])
        self.assertNotEqual(recipe_problems(any_branch), [])
        self.assertEqual(recipe_problems(pinned), [])


if __name__ == "__main__":
    unittest.main()
