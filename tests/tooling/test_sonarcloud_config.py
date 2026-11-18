#!/usr/bin/env python3
"""SonarQube Cloud analyses the server, packaging and workflows, and ignores tests and tooling (ADR-0229),
from a CI scan that reads the build's compilation database (ADR-0250)."""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SONAR_CONFIG = REPO_ROOT / "sonar-project.properties"
AUTOMATIC_ANALYSIS_CONFIG = REPO_ROOT / ".sonarcloud.properties"
# The scan is a step of the coverage job: one build and one run of the suites feed Codecov and Sonar.
SONAR_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "coverage.yml"

# Paths whose findings must keep reaching the quality gate: the server itself,
# what packages install on a user's system, and the CI workflows.
ALWAYS_ANALYSED_PREFIXES = ("src/", "include/", "packaging/", ".github/", "migrations/", "config/")

# Developer and CI tooling outside scripts/ and tests/.
TOOLING_FILES = ("build.py", "llvm.sh", ".codex/hooks/clang_format_after_edit.py")


def sonar_property(name: str) -> str:
    for line in SONAR_CONFIG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip()
    raise AssertionError(f"{SONAR_CONFIG.name} sets no {name}")


def sonar_pattern(pattern: str) -> re.Pattern[str]:
    # Sonar's path patterns: ** is any number of directories, * is any run of
    # characters within one path segment, ? is one such character.
    expression = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            expression += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            expression += ".*"
            index += 2
        elif pattern[index] == "*":
            expression += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            expression += "[^/]"
            index += 1
        else:
            expression += re.escape(pattern[index])
            index += 1
    return re.compile(expression + r"\Z")


def excluded(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.match(path) for pattern in patterns)


def repository_files() -> list[str]:
    """The tracked files, or, where git cannot read this checkout (a CI container
    that does not own it, a source tarball), the files under every path this test
    judges, read from the filesystem."""
    try:
        output = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files"], check=True, capture_output=True, text=True
        ).stdout
        return [line for line in output.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):
        pass
    files = [name for name in TOOLING_FILES if (REPO_ROOT / name).is_file()]
    for top in ("tests", "scripts", *(prefix.rstrip("/") for prefix in ALWAYS_ANALYSED_PREFIXES)):
        root = REPO_ROOT / top
        if root.is_dir():
            files.extend(path.relative_to(REPO_ROOT).as_posix() for path in root.rglob("*") if path.is_file())
    return files


def job_text(workflow: str, job: str) -> str:
    """The text of one job: from its `  <job>:` line under `jobs:` to the next job or the end of the file."""
    section = workflow.split("\njobs:\n", 1)[1]
    # A job's header may carry a trailing comment (`  codecov: # upload job`); it still starts that job.
    header = r"[ \t]*(?:#[^\n]*)?"
    match = re.search(
        rf"(?m)^  {re.escape(job)}:{header}\n(.*?)(?=^  [A-Za-z0-9_-]+:{header}$|\Z)", section, re.DOTALL
    )
    assert match, f"the workflow has no job {job}"
    return match.group(1)


def steps_of(workflow: str, job: str) -> list[str]:
    """The job's own steps, each indented like a step's later keys so its first key reads like the rest."""
    steps = ("\n" + job_text(workflow, job)).split("\n    steps:\n", 1)[1].split("\n      - ")
    # A step's first key follows its `- ` marker, so `uses:` is not indented there; indent that first line like the rest.
    return ["        " + step for step in steps]


def scan_step_of(workflow: str) -> str:
    """The step of `jobs.coverage` that uses the SonarQube scan action, found by its `uses:` and not by its name."""
    scans = [
        step
        for step in steps_of(workflow, "coverage")
        if re.search(r"(?m)^        uses: SonarSource/sonarqube-scan-action@", step)
    ]
    assert len(scans) == 1, "expected exactly one SonarQube scan step in jobs.coverage"
    return scans[0]


def codecov_is_confined(workflow: str) -> bool:
    """The Codecov action appears in `jobs.codecov` and never in `jobs.coverage`, which holds the Sonar token."""
    action = "codecov/codecov-action@"
    return action in job_text(workflow, "codecov") and action not in job_text(workflow, "coverage")


def build_step_of(workflow: str) -> str:
    """The step of `jobs.coverage` that runs scripts/build-linux.sh."""
    builds = [
        step for step in steps_of(workflow, "coverage") if re.search(r"(?m)^        run: .*build-linux\.sh", step)
    ]
    assert len(builds) == 1, "expected exactly one build step in jobs.coverage"
    return builds[0]


def permissions_of(job: str) -> dict[str, str] | str | None:
    """The job's own `permissions:`: its mapping, an inline value such as `write-all`, or None without one."""
    match = re.search(r"(?m)^    permissions:[ \t]*(.*)\n((?:      .*\n?)*)", job)
    if match is None:
        return None
    if match.group(1).strip():
        return match.group(1).strip()
    pairs = (line.split(":", 1) for line in match.group(2).splitlines() if line.strip())
    return {key.strip(): value.strip() for key, value in pairs}


def step_env(step: str) -> dict[str, str]:
    """The `name: value` pairs of the step's own `env:` mapping."""
    match = re.search(r"(?m)^        env:\n((?:          .*(?:\n|$))+)", step)
    assert match, "the step has no env"
    pairs = (line.split(":", 1) for line in match.group(1).splitlines() if line.strip())
    return {key.strip(): value.strip() for key, value in pairs}


class ScanStepLookupTest(unittest.TestCase):
    @staticmethod
    def workflow(first_key: str, other_keys: str) -> str:
        return (
            "name: x\njobs:\n  coverage:\n    steps:\n      - name: other\n        run: true\n"
            f"      - {first_key}\n{other_keys}"
        )

    def test_given_uses_as_the_first_key_when_the_step_is_looked_up_then_it_is_found(self) -> None:
        # GIVEN a workflow whose scan step starts with `- uses:`.
        text = self.workflow(
            "uses: SonarSource/sonarqube-scan-action@abc", "        env:\n          SONAR_TOKEN: t\n"
        )

        # WHEN the scan step is looked up.
        step = scan_step_of(text)

        # THEN it is that step, with its env readable.
        self.assertEqual(step_env(step), {"SONAR_TOKEN": "t"})

    def test_given_uses_as_a_later_key_when_the_step_is_looked_up_then_it_is_found(self) -> None:
        # GIVEN a workflow whose scan step names itself first and has an indented `uses:`.
        text = self.workflow(
            "name: Scan", "        uses: SonarSource/sonarqube-scan-action@abc\n        env:\n          SONAR_TOKEN: t\n"
        )

        # WHEN the scan step is looked up.
        step = scan_step_of(text)

        # THEN it is that step.
        self.assertEqual(step_env(step), {"SONAR_TOKEN": "t"})


    def test_given_the_action_only_in_a_later_job_when_the_step_is_looked_up_then_it_is_not_found(self) -> None:
        # GIVEN a workflow whose coverage job has no scan, and a later job that has one.
        text = (
            "name: x\njobs:\n  coverage:\n    steps:\n      - name: other\n        run: true\n"
            "  codecov:\n    steps:\n      - uses: SonarSource/sonarqube-scan-action@abc\n"
            "        env:\n          SONAR_TOKEN: t\n"
        )

        # WHEN the scan step is looked up.
        # THEN jobs.coverage has none, so the lookup fails instead of finding the later job's step.
        with self.assertRaises(AssertionError):
            scan_step_of(text)

    def test_given_a_later_job_header_with_a_comment_when_the_step_is_looked_up_then_it_is_not_found(self) -> None:
        # GIVEN the same workflow, but the later job's header and the coverage job's header carry comments.
        text = (
            "name: x\njobs:\n  coverage: # instrumented build\n    steps:\n      - name: other\n        run: true\n"
            "  codecov: # upload job\n    steps:\n      - uses: SonarSource/sonarqube-scan-action@abc\n"
            "        env:\n          SONAR_TOKEN: t\n"
        )

        # WHEN the scan step is looked up.
        # THEN the commented header still ends jobs.coverage, so the later job's step is not found.
        with self.assertRaises(AssertionError):
            scan_step_of(text)
        self.assertNotIn("sonarqube-scan-action", job_text(text, "coverage"))
        self.assertIn("sonarqube-scan-action", job_text(text, "codecov"))


class JobScopedReadersTest(unittest.TestCase):
    CODECOV = "        uses: codecov/codecov-action@abc\n"

    def test_given_codecov_with_write_all_and_a_later_job_with_contents_when_read_then_it_is_not_contents_read(
        self,
    ) -> None:
        # GIVEN a codecov job granting `write-all`, followed by a job that grants `contents: read`.
        text = (
            "name: x\njobs:\n  codecov:\n    permissions: write-all\n    steps:\n      - run: true\n"
            "  later:\n    permissions:\n      contents: read\n"
        )

        # WHEN the permissions of the codecov job are read from its own text.
        permissions = permissions_of(job_text(text, "codecov"))

        # THEN they are `write-all`, not the later job's mapping.
        self.assertEqual(permissions, "write-all")
        self.assertEqual(permissions_of(job_text(text, "later")), {"contents": "read"})

    def test_given_a_build_step_with_a_false_condition_when_read_then_it_has_a_condition(self) -> None:
        # GIVEN a coverage job whose build step is switched off by `if: ${{ false }}`.
        text = (
            "name: x\njobs:\n  coverage:\n    steps:\n      - name: Build\n        if: ${{ false }}\n"
            "        run: sh scripts/build-linux.sh --builddir build-coverage --coverage\n"
        )

        # WHEN the build step is found.
        step = build_step_of(text)

        # THEN its own `if:` is visible, so the check that it always runs fails.
        self.assertRegex(step, r"(?m)^        if:")

    def test_given_codecov_moved_into_the_coverage_job_when_read_then_it_is_not_confined_to_its_own_job(self) -> None:
        # GIVEN a coverage job that uploads to Codecov right after the scan, and a codecov job that does too.
        text = (
            "name: x\njobs:\n  coverage:\n    steps:\n      - uses: SonarSource/sonarqube-scan-action@abc\n"
            "      - name: Upload\n" + self.CODECOV + "  codecov:\n    steps:\n      - name: Upload\n" + self.CODECOV
        )

        # WHEN each job's text is searched for the Codecov action.
        # THEN the confinement check rejects it, and accepts the same workflow without the coverage job's upload.
        self.assertFalse(codecov_is_confined(text))
        self.assertTrue(codecov_is_confined(text.replace("      - name: Upload\n" + self.CODECOV, "", 1)))


class SonarCloudExclusionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.patterns = [sonar_pattern(p.strip()) for p in sonar_property("sonar.exclusions").split(",") if p.strip()]
        self.files = repository_files()

    def test_given_the_tracked_tests_and_scripts_when_matched_then_every_one_is_excluded(self) -> None:
        tooling = [f for f in self.files if f.startswith(("tests/", "scripts/")) or f in TOOLING_FILES]
        self.assertGreater(len(tooling), 0)
        not_excluded = [f for f in tooling if not excluded(f, self.patterns)]
        self.assertEqual(not_excluded, [], "test or tooling files still analysed")

    def test_given_the_server_packaging_and_workflows_when_matched_then_none_is_excluded(self) -> None:
        analysed = [f for f in self.files if f.startswith(ALWAYS_ANALYSED_PREFIXES)]
        self.assertTrue(any(f.startswith("src/") for f in analysed))
        self.assertTrue(any(f.startswith(".github/workflows/") for f in analysed))
        self.assertIn("packaging/netbsd/files/merovingian.sh", analysed)
        hidden = [f for f in analysed if excluded(f, self.patterns)]
        self.assertEqual(hidden, [], "files that must reach the quality gate are excluded")

    def test_given_the_pattern_reader_when_given_known_paths_then_it_reads_sonar_globs(self) -> None:
        patterns = [sonar_pattern("tests/**"), sonar_pattern("build.py")]
        self.assertTrue(excluded("tests/unit/test_x.cpp", patterns))
        self.assertTrue(excluded("build.py", patterns))
        self.assertFalse(excluded("src/build.py", patterns))
        self.assertFalse(excluded("teststuff/x.cpp", patterns))


class SonarCloudCiScanTest(unittest.TestCase):
    """ADR-0250: the scan runs in CI, against the compilation database of a real build.

    The scan is a step of the `coverage` job, which builds once and feeds Codecov and Sonar from that build."""

    def setUp(self) -> None:
        self.workflow = SONAR_WORKFLOW.read_text(encoding="utf-8")

    def test_given_the_properties_when_read_then_they_name_this_project(self) -> None:
        self.assertEqual(sonar_property("sonar.organization"), "omg-software")
        self.assertEqual(sonar_property("sonar.projectKey"), "OMG-Software_Merovingian")

    def test_given_ci_analysis_when_the_repository_is_read_then_no_automatic_analysis_config_remains(self) -> None:
        # Automatic analysis and CI analysis must not both run; one configuration file says what is analysed.
        self.assertFalse(AUTOMATIC_ANALYSIS_CONFIG.exists())

    def test_given_the_compile_commands_property_when_read_then_ci_builds_that_directory(self) -> None:
        compile_commands = sonar_property("sonar.cfamily.compile-commands")
        builddir, _, filename = compile_commands.rpartition("/")
        self.assertEqual(filename, "compile_commands.json")
        self.assertTrue(builddir)
        # The coverage build writes the compilation database the analysis reads.
        self.assertIn(f"scripts/build-linux.sh --builddir {builddir} --coverage", self.workflow)
        # The build directory's generated files are not project sources.
        patterns = [sonar_pattern(p.strip()) for p in sonar_property("sonar.exclusions").split(",") if p.strip()]
        self.assertTrue(excluded(f"{builddir}/meson-private/sanitycheckcpp.cc", patterns))

    def test_given_the_workflow_when_read_then_the_scan_action_is_pinned_to_a_commit(self) -> None:
        # The action receives SONAR_TOKEN: a tag can be moved, a commit cannot.
        self.assertRegex(
            self.workflow, r"(?m)uses: SonarSource/sonarqube-scan-action@[0-9a-f]{40}(?:[ \t]+#.*)?$"
        )
        self.assertNotRegex(self.workflow, r"uses: SonarSource/sonarqube-scan-action@v")

    def test_given_the_workflow_when_read_then_the_steps_before_the_scan_are_pinned_to_a_commit(self) -> None:
        # The job holds SONAR_TOKEN, in the scan step only, but a step that ran earlier in the job can still change
        # what that step runs: the checkout, Python setup and ccache steps that precede it are pinned to a commit,
        # where a tag can be moved. The artifact upload and Codecov's action come after the scan.
        scan = self.workflow.index("uses: SonarSource/sonarqube-scan-action@")
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", self.workflow[:scan])
        self.assertGreaterEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", f"{action} runs before the scan and is not pinned to a commit")

    def test_given_the_codecov_job_when_read_then_every_action_it_runs_is_pinned_to_a_commit(self) -> None:
        # GIVEN the codecov job, which holds CODECOV_TOKEN: any step that runs before the upload can change what the
        # upload sends, and a tag can be moved where a commit cannot.
        codecov_job = job_text(self.workflow, "codecov")
        # WHEN the actions it uses are read.
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", codecov_job)
        # THEN there are the checkout, the artifact download and the upload, each pinned to a commit.
        self.assertGreaterEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", f"{action} runs in the codecov job and is not pinned")

    def test_given_the_workflow_when_read_then_it_scans_full_history_with_least_privilege(self) -> None:
        # GIVEN the coverage workflow.
        # WHEN its checkout depth and permissions are read.
        coverage_job = job_text(self.workflow, "coverage")
        codecov_job = job_text(self.workflow, "codecov")

        # THEN it fetches full history, grants nothing at workflow level, and only the scanning job may read pull
        # requests; the Codecov job reads contents alone, each judged within its own job's text.
        self.assertIn("fetch-depth: 0", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^permissions: \{\}$")
        self.assertEqual(permissions_of(coverage_job), {"contents": "read", "pull-requests": "read"})
        self.assertEqual(permissions_of(codecov_job), {"contents": "read"})

    def test_given_the_workflow_when_read_then_the_token_is_in_the_scan_step_alone(self) -> None:
        # GIVEN the job runs beside third-party actions (Codecov downloads its CLI at run time).
        # THEN the secret is named once, in the scan step's own environment: not in the workflow's or the job's env.
        self.assertEqual(self.workflow.count("secrets.SONAR_TOKEN"), 1)
        before_steps, steps = self.workflow.split("\n    steps:\n", 1)
        self.assertNotIn("secrets.SONAR_TOKEN", before_steps)
        # AND that step's own `env` maps the token to the secret, and binds nothing else.
        self.assertEqual(step_env(scan_step_of(self.workflow)), {"SONAR_TOKEN": "${{ secrets.SONAR_TOKEN }}"})
        # AND the Codecov CLI, downloaded at run time with its signature check skipped, runs in its own job and never
        # in the job that holds the token.
        self.assertTrue(codecov_is_confined(self.workflow))

    def test_given_a_cpp26_build_when_the_properties_are_read_then_cpp26_analysis_is_enabled(self) -> None:
        # The analyser stops with "C++26 standard detected" unless this is set.
        self.assertEqual(sonar_property("sonar.cfamily.experimental.cpp26.enabled"), "true")

    def test_given_the_workflow_when_read_then_it_installs_what_the_thumbnail_worker_needs(self) -> None:
        # Without libpng and libturbojpeg Meson drops the thumbnail worker, and the
        # compilation database, so the analysis, never holds media/thumbnail_worker_main.cpp.
        self.assertIn("libpng-dev", self.workflow)
        self.assertIn("libturbojpeg0-dev", self.workflow)

    def test_given_the_workflow_when_read_then_build_tools_install_from_hashed_wheels_only(self) -> None:
        # The job holds SONAR_TOKEN: a dependency resolved at run time, or an sdist's setup
        # script run during installation, would run unreviewed code next to it.
        self.assertIn(
            "python -m pip install --require-hashes --only-binary :all: --requirement requirements-build.txt",
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"pip install (--upgrade )?(pip|meson)")

    def test_given_the_build_requirements_when_read_then_meson_and_ninja_are_pinned_with_hashes(self) -> None:
        requirements = (REPO_ROOT / "requirements-build.txt").read_text(encoding="utf-8")
        for package in ("meson", "ninja"):
            self.assertRegex(requirements, rf"(?m)^{package}==[0-9][^ ]* \\\n    --hash=sha256:[0-9a-f]{{64}}")

    def test_given_the_properties_when_read_then_the_scan_reads_a_sonarqube_coverage_report(self) -> None:
        # Without a report every new line reads as uncovered and the quality gate fails.
        self.assertEqual(sonar_property("sonar.coverageReportPaths"), "coverage/sonarqube.xml")

    def test_given_the_workflow_when_read_then_it_builds_with_coverage_and_runs_the_suites_with_gcc(self) -> None:
        # --coverage builds instrumented and runs meson test; --compile-only would run nothing.
        self.assertNotIn("--compile-only", self.workflow)
        # GCC: only GCC's gcov labels the throw edges that
        # --exclude-throw-branches drops (ADR-0217).
        self.assertIn("CC: ccache gcc-14", self.workflow)
        self.assertIn("CXX: ccache g++-14", self.workflow)

    def test_given_the_workflow_when_read_then_gcovr_writes_the_report_the_scan_reads(self) -> None:
        report = sonar_property("sonar.coverageReportPaths")
        self.assertIn(f"--sonarqube {report}", self.workflow)
        for option in ("--gcov-executable gcov-14", "--exclude-throw-branches", "--exclude-unreachable-branches",
                       "--gcov-exclude-directories '.*/subprojects$'",
                       "--filter 'src/'",
                       "--filter 'include/merovingian/'"):
            self.assertIn(option, self.workflow)

    def test_given_the_workflow_when_read_then_postgresql_scenarios_run_against_a_pinned_image(self) -> None:
        # Without a live PostgreSQL the [postgresql] scenarios skip and the PostgreSQL store
        # reads as uncovered. The image is pinned by digest: this job holds SONAR_TOKEN.
        self.assertRegex(self.workflow, r"image: postgres:16@sha256:[0-9a-f]{64}")
        self.assertIn("MEROVINGIAN_TEST_POSTGRESQL_URI:", self.workflow)

    def test_given_a_pull_request_from_a_fork_when_the_workflow_runs_then_only_the_scan_is_skipped(self) -> None:
        # A fork's pull request gets no secrets; it is scanned once merged. The coverage build, reports and Codecov
        # upload still run for it, so the skip is the scan step's own condition and the job has none.
        condition = "if: github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository"
        self.assertEqual(self.workflow.count(condition), 1)
        # The scan step is found by its `uses:`, and the guard is that step's own `if:`.
        scan = scan_step_of(self.workflow)
        self.assertRegex(scan, r"(?m)^        " + re.escape(condition) + r"$")
        job = self.workflow.split("\njobs:\n", 1)[1].split("\n    steps:\n", 1)[0]
        self.assertNotRegex(job, r"(?m)^    if:")

    def test_given_the_workflow_when_read_then_the_build_step_always_runs_its_real_command(self) -> None:
        # GIVEN the build step of the coverage job.
        builddir = sonar_property("sonar.cfamily.compile-commands").rpartition("/")[0]
        step = build_step_of(self.workflow)

        # WHEN its condition and command are read.
        # THEN it has no `if:` of its own, so it cannot be switched off, and it runs the coverage build.
        self.assertNotRegex(step, r"(?m)^        if:")
        command = rf"sh scripts/build-linux\.sh --builddir {re.escape(builddir)} --coverage --skip-job coverage"
        self.assertRegex(step, rf"(?m)^        run: {command}$")

    def test_given_the_workflow_when_read_then_one_build_feeds_the_scan_and_the_reports(self) -> None:
        # The scan reads the build directory the coverage build writes; nothing else compiles in the job.
        builddir = sonar_property("sonar.cfamily.compile-commands").rpartition("/")[0]
        self.assertEqual(self.workflow.count("run: sh scripts/build-linux.sh"), 1)
        self.assertNotIn("meson compile", self.workflow)
        self.assertIn(f"            {builddir}\n", self.workflow)

if __name__ == "__main__":
    unittest.main()
