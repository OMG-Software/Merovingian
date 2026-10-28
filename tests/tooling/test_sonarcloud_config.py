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
SONAR_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sonarcloud.yml"

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
    """ADR-0250: the scan runs in CI, against the compilation database of a real build."""

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
        # The coverage build also writes the compilation database the analysis reads.
        self.assertIn(f"scripts/build-linux.sh --builddir {builddir} --coverage", self.workflow)
        # The build directory's generated files are not project sources.
        patterns = [sonar_pattern(p.strip()) for p in sonar_property("sonar.exclusions").split(",") if p.strip()]
        self.assertTrue(excluded(f"{builddir}/meson-private/sanitycheckcpp.cc", patterns))

    def test_given_the_workflow_when_read_then_the_scan_action_is_pinned_to_a_commit(self) -> None:
        # The action receives SONAR_TOKEN: a tag can be moved, a commit cannot.
        self.assertRegex(self.workflow, r"uses: SonarSource/sonarqube-scan-action@[0-9a-f]{40}\b")
        self.assertNotRegex(self.workflow, r"uses: SonarSource/sonarqube-scan-action@v")

    def test_given_the_workflow_when_read_then_every_action_is_pinned_to_a_commit(self) -> None:
        # Every step shares the job with SONAR_TOKEN, the checkout and Python setup included.
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", self.workflow)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"@[0-9a-f]{40}$", f"{action} is not pinned to a commit")

    def test_given_the_workflow_when_read_then_it_scans_full_history_with_the_repository_secret(self) -> None:
        self.assertIn("fetch-depth: 0", self.workflow)
        self.assertIn("SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^permissions:\n  contents: read")

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
        # GCC, as in coverage.yml: only GCC's gcov labels the throw edges that
        # --exclude-throw-branches drops (ADR-0217).
        self.assertIn("CC: gcc-14", self.workflow)
        self.assertIn("CXX: g++-14", self.workflow)

    def test_given_the_workflow_when_read_then_gcovr_writes_the_report_the_scan_reads(self) -> None:
        report = sonar_property("sonar.coverageReportPaths")
        self.assertIn(f"--sonarqube {report}", self.workflow)
        for option in ("--gcov-executable gcov-14", "--exclude-throw-branches", "--exclude-unreachable-branches",
                       "--gcov-exclude-directories '.*/subprojects/'",
                       "--filter 'src/'",
                       "--filter 'include/merovingian/'"):
            self.assertIn(option, self.workflow)

    def test_given_the_workflow_when_read_then_postgresql_scenarios_run_against_a_pinned_image(self) -> None:
        # Without a live PostgreSQL the [postgresql] scenarios skip and the PostgreSQL store
        # reads as uncovered. The image is pinned by digest: this job holds SONAR_TOKEN.
        self.assertRegex(self.workflow, r"image: postgres:16@sha256:[0-9a-f]{64}")
        self.assertIn("MEROVINGIAN_TEST_POSTGRESQL_URI:", self.workflow)

    def test_given_a_pull_request_from_a_fork_when_the_workflow_runs_then_the_scan_is_skipped(self) -> None:
        # A fork's pull request gets no secrets; it is analysed once merged.
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", self.workflow)


if __name__ == "__main__":
    unittest.main()
