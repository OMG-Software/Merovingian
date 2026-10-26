#!/usr/bin/env python3
"""SonarQube Cloud analyses the server, packaging and workflows, and ignores tests and tooling (ADR-0229)."""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SONAR_CONFIG = REPO_ROOT / ".sonarcloud.properties"

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


if __name__ == "__main__":
    unittest.main()
