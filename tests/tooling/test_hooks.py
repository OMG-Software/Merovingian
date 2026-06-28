#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PRE_COMMIT_HOOK = REPO_ROOT / "scripts" / "hooks" / "pre-commit"
CHANGE_RECORD_SCRIPT = REPO_ROOT / "scripts" / "check-staged-changelog-docs.sh"
CODEX_HOOKS_CONFIG = REPO_ROOT / ".codex" / "hooks.json"
CODEX_CLANG_FORMAT_HOOK = REPO_ROOT / ".codex" / "hooks" / "clang_format_after_edit.py"


class HookToolingTests(unittest.TestCase):
    def run_change_record_check(self, staged_files: str) -> subprocess.CompletedProcess[str]:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("POSIX sh is not available")

        env = os.environ.copy()
        env["GIT_STAGED_FILES"] = staged_files
        return subprocess.run(
            [shell, str(CHANGE_RECORD_SCRIPT), str(REPO_ROOT)],
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_pre_commit_runs_project_safety_and_test_shape_gates(self) -> None:
        # GIVEN the checked-in pre-commit hook template.
        self.assertTrue(PRE_COMMIT_HOOK.is_file(), "pre-commit hook template is missing")
        hook = PRE_COMMIT_HOOK.read_text(encoding="utf-8")

        # WHEN developers install the hook.
        # THEN commits run the fast project safety and BDD registration gates.
        self.assertIn("bash scripts/reject-unsafe.sh", hook)
        self.assertIn("sh scripts/check-catch2-bdd-tests.sh", hook)
        self.assertIn("sh scripts/check-unit-test-registration.sh", hook)
        self.assertIn("sh scripts/check-staged-changelog-docs.sh", hook)

    def test_codex_post_edit_hook_formats_cpp_sources(self) -> None:
        # GIVEN the project-local Codex hook configuration.
        self.assertTrue(CODEX_HOOKS_CONFIG.is_file(), "Codex hooks config is missing")
        self.assertTrue(CODEX_CLANG_FORMAT_HOOK.is_file(), "Codex clang-format hook is missing")
        config = CODEX_HOOKS_CONFIG.read_text(encoding="utf-8")
        hook = CODEX_CLANG_FORMAT_HOOK.read_text(encoding="utf-8")

        # WHEN Codex finishes an edit/write tool call.
        # THEN C and C++ files are routed through the clang-format hook.
        self.assertIn('"PostToolUse"', config)
        self.assertIn("^apply_patch$|^Edit$|^Write$", config)
        self.assertIn("clang_format_after_edit.py", config)
        self.assertIn("FORMATTED_SUFFIXES", hook)
        self.assertIn("clang-format", hook)

    def test_project_changes_require_changelog_and_docs_updates(self) -> None:
        # GIVEN a staged production source change without matching records.
        result = self.run_change_record_check("src/main.cpp\n")

        # WHEN the changelog/docs guard runs.
        # THEN it rejects the staged files and reports both missing records.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CHANGELOG.md", result.stderr)
        self.assertIn("docs/*.md", result.stderr)

    def test_project_changes_pass_with_changelog_and_docs_updates(self) -> None:
        # GIVEN a staged source change with the required process records.
        result = self.run_change_record_check(
            "src/main.cpp\nCHANGELOG.md\ndocs/dev-environment.md\n"
        )

        # WHEN the changelog/docs guard runs.
        # THEN it accepts the staged set.
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_docs_only_changes_do_not_require_an_extra_changelog_record(self) -> None:
        # GIVEN a staged docs-only edit.
        result = self.run_change_record_check("docs/dev-environment.md\n")

        # WHEN the changelog/docs guard runs.
        # THEN it does not force a second documentation or changelog edit.
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
