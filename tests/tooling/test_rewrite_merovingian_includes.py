#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "rewrite_merovingian_includes.py"


class RewriteMerovingianIncludesTests(unittest.TestCase):
    def test_rewrites_angle_bracket_project_includes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            # GIVEN a source file with Merovingian project includes in angle brackets.
            source = Path(temporary_directory) / "example.cpp"
            source.write_text(
                '#include <merovingian/core/not_null.hpp>\n'
                '#include <vector>\n'
                '#include "merovingian/already_quoted.hpp"\n'
                '  # include <merovingian/http/request.hpp> // keep comment\n',
                encoding="utf-8",
            )

            # WHEN the rewrite tool runs against the file.
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )

            # THEN only angle-bracket Merovingian includes are quoted.
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                source.read_text(encoding="utf-8"),
                '#include "merovingian/core/not_null.hpp"\n'
                '#include <vector>\n'
                '#include "merovingian/already_quoted.hpp"\n'
                '  # include "merovingian/http/request.hpp" // keep comment\n',
            )

    def test_check_mode_reports_pending_rewrites_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            # GIVEN a source file that still uses an angle-bracket project include.
            source = Path(temporary_directory) / "example.hpp"
            original = '#include <merovingian/events/event.hpp>\n'
            source.write_text(original, encoding="utf-8")

            # WHEN the tool runs in check mode.
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--check", str(source)],
                check=False,
                capture_output=True,
                text=True,
            )

            # THEN it exits non-zero and leaves the file unchanged.
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertIn("need include rewriting", result.stderr)

    def test_skips_clwb_and_build_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            # GIVEN ignored workspace directories containing matching includes.
            root = Path(temporary_directory)
            skipped_clwb = root / ".clwb" / "ignored.cpp"
            skipped_build = root / "build-test" / "ignored.cpp"
            included = root / "src" / "kept.cpp"
            skipped_clwb.parent.mkdir(parents=True)
            skipped_build.parent.mkdir(parents=True)
            included.parent.mkdir(parents=True)
            for source in (skipped_clwb, skipped_build, included):
                source.write_text('#include <merovingian/core/id.hpp>\n', encoding="utf-8")

            # WHEN the tool scans the root directory.
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(root)],
                check=False,
                capture_output=True,
                text=True,
            )

            # THEN ignored directories stay untouched while normal source files are rewritten.
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                skipped_clwb.read_text(encoding="utf-8"),
                '#include <merovingian/core/id.hpp>\n',
            )
            self.assertEqual(
                skipped_build.read_text(encoding="utf-8"),
                '#include <merovingian/core/id.hpp>\n',
            )
            self.assertEqual(
                included.read_text(encoding="utf-8"),
                '#include "merovingian/core/id.hpp"\n',
            )

            # WHEN an ignored directory is passed directly.
            skipped_clwb.write_text('#include <merovingian/core/id.hpp>\n', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(skipped_clwb.parent)],
                check=False,
                capture_output=True,
                text=True,
            )

            # THEN direct ignored paths are still skipped.
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                skipped_clwb.read_text(encoding="utf-8"),
                '#include <merovingian/core/id.hpp>\n',
            )


if __name__ == "__main__":
    unittest.main()
