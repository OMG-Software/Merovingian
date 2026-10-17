#!/usr/bin/env python3
"""Every tracked text file checks out with LF line endings, whatever the platform.

A Windows checkout with core.autocrlf=true otherwise writes CRLF into the working
tree. The systemd unit then failed the "[platform][iso8]" unit scenario (it searches
for "\\nRestrictAddressFamilies=...\\n"), and a package built from such a checkout
would ship CRLF maintainer scripts and unit files (ADR-0158).
"""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Windows-only scripts are the one deliberate exception.
CRLF_SUFFIXES = (".ps1", ".cmd")


def tracked_eol_report() -> list[tuple[str, str, str, str]] | None:
    """Return (index_eol, worktree_eol, attributes, path) for every tracked file.

    None when git cannot read this checkout: a source tarball, or a worktree created
    by Windows git and opened from WSL, whose .git file names a C:/ path.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "--eol", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    rows = []
    for record in result.stdout.decode("utf-8").split("\0"):
        if not record:
            continue
        info, path = record.split("\t", 1)
        # "i/lf    w/crlf  attr/text eol=crlf      ": the attributes field may hold spaces.
        index_eol, worktree_eol, attributes = (info.split(maxsplit=2) + ["", "", ""])[:3]
        attributes = attributes.strip()
        rows.append((index_eol, worktree_eol, attributes, path))
    return rows


def attributes_of(path: str) -> dict[str, str]:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-attr", "text", "eol", "--", path],
        check=True,
        capture_output=True,
        text=True,
    )
    values = {}
    for line in result.stdout.splitlines():
        _, name, value = line.rsplit(": ", 2)
        values[name] = value
    return values


class LineEndingAttributesTest(unittest.TestCase):
    rows: list[tuple[str, str, str, str]] | None = None

    @classmethod
    def setUpClass(cls) -> None:
        # One scan for the whole class: `git ls-files --eol` reads every tracked
        # file, which takes several seconds on a WSL /mnt/c checkout, and running
        # it before each test pushed the suite past Meson's 30 s default timeout.
        cls.rows = tracked_eol_report()

    def setUp(self) -> None:
        if self.rows is None:
            self.skipTest("git cannot read this checkout; line-ending attributes are checked where it can")

    def test_given_the_packaged_systemd_unit_when_its_attributes_are_read_then_it_checks_out_with_lf(self) -> None:
        values = attributes_of("packaging/systemd/merovingian.service")
        self.assertEqual(values.get("eol"), "lf")
        self.assertNotEqual(values.get("text"), "unset")

    def test_given_every_tracked_text_file_when_its_attributes_are_read_then_it_checks_out_with_lf(self) -> None:
        wrong = [
            path
            for index_eol, _, attributes, path in self.rows
            if index_eol != "i/-text"
            and not path.endswith(CRLF_SUFFIXES)
            and "eol=lf" not in attributes
        ]
        self.assertEqual(wrong, [], "text files without eol=lf (first 20 shown): " + ", ".join(wrong[:20]))

    def test_given_windows_scripts_when_their_attributes_are_read_then_they_keep_crlf(self) -> None:
        for index_eol, _, attributes, path in self.rows:
            if path.endswith(CRLF_SUFFIXES):
                with self.subTest(path=path):
                    self.assertIn("eol=crlf", attributes)

    def test_given_the_index_when_line_endings_are_read_then_no_lf_file_is_stored_with_crlf(self) -> None:
        stored_crlf = [
            path
            for index_eol, _, _, path in self.rows
            if index_eol in ("i/crlf", "i/mixed") and not path.endswith(CRLF_SUFFIXES)
        ]
        self.assertEqual(stored_crlf, [])


if __name__ == "__main__":
    unittest.main()
