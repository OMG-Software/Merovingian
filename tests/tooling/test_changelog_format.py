#!/usr/bin/env python3
"""Hold CHANGELOG.md to the format in docs/versioning.md (ADR-0741)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
MESON_BUILD = REPO_ROOT / "meson.build"

VERSION_HEADING = re.compile(r"^# Version (\d+)\.(\d+)\.(\d+)$")
SECTIONS = ("Features", "Security Fixes", "Bug fixes", "Release notes")
BULLET_SECTIONS = SECTIONS[:-1]
MAX_LINE = 120
MAX_BULLET_LINES = 2


def format_problems(text: str) -> list[str]:
    """Return every way text breaks the changelog format; empty when it holds."""
    problems: list[str] = []
    lines = text.split("\n")
    for number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE:
            problems.append(f"line {number} is {len(line)} characters, over {MAX_LINE}")
        if line != line.rstrip():
            problems.append(f"line {number} has trailing whitespace")

    versions: list[tuple[int, int, int]] = []
    version: str | None = None
    section: str | None = None
    seen: list[str] = []
    body: list[tuple[int, str]] = []

    def close_section() -> None:
        if version is None or section is None:
            return
        problems.extend(section_problems(version, section, body))

    def close_version() -> None:
        close_section()
        if version is not None and tuple(seen) != SECTIONS:
            problems.append(f"{version} has sections {seen}, expected {list(SECTIONS)} in that order")

    for number, line in enumerate(lines, start=1):
        if line.startswith("#"):
            match = VERSION_HEADING.match(line)
            if match:
                close_version()
                version = line[2:]
                versions.append(tuple(int(part) for part in match.groups()))
                section = None
                seen = []
                body = []
            elif line.startswith("## ") and version is not None:
                close_section()
                section = line[3:]
                seen.append(section)
                body = []
            else:
                problems.append(f"line {number}: heading {line!r} is not '# Version X.Y.Z' or a section")
        elif section is not None:
            body.append((number, line))
        elif version is not None and line.strip():
            problems.append(f"line {number}: text under {version} before its first section")
    close_version()

    if not versions:
        problems.append("no '# Version X.Y.Z' heading")
    if versions != sorted(versions, reverse=True) or len(set(versions)) != len(versions):
        problems.append("versions are not unique and newest first")
    return problems


def section_problems(version: str, section: str, body: list[tuple[int, str]]) -> list[str]:
    where = f"{version} / {section}"
    if section not in SECTIONS:
        return [f"{where}: unknown section"]
    content = [(number, line) for number, line in body if line.strip()]
    if not content:
        return [f"{where}: empty; write '* None.' instead"]

    if section not in BULLET_SECTIONS:
        numbers = [number for number, _ in content]
        problems = []
        if numbers != list(range(numbers[0], numbers[-1] + 1)):
            problems.append(f"{where}: more than one paragraph")
        if any(line.startswith(("* ", "- ")) for _, line in content):
            problems.append(f"{where}: a paragraph, not a list")
        return problems

    problems = []
    bullet_lines = 0
    for number, line in content:
        if line.startswith("* "):
            bullet_lines = 1
        elif line.startswith("  ") and bullet_lines:
            bullet_lines += 1
            if bullet_lines > MAX_BULLET_LINES:
                problems.append(f"line {number}: {where} bullet runs over {MAX_BULLET_LINES} lines")
        else:
            problems.append(f"line {number}: {where} holds '* ' bullets only")
    return problems


def meson_version() -> str:
    match = re.search(r"version\s*:\s*'(\d+\.\d+\.\d+)'", MESON_BUILD.read_text(encoding="utf-8"))
    if match is None:
        raise AssertionError("meson.build declares no project version")
    return match.group(1)


GOOD = """Intro line.

# Version 1.0.1

## Features

* One feature that wraps
  onto a second line.

## Security Fixes

* None.

## Bug fixes

* A fix.

## Release notes

A short paragraph
over two lines.

# Version 1.0.0

## Features

* Versioning.

## Security Fixes

* None.

## Bug fixes

* None.

## Release notes

First release.
"""


class ChangelogFormatTests(unittest.TestCase):
    def test_the_repository_changelog_holds_the_format(self) -> None:
        # GIVEN the checked-in changelog.
        text = CHANGELOG.read_text(encoding="utf-8")

        # WHEN it is checked against the format.
        problems = format_problems(text)

        # THEN it holds, and its newest version is the one meson.build declares.
        self.assertEqual(problems, [])
        first = next(line for line in text.split("\n") if VERSION_HEADING.match(line))
        self.assertEqual(first, f"# Version {meson_version()}")

    def test_a_well_formed_changelog_passes(self) -> None:
        # GIVEN a changelog with two versions in the format.
        # WHEN it is checked.
        # THEN nothing is reported.
        self.assertEqual(format_problems(GOOD), [])

    def test_each_departure_from_the_format_is_reported(self) -> None:
        # GIVEN changelogs that each break one rule.
        cases = {
            "three-line bullet": GOOD.replace("onto a second line.", "onto a second line,\n  and a third."),
            "missing section": GOOD.replace("## Security Fixes\n\n* None.\n\n## Bug fixes\n\n* A fix.", "## Bug fixes\n\n* A fix.", 1),
            "sections out of order": GOOD.replace("## Features\n\n* Versioning.", "## Bug fixes\n\n* Versioning.", 1),
            "old version heading": GOOD.replace("# Version 1.0.0", "## 1.0.0"),
            "subsection": GOOD.replace("* A fix.", "### Detail\n\n* A fix."),
            "empty section": GOOD.replace("## Bug fixes\n\n* A fix.", "## Bug fixes\n"),
            "prose in a list section": GOOD.replace("* A fix.", "A fix."),
            "two release-note paragraphs": GOOD.replace("over two lines.", "over two lines.\n\nAnd another."),
            "versions oldest first": GOOD.replace("# Version 1.0.1", "# Version 0.9.9"),
            "line over 120 characters": GOOD.replace("* A fix.", "* " + "x" * 119),
        }
        for name, text in cases.items():
            with self.subTest(name):
                # WHEN each is checked.
                # THEN the departure is reported.
                self.assertNotEqual(format_problems(text), [], name)


if __name__ == "__main__":
    unittest.main()
