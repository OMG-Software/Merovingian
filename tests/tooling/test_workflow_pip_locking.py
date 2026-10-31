#!/usr/bin/env python3
"""Every `pip install` a workflow runs installs hash-locked wheels from a requirements file
(ADR-0313). A package resolved at run time can be any release PyPI serves that day, and an
sdist runs its own setup script while it installs; either way unreviewed code runs in the job,
next to its token and, in release.yml, inside the packages that are published."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# pip's global options (`--disable-pip-version-check`, `-q`, ...) may stand between `pip` and
# `install`, so anything up to the first `install` word counts.
PIP_INSTALL = re.compile(r"\bpip3?\b(?:\s+\S+)*?\s+install\b(?P<arguments>.*)$")
HASH_LINE = re.compile(r"--hash=sha256:[0-9a-f]{64}")
# A `run:` value on the key's own line that is not a block scalar or quoted is a YAML plain scalar.
PLAIN_RUN = re.compile(r"""^\s*(?:-\s+)?run:\s+(?P<value>[^\s|>"'].*)$""")


def install_arguments(line: str) -> str | None:
    """The arguments after `pip install` on a workflow line, or None if it installs nothing."""
    if line.strip().startswith("#"):
        return None
    match = PIP_INSTALL.search(line)
    return match.group("arguments") if match else None


def workflows() -> list[Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """(1-based number of the first physical line, the line) with each shell continuation (a line
    ending in a backslash) joined to the next, as the shell runs them. PyYAML is not available to
    the tooling tests (see test_workflow_action_pinning.py), so `run:` scripts are read as text."""
    joined = []
    start, pending = 0, ""
    for number, line in enumerate(lines, start=1):
        if not pending:
            start = number
            if line.lstrip().startswith("#"):
                # A comment runs to the end of its line; a trailing backslash continues nothing.
                joined.append((start, line))
                continue
        if line.endswith("\\"):
            # Only a backslash that is the line's last character continues it (`\ ` escapes a
            # space). The shell removes just the backslash-newline pair; option checks split on
            # whitespace.
            pending += line[:-1]
            continue
        joined.append((start, pending + line))
        pending = ""
    if pending:
        joined.append((start, pending))
    return joined


def install_options(arguments: str) -> tuple[set[str], list[str], list[str]]:
    """The locking options, the requirements files, and every other word of a `pip install`'s
    arguments, read as whitespace-separated shell words."""
    words = arguments.split()
    options, requirements, others = set(), [], []
    index = 0
    while index < len(words):
        word = words[index]
        following = words[index + 1] if index + 1 < len(words) else None
        if word == "--require-hashes":
            options.add(word)
        elif word == "--only-binary=:all:" or (word == "--only-binary" and following == ":all:"):
            options.add("--only-binary :all:")
            index += 0 if "=" in word else 1
        elif word in ("-r", "--requirement") and following is not None:
            requirements.append(following)
            index += 1
        elif word.startswith("--requirement="):
            requirements.append(word.split("=", 1)[1])
        else:
            others.append(word)
        index += 1
    return options, requirements, others


def pip_install_lines() -> list[tuple[str, int, str, str]]:
    """(workflow file name, 1-based line number, the line, the arguments after `pip install`)."""
    found = []
    for workflow in workflows():
        for number, line in logical_lines(workflow.read_text(encoding="utf-8").splitlines()):
            arguments = install_arguments(line)
            if arguments is not None:
                found.append((workflow.name, number, line, arguments))
    return found


def pip_installs() -> list[tuple[str, int, str]]:
    """(workflow file name, 1-based line number, the arguments after `pip install`)."""
    return [(workflow, number, arguments) for workflow, number, _, arguments in pip_install_lines()]


class WorkflowPipLockingTests(unittest.TestCase):
    def test_given_the_workflows_when_read_then_some_install_python_packages(self) -> None:
        # Guards the checks below against passing because the pattern matched nothing.
        self.assertGreater(len(pip_installs()), 0)

    def test_given_pip_global_options_before_install_when_parsed_then_the_install_is_found(self) -> None:
        self.assertEqual(install_arguments("python -m pip --disable-pip-version-check install meson"), " meson")
        self.assertEqual(install_arguments("pip3 -q install -r x.txt"), " -r x.txt")
        self.assertEqual(install_arguments("          python -m pip install --upgrade pip"), " --upgrade pip")

    def test_given_a_shell_line_continuation_when_read_then_the_install_is_found(self) -> None:
        # The shell runs `pip \` + `install meson` as one command, so the check must too.
        lines = logical_lines(["          python -m pip \\", "            install meson", "          meson setup build"])
        self.assertEqual([(number, install_arguments(line)) for number, line in lines],
                         [(1, " meson"), (3, None)])

    def test_given_a_comment_ending_in_a_backslash_when_read_then_the_next_install_is_still_found(self) -> None:
        # A shell comment runs to the end of its line; its backslash continues nothing.
        lines = logical_lines(["          # build tools \\", "          python -m pip install meson"])
        self.assertEqual([(number, install_arguments(line)) for number, line in lines],
                         [(1, None), (2, " meson")])

    def test_given_a_backslash_followed_by_whitespace_when_read_then_the_next_line_is_its_own_command(self) -> None:
        # `\ ` escapes the space; only a backslash that is the line's last character continues it.
        lines = logical_lines(["          python -m pip install meson \\ ",
                               "            --require-hashes --only-binary :all: -r requirements-build.txt"])
        self.assertEqual([number for number, _ in lines], [1, 2])
        self.assertEqual(install_options(install_arguments(lines[0][1]))[0], set())

    def test_given_options_split_across_a_continuation_when_parsed_then_they_still_lock_the_install(self) -> None:
        # The shell drops only the backslash-newline, so the next line's indentation stays.
        (_, line), = logical_lines(["          python -m pip install --require-hashes --only-binary \\",
                                    "            :all: --requirement requirements-build.txt"])
        self.assertEqual(install_options(install_arguments(line)),
                         ({"--require-hashes", "--only-binary :all:"}, ["requirements-build.txt"], []))

    def test_given_lines_that_install_nothing_when_parsed_then_none_is_found(self) -> None:
        self.assertIsNone(install_arguments("# python -m pip install meson"))
        self.assertIsNone(install_arguments("python -m pip list"))
        self.assertIsNone(install_arguments("sudo apt-get install -y python3-pip"))

    def test_given_an_install_on_a_plain_run_value_when_read_then_it_holds_no_colon_space(self) -> None:
        # In a YAML plain scalar ": " starts a mapping, so `--only-binary :all: --requirement ...`
        # on `run:`'s own line makes the whole workflow fail to load. Use a block scalar (`run: |`).
        for workflow, number, line, _ in pip_install_lines():
            plain = PLAIN_RUN.match(line)
            if plain is None:
                continue
            with self.subTest(workflow=workflow, line=number):
                self.assertNotIn(": ", plain.group("value"))

    def test_given_any_workflow_pip_install_when_read_then_it_requires_hashes(self) -> None:
        for workflow, number, arguments in pip_installs():
            with self.subTest(workflow=workflow, line=number):
                self.assertIn("--require-hashes", install_options(arguments)[0])

    def test_given_any_workflow_pip_install_when_read_then_it_installs_wheels_only(self) -> None:
        for workflow, number, arguments in pip_installs():
            with self.subTest(workflow=workflow, line=number):
                self.assertIn("--only-binary :all:", install_options(arguments)[0])

    def test_given_any_workflow_pip_install_when_read_then_it_reads_a_locked_requirements_file(self) -> None:
        for workflow, number, arguments in pip_installs():
            with self.subTest(workflow=workflow, line=number):
                _, requirements, others = install_options(arguments)
                self.assertTrue(requirements, "installs named packages instead of a requirements file")
                # Nothing else may be named: a bare package beside the file is unlocked.
                self.assertEqual(others, [])
                for requirement in requirements:
                    locked = REPO_ROOT / requirement
                    self.assertTrue(locked.is_file(), f"{locked} is missing")
                    self.assertRegex(locked.read_text(encoding="utf-8"), HASH_LINE)

    def test_given_a_locked_requirements_file_when_read_then_its_regeneration_command_is_wheel_only(self) -> None:
        # A lock regenerated without --only-binary could take an sdist that the install then refuses.
        for workflow, number, arguments in pip_installs():
            for requirement in install_options(arguments)[1]:
                locked = REPO_ROOT / requirement
                with self.subTest(requirements=locked.name):
                    self.assertIn("--only-binary :all:", locked.read_text(encoding="utf-8").splitlines()[1])


if __name__ == "__main__":
    unittest.main()
