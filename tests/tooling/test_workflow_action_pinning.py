#!/usr/bin/env python3
"""Every third-party action a workflow uses is pinned to a full commit SHA, with the
release it was taken from in a trailing comment (ADR-0266). A tag can be moved to other
code by whoever controls the action's repository; a commit SHA cannot. GitHub's own
actions (`actions/*`, `github/*`) and this repository's reusable workflows (`./...`) may
use a tag."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# PyYAML is not available to the tooling tests, so `uses` entries are found line by line. A
# `uses` key may be bare or quoted, in block or flow style; it must start a mapping entry (line
# start, `- `, `{` or `,`), so `causes:` does not match. Its value may follow on the same line or,
# as a plain or block (`|`, `>`) scalar, on the next non-blank line. Anything this cannot place
# fails the pinning checks rather than passing them: the target then keeps its stray characters.
USES_KEY = re.compile(r"""(?:^|[\s{,])(?:-\s+)?(?P<kq>["']?)uses(?P=kq)\s*:(?P<after>.*)$""")
VALUE = re.compile(r"""^\s*(?P<vq>["']?)(?P<target>[^\s"',{}#|>]+)(?P=vq)(?P<rest>.*)$""")
NO_INLINE_VALUE = re.compile(r"^\s*(?:[|>][-+0-9]*)?\s*(?:#.*)?$")
BLOCK_SCALAR_HEADER = re.compile(r":\s+[|>][-+0-9]*\s*(?:#.*)?$")
KEY_PREFIX = re.compile(r"^\s*(?:-\s+)*")
RELEASE_COMMENT = re.compile(r"\s#\s*v\d+\.\d+\.\d+\s*$")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
TAG_ALLOWED_OWNERS = ("actions", "github")


def is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def key_column(line: str) -> int:
    # The column a mapping key starts in, after any `- ` sequence markers.
    return len(KEY_PREFIX.match(line).group(0))


def uses_entries(lines: list[str]) -> list[tuple[int, str, str]]:
    """(1-based line number of the value, action reference, text after it) for each `uses`.

    The content of a block scalar (`run: |`, `run: >-`, ...) is text, not mapping entries, so a
    `uses:` inside a script is not an action. YAML ends a block scalar at the first non-blank line
    indented no deeper than its key; only lines deeper than that are skipped, so a following step
    or sibling key is always read."""
    found = []
    block_key_column = None
    for index, line in enumerate(lines):
        if block_key_column is not None:
            if not line.strip() or indentation(line) > block_key_column:
                continue
            block_key_column = None
        if is_comment_or_blank(line):
            continue
        if BLOCK_SCALAR_HEADER.search(line):
            block_key_column = key_column(line)
        key = USES_KEY.search(line)
        if key is None:
            continue
        after = key["after"]
        value = VALUE.match(after)
        if value is not None:
            found.append((index + 1, value["target"], value["rest"]))
            continue
        if not NO_INLINE_VALUE.match(after):
            found.append((index + 1, after.strip(), ""))
            continue
        following = next((i for i in range(index + 1, len(lines)) if not is_comment_or_blank(lines[i])), None)
        if following is None:
            found.append((index + 1, "", ""))
            continue
        value = VALUE.match(lines[following])
        if value is None:
            found.append((following + 1, lines[following].strip(), ""))
        else:
            found.append((following + 1, value["target"], value["rest"]))
    return found


def uses_in_line(line: str) -> tuple[str, str] | None:
    found = uses_entries([line])
    return None if not found else (found[0][1], found[0][2])


def names_a_release(rest: str) -> bool:
    # The comment may follow a closing quote or flow-mapping brace: `...@<sha>} # v1.2.3`.
    return RELEASE_COMMENT.search(rest) is not None


def workflow_uses() -> list[tuple[str, int, str, str]]:
    found = []
    for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for number, target, rest in uses_entries(lines):
            found.append((workflow.name, number, target, rest))
    return found


def is_third_party(target: str) -> bool:
    if target.startswith("./"):
        return False
    return target.split("/", 1)[0] not in TAG_ALLOWED_OWNERS


class UsesMatcherTest(unittest.TestCase):
    """The pinning tests are only as strong as the matcher: a `uses:` it cannot see is never
    checked. Every YAML spelling of the key and value must be found."""

    def test_given_each_spelling_of_uses_when_matched_then_the_action_is_found(self) -> None:
        spellings = {
            "      - uses: vendor/action@v1": "vendor/action@v1",
            "        uses: vendor/action@v1": "vendor/action@v1",
            '      - "uses": vendor/action@v1': "vendor/action@v1",
            "      - 'uses': vendor/action@v1": "vendor/action@v1",
            '      - uses: "vendor/action@v1"': "vendor/action@v1",
            "      - uses: 'vendor/action@v1'": "vendor/action@v1",
            "      - {uses: vendor/action@v1}": "vendor/action@v1",
            '      - { name: x, "uses": vendor/action@v1 }': "vendor/action@v1",
        }
        for line, expected in spellings.items():
            with self.subTest(line=line):
                found = uses_in_line(line)
                self.assertIsNotNone(found)
                self.assertEqual(expected, found[0])

    def test_given_a_value_on_the_next_line_when_matched_then_the_action_is_found(self) -> None:
        layouts = {
            "plain scalar": ["      - uses:", "          vendor/action@v1", "        with:"],
            "after a blank line": ["      - uses:", "", "          vendor/action@v1"],
            "folded scalar": ["      - uses: >-", "          vendor/action@v1"],
            "literal scalar": ["      - uses: |", "          vendor/action@v1"],
            "quoted on the next line": ["      - uses:", '          "vendor/action@v1"'],
        }
        for layout, lines in layouts.items():
            with self.subTest(layout=layout):
                found = uses_entries(lines)
                self.assertEqual(1, len(found))
                self.assertEqual("vendor/action@v1", found[0][1])

    def test_given_uses_text_inside_a_block_scalar_when_matched_then_it_is_not_an_action(self) -> None:
        for header in ("run: |", "run: >-", "run: |+ # script"):
            with self.subTest(header=header):
                lines = [
                    f"      - {header}",
                    "          echo 'uses: vendor/script-text@v1'",
                    "",
                    "          uses: vendor/indented-text@v1",
                ]
                self.assertEqual([], uses_entries(lines))

    def test_given_an_action_after_a_block_scalar_when_matched_then_it_is_still_found(self) -> None:
        # The block ends at the first line indented no deeper than its key, so the
        # skipping can never swallow a real step or a sibling key.
        lines = [
            "      - name: build",
            "        run: |",
            "          uses: vendor/script-text@v1",
            "        uses: vendor/sibling@v1",
            "      - run: >",
            "          more text",
            "      - uses: vendor/next-step@v1",
        ]
        self.assertEqual(
            ["vendor/sibling@v1", "vendor/next-step@v1"], [target for _, target, _ in uses_entries(lines)]
        )

    def test_given_uses_as_a_block_scalar_when_matched_then_its_value_is_read_once(self) -> None:
        lines = ["      - uses: >-", "          vendor/action@v1", "      - uses: vendor/other@v1"]
        self.assertEqual(["vendor/action@v1", "vendor/other@v1"], [target for _, target, _ in uses_entries(lines)])

    def test_given_a_pin_with_its_comment_when_matched_then_the_comment_is_recognised(self) -> None:
        sha = "a" * 40
        spellings = (
            f'      - uses: "vendor/action@{sha}" # v1.2.3',
            f"      - {{uses: vendor/action@{sha}}} # v1.2.3",
            f"      - {{uses: vendor/action@{sha}, name: x}} # v1.2.3",
        )
        for line in spellings:
            with self.subTest(line=line):
                found = uses_in_line(line)
                self.assertIsNotNone(found)
                self.assertTrue(PINNED.match(found[0]))
                self.assertTrue(names_a_release(found[1]))

    def test_given_a_pin_without_a_release_comment_when_matched_then_no_release_is_named(self) -> None:
        for rest in ("", "}", " # pinned", "  # v1.2"):
            with self.subTest(rest=rest):
                self.assertFalse(names_a_release(rest))

    def test_given_a_key_that_only_ends_in_uses_when_matched_then_nothing_is_found(self) -> None:
        self.assertIsNone(uses_in_line("        causes: vendor/action@v1"))


class WorkflowActionPinningTest(unittest.TestCase):
    def test_given_the_workflows_when_read_then_they_use_third_party_actions(self) -> None:
        # Guards the other tests against passing because nothing was parsed.
        self.assertTrue(any(is_third_party(target) for _, _, target, _ in workflow_uses()))

    def test_given_a_third_party_action_when_used_then_it_is_pinned_to_a_full_commit_sha(self) -> None:
        unpinned = [
            f"{name}:{number} {target}"
            for name, number, target, _ in workflow_uses()
            if is_third_party(target) and not PINNED.match(target)
        ]
        self.assertEqual([], unpinned)

    def test_given_a_pinned_action_when_used_then_a_comment_names_its_release(self) -> None:
        uncommented = [
            f"{name}:{number} {target}"
            for name, number, target, rest in workflow_uses()
            if is_third_party(target) and not names_a_release(rest)
        ]
        self.assertEqual([], uncommented)

    def test_given_one_action_when_pinned_in_several_places_then_every_place_uses_the_same_commit(self) -> None:
        commits: dict[str, set[str]] = {}
        for _, _, target, _ in workflow_uses():
            if is_third_party(target) and "@" in target:
                action, ref = target.rsplit("@", 1)
                commits.setdefault(action, set()).add(ref)
        self.assertEqual({}, {action: refs for action, refs in commits.items() if len(refs) > 1})


if __name__ == "__main__":
    unittest.main()
