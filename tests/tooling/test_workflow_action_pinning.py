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

# A `uses` key in block or flow style, bare or quoted, with a bare or quoted value. The key
# must start a mapping entry (line start, `- `, `{` or `,`), so `causes:` does not match.
# PyYAML is not available to the tooling tests; a line this cannot place fails the pinning
# checks rather than passing them, because the target then carries the stray characters.
USES = re.compile(
    r"""(?:^|[\s{,])(?:-\s+)?(?P<kq>["']?)uses(?P=kq)\s*:\s*"""
    r"""(?P<vq>["']?)(?P<target>[^\s"',{}#]+)(?P=vq)(?P<rest>.*)$"""
)
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s+#\s*v\d+\.\d+\.\d+\s*$")
TAG_ALLOWED_OWNERS = ("actions", "github")


def uses_in_line(line: str) -> tuple[str, str] | None:
    match = USES.search(line)
    return None if match is None else (match["target"], match["rest"])


def workflow_uses() -> list[tuple[str, int, str, str]]:
    found = []
    for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            match = uses_in_line(line)
            if match:
                found.append((workflow.name, number, match[0], match[1]))
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

    def test_given_a_quoted_pin_with_its_comment_when_matched_then_the_comment_is_recognised(self) -> None:
        found = uses_in_line(f'      - uses: "vendor/action@{"a" * 40}" # v1.2.3')
        self.assertIsNotNone(found)
        self.assertTrue(PINNED.match(found[0]))
        self.assertTrue(VERSION_COMMENT.match(found[1]))

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
            if is_third_party(target) and not VERSION_COMMENT.match(rest)
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
