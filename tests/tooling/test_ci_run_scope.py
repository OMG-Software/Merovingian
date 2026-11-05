#!/usr/bin/env python3
"""A pull request's head runs each workflow once, and the PostgreSQL job runs only what uses PostgreSQL (ADR-0511)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
INTEGRATION_TESTS = REPO_ROOT / "tests" / "integration"

# The documentation site builds strictly on every branch by design (test_docs_site.py), and that takes under a minute.
RUNS_ON_EVERY_PUSH_BY_DESIGN = {"pages.yml"}

# Names only ever pushed by an automated agent, which may not open a pull request.
PUSH_BRANCHES_WITHOUT_A_PULL_REQUEST = {"main", "master", "claude/**", "codex/**", "alpha-release"}

USES_POSTGRESQL = re.compile(
    r"POSTGRESQL_URI|postgresql_uri|open_postgresql_persistent_store|ScratchPostgresql\w*|database\.backend\s*=\s*\"postgresql"
)
SCENARIO_START = re.compile(r"^(?:SCENARIO|TEST_CASE)\(", re.MULTILINE)


def triggers(workflow: Path) -> str:
    text = workflow.read_text(encoding="utf-8")
    match = re.search(r"^on:\n(.*?)(?=^[a-z_]+:)", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def push_trigger(workflow: Path) -> str | None:
    """The body of the `push:` trigger, or None when the workflow has no such trigger."""
    match = re.search(r"^  push:[ \t]*\n((?:    .*\n|\s*\n)*)", triggers(workflow), flags=re.MULTILINE)
    return match.group(1) if match else None


def push_branches(body: str) -> set[str]:
    inline = re.search(r"branches:\s*\[(.*?)\]", body)
    if inline:
        return {item.strip().strip("'\"") for item in inline.group(1).split(",")}
    return {item.strip().strip("'\"") for item in re.findall(r"^\s*-\s*(\S+)\s*$", body, flags=re.MULTILINE)}


class ARunOncePerPullRequestHead(unittest.TestCase):
    def test_given_a_workflow_on_both_events_when_a_pull_request_branch_is_pushed_then_only_one_event_fires(self) -> None:
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            if workflow.name in RUNS_ON_EVERY_PUSH_BY_DESIGN or "pull_request:" not in triggers(workflow):
                continue
            body = push_trigger(workflow)
            if body is None:
                continue
            with self.subTest(workflow=workflow.name):
                self.assertIn("branches", body, "a bare push trigger also fires for every pull request branch")
                extra = push_branches(body) - PUSH_BRANCHES_WITHOUT_A_PULL_REQUEST
                self.assertEqual(extra, set(), "these branches also get the pull_request run")

    def test_given_the_required_sanitizer_and_tidy_checks_when_main_or_a_pull_request_runs_then_they_still_run(self) -> None:
        for name in ("sanitizers.yml", "static-analysis.yml"):
            with self.subTest(workflow=name):
                on = triggers(WORKFLOWS / name)
                self.assertRegex(on, r"(?m)^  pull_request:[ \t]*$", "must run for a pull request of any base")
                body = push_trigger(WORKFLOWS / name)
                self.assertIsNotNone(body)
                self.assertIn("main", push_branches(body or ""))

    def test_given_the_packages_workflow_when_main_is_pushed_then_it_still_runs(self) -> None:
        body = push_trigger(WORKFLOWS / "packages.yml")
        self.assertIsNotNone(body)
        self.assertIn("main", push_branches(body or ""))


class ThePostgresqlJob(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (WORKFLOWS / "postgres-integration.yml").read_text(encoding="utf-8")

    def test_given_the_job_when_it_builds_then_it_compiles_the_integration_binary_without_running_the_suite(self) -> None:
        self.assertIn("sh scripts/build-linux.sh --builddir build --setup-only", self.workflow)
        self.assertIn("meson compile -C build merovingian-integration-tests", self.workflow)
        self.assertNotRegex(self.workflow, r"build-linux\.sh --builddir build\s*$")
        self.assertNotIn("meson test", self.workflow)

    def test_given_the_job_when_it_tests_then_it_selects_every_scenario_tagged_postgresql(self) -> None:
        self.assertIn('./build/tests/merovingian-integration-tests "[postgresql]"', self.workflow)

    def test_given_a_scenario_that_reaches_postgresql_when_it_is_written_then_it_carries_the_tag_the_job_selects(self) -> None:
        untagged = []
        for path in sorted(INTEGRATION_TESTS.glob("test_*.cpp")):
            text = path.read_text(encoding="utf-8")
            starts = [match.start() for match in SCENARIO_START.finditer(text)]
            for start in starts:
                closing = text.find("\n}\n", start)
                scenario = text[start : closing if closing != -1 else len(text)]
                if USES_POSTGRESQL.search(scenario) and "[postgresql]" not in scenario.split("{", 1)[0]:
                    untagged.append(f"{path.name}: {scenario.splitlines()[0][:90]}")
        self.assertEqual(untagged, [])


if __name__ == "__main__":
    unittest.main()
