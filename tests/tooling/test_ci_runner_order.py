#!/usr/bin/env python3
"""Sonar and CodeQL take a runner as soon as a pull request is pushed (ADR-0580).

GitHub Actions has no job priority. Every workflow a push triggers creates its jobs at once, and the account runs at most
20 at a time; the rest wait in a queue. A job with `needs:` does not join that queue until what it needs has finished.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Hosted runners the account may use at once (GitHub Free for organisations).
RUNNER_CAP = 20
GATE = "queue-after-analyses"
GATED_WORKFLOWS = ("ci.yml", "packages.yml")
# The two long analyses that must not wait: about an hour and half an hour.
ANALYSES = (("sonarcloud.yml", "sonarcloud"), ("codeql.yml", "analyze"))

JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)


def triggers(text: str) -> str:
    match = re.search(r"^on:\n(.*?)(?=^[a-z_]+:)", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def runs_for_a_pull_request_to_main(text: str) -> bool:
    match = re.search(r"^  pull_request:[ \t]*\n((?:    .*\n|\s*\n)*)", triggers(text), flags=re.MULTILINE)
    if match is None:
        return False
    body = match.group(1)
    if "branches" not in body:
        return True
    return re.search(r"\bmain\b", body) is not None


def jobs(text: str) -> dict[str, str]:
    """Each top-level job's id and its own text, up to the next job."""
    section = text.split("\njobs:\n", 1)[1]
    headers = list(JOB_HEADER.finditer(section))
    return {
        header.group(1): section[header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(section)]
        for index, header in enumerate(headers)
    }


def needs(job: str) -> list[str]:
    match = re.search(r"^    needs:[ \t]*(.+)$", job, re.MULTILINE)
    if match is None:
        return []
    value = match.group(1).strip()
    if value.startswith("["):
        return [item.strip() for item in value.strip("[]").split(",") if item.strip()]
    return [value]


def job_if(job: str) -> str | None:
    """The job's condition on one line, a `|` block scalar's lines joined."""
    match = re.search(r"^    if:[ \t]*(.+)$", job, re.MULTILINE)
    if match is None:
        return None
    value = match.group(1).strip()
    if value in ("|", ">", "|-", ">-"):
        block = re.match(r"((?:      .*\n)+)", job[match.end() + 1 :])
        value = " ".join(block.group(1).split()) if block else ""
    return value


def downstream_of_the_gate(workflow_jobs: dict[str, str]) -> list[str]:
    """Jobs that wait for the gate through another job: the gate is an ancestor, not a direct need."""
    found: list[str] = []
    for job_id, job in workflow_jobs.items():
        pending = list(needs(job))
        if GATE in pending:
            continue
        seen: set[str] = set()
        while pending:
            ancestor = pending.pop()
            if ancestor in seen or ancestor not in workflow_jobs:
                continue
            seen.add(ancestor)
            pending.extend(needs(workflow_jobs[ancestor]))
        if GATE in seen:
            found.append(job_id)
    return found


def matrix_size(job: str) -> int:
    match = re.search(r"^      matrix:[ \t]*\n((?:        .*\n|\s*\n)*)", job, re.MULTILINE)
    if match is None:
        return 1
    body = match.group(1)
    if re.search(r"^        include:", body, re.MULTILINE):
        return len(re.findall(r"^          - ", body, re.MULTILINE))
    size = 1
    for values in re.findall(r"^        [A-Za-z0-9_-]+:[ \t]*\[(.*)\]", body, re.MULTILINE):
        size *= len([value for value in values.split(",") if value.strip()])
    return size


def jobs_that_start_at_once() -> dict[str, int]:
    started: dict[str, int] = {}
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        if not runs_for_a_pull_request_to_main(text):
            continue
        for job_id, job in jobs(text).items():
            if not needs(job):
                started[f"{workflow.name}:{job_id}"] = matrix_size(job)
    return started


class TheAnalysesTakeRunnersFirst(unittest.TestCase):
    def test_given_a_pull_request_when_its_workflows_start_then_the_jobs_needing_nothing_fit_in_the_runner_cap(self) -> None:
        # GIVEN every workflow that runs for a pull request to main.
        # WHEN the jobs that need no other job are counted, one per matrix entry.
        started = jobs_that_start_at_once()

        # THEN they fit in the runners the account has, so none of them waits in the queue.
        self.assertLessEqual(
            sum(started.values()),
            RUNNER_CAP,
            f"{sum(started.values())} jobs start at once; Sonar and CodeQL may queue behind them: {sorted(started)}",
        )
        # AND Sonar and CodeQL are among them.
        for workflow, job in ANALYSES:
            self.assertIn(f"{workflow}:{job}", started)

    def test_given_the_analyses_when_their_jobs_are_read_then_they_wait_for_nothing(self) -> None:
        for workflow, job_id in ANALYSES:
            with self.subTest(workflow=workflow):
                # GIVEN the analysis workflow.
                # WHEN its job is read.
                job = jobs((WORKFLOWS / workflow).read_text(encoding="utf-8"))[job_id]

                # THEN it needs no other job.
                self.assertEqual(needs(job), [], "an analysis behind another job starts later and finishes later")

    def test_given_the_long_workflows_when_a_job_needs_nothing_else_then_it_waits_for_the_gate(self) -> None:
        for workflow in GATED_WORKFLOWS:
            # GIVEN the workflows that hold the OS builds and the packages.
            workflow_jobs = jobs((WORKFLOWS / workflow).read_text(encoding="utf-8"))
            self.assertIn(GATE, workflow_jobs, f"{workflow} has no gate")
            for job_id, job in workflow_jobs.items():
                if job_id == GATE:
                    continue
                with self.subTest(workflow=workflow, job=job_id):
                    # WHEN each other job is read.
                    # THEN it waits for the gate or for another job.
                    self.assertNotEqual(needs(job), [], "a job needing nothing starts with the analyses")
                    # AND one that waits for the gate still runs if the gate fails: a job skipped because what it
                    # needs failed reports a skipped check, and a skipped required check counts as passed.
                    if GATE in needs(job):
                        self.assertEqual(job_if(job), "${{ !cancelled() }}")

    def test_given_a_job_behind_the_gate_through_another_when_its_condition_is_read_then_it_ignores_the_gate(
        self,
    ) -> None:
        for workflow in GATED_WORKFLOWS:
            # GIVEN the jobs that have the gate as an ancestor but do not need it directly.
            workflow_jobs = jobs((WORKFLOWS / workflow).read_text(encoding="utf-8"))
            downstream = downstream_of_the_gate(workflow_jobs)
            self.assertNotEqual(downstream, [], f"{workflow}: no job found behind the gate; is the parser right?")
            for job_id in downstream:
                with self.subTest(workflow=workflow, job=job_id):
                    # WHEN its condition is read.
                    condition = job_if(workflow_jobs[job_id])

                    # THEN it is written out: with none, GitHub applies success(), which looks at every ancestor, so
                    # a failed gate would skip the job and a skipped required check counts as passed.
                    self.assertIsNotNone(condition, "no `if`: the implicit success() also sees the gate")
                    # AND it names no status check that looks at every ancestor: a failed gate would stop signing
                    # and publishing although every package built.
                    self.assertNotRegex(condition, r"\b(success|failure)\(\)", "judge `needs.<job>.result` instead")

    def test_given_the_gate_when_it_runs_then_it_is_quick_and_never_skipped(self) -> None:
        for workflow in GATED_WORKFLOWS:
            with self.subTest(workflow=workflow):
                # GIVEN the gate job.
                gate = jobs((WORKFLOWS / workflow).read_text(encoding="utf-8"))[GATE]

                # WHEN its definition is read.
                # THEN it has no condition and no dependency, so it runs on every event the workflow runs on.
                self.assertIsNone(job_if(gate))
                self.assertEqual(needs(gate), [])
                # AND it checks nothing out and holds no permission: it only orders the queue.
                self.assertIn("permissions: {}", gate)
                self.assertNotIn("uses:", gate)
                self.assertRegex(gate, r"(?m)^    timeout-minutes: [1-5]$")


if __name__ == "__main__":
    unittest.main()
