#!/usr/bin/env python3
"""Workflow tiers: a pull request runs a few jobs, the merge queue the rest; only main writes the ccache.

The org has 20 hosted runners, so every job a push starts is a job another waits behind. A pull request runs the
`ubuntu` and `freebsd` build and test jobs and the analyses; the merge queue (`merge_group`), `main`, the schedule and a
manual dispatch run everything. The main ruleset requires every check below, and a required check that never reports
leaves the pull request pending for ever, while a job skipped by its own `if:` reports success.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Mirrors the "Protect main" ruleset's required status checks: update both together.
REQUIRED_CHECKS = (
    "ubuntu-build-and-test",
    "ubuntu-hardened-listener-coverage",
    "fedora-build-and-test",
    "debian-build-and-test",
    "rhel-build-and-test",
    "opensuse-build-and-test",
    "freebsd-build-and-test",
    "openbsd-build-and-test",
    "netbsd-build-and-test",
    "CodeQL analyze C++",
    "coverage",
    "fuzz-targets",
    "postgres-integration",
    "asan-ubsan",
    "tsan",
    "gitleaks",
    "clang-tidy",
    "dependency-review",
    "dependency-triage",
    "build",
    "Debian package",
    "Static Linux fallback binary",
    "Fedora RPM package",
    "FreeBSD package",
    "OpenBSD package",
    "Debian trixie package",
    "Docker image startup gate",
    "RHEL-compatible (AlmaLinux 10) RPM",
    "OpenSUSE Tumbleweed RPM",
)

# The jobs ci.yml runs for a pull request; every other job of ci.yml waits for the merge queue.
CI_JOBS_ON_A_PULL_REQUEST = {"queue-after-analyses", "ubuntu-build-and-test", "freebsd-build-and-test"}
NOT_A_PULL_REQUEST = "github.event_name != 'pull_request'"

# Workflows that run the compiler and whose ccache must work; the others (CodeQL must see every compile, the
# analyses and the reproducible build must not reuse objects) have no ccache.
CCACHE_WORKFLOWS = ("ci.yml", "sanitizers.yml", "fuzz.yml", "coverage.yml")
NO_CCACHE_WORKFLOWS = ("codeql.yml", "static-analysis.yml", "reproducible-build.yml")

JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)


def text_of(workflow: str) -> str:
    return (WORKFLOWS / workflow).read_text(encoding="utf-8")


def triggers(text: str) -> str:
    match = re.search(r"^on:\n(.*?)(?=^[a-z_]+:)", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1) if match else ""


def has_trigger(text: str, trigger: str) -> bool:
    return re.search(rf"(?m)^  {trigger}:", triggers(text)) is not None


def pull_request_admits_main(text: str) -> bool:
    """The pull_request trigger has no `branches:` filter, or one that lists `main`."""
    match = re.search(r"^  pull_request:[ \t]*\n((?:    .*\n|\s*\n)*)", triggers(text), flags=re.MULTILINE)
    if match is None:
        return False
    body = match.group(1)
    return "branches" not in body or re.search(r"(?m)^\s*(?:branches:.*|- )['\"\[]?main\b", body) is not None


def jobs(text: str) -> dict[str, str]:
    if "\njobs:\n" not in text:
        return {}
    section = text.split("\njobs:\n", 1)[1]
    headers = list(JOB_HEADER.finditer(section))
    return {
        header.group(1): section[header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(section)]
        for index, header in enumerate(headers)
    }


def job_name(job_id: str, job: str) -> str:
    match = re.search(r"^    name:[ \t]*(.+?)[ \t]*$", job, re.MULTILINE)
    return match.group(1).strip("'\"") if match else job_id


def job_if(job: str) -> str:
    """The job's condition, a `|` block scalar's lines joined."""
    match = re.search(r"^    if:[ \t]*(.*)$", job, re.MULTILINE)
    if match is None:
        return ""
    value = match.group(1).strip()
    if value in ("|", ">", "|-", ">-"):
        block = re.match(r"((?:      .*\n)+)", job[match.end() + 1 :])
        value = " ".join(block.group(1).split()) if block else ""
    return value


def matrix_rows(job: str) -> list[dict[str, str]]:
    """The rows of the job's `matrix.include` list; a matrix without one has no row that names a job."""
    match = re.search(r"(?m)^        include:[ \t]*\n((?:          .*\n|\s*\n)*)", job)
    if match is None:
        return []
    rows = re.split(r"(?m)^          - ", "\n" + match.group(1))[1:]
    return [
        {key: value.strip().strip("'\"") for key, value in re.findall(r"(?m)^(?:          - )?\s*([A-Za-z0-9_-]+):[ \t]*(.*)$", "          - " + row)}
        for row in rows
    ]


def rendered_names(label: str, job: str) -> list[str]:
    """The job's `name:` once `${{ matrix.<field> }}` is replaced by each include row's value."""
    names = []
    for row in matrix_rows(job):
        names.append(re.sub(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", lambda m: row.get(m.group(1), m.group(0)), label))
    return names


def check_producers(name: str) -> list[tuple[str, str]]:
    """The (workflow, job id) pairs that report a check called exactly `name` for a pull request."""
    found = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for job_id, job in jobs(text).items():
            label = job_name(job_id, job)
            if label == name:
                found.append((workflow.name, job_id))
            elif "${{ matrix." in label and name in rendered_names(label, job):
                # A matrix leg reports its rendered name, which must be the check's own name, and only when the job is
                # not skipped: a job-level `if` that is false reports one check under the unexpanded template.
                if NOT_A_PULL_REQUEST not in job_if(job):
                    found.append((workflow.name, job_id))
    return found


class TheMergeQueueRunsWhatAPullRequestSkips(unittest.TestCase):
    def test_given_every_workflow_with_a_pull_request_trigger_when_read_then_it_also_runs_in_the_merge_queue(self) -> None:
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            if not has_trigger(text, "pull_request"):
                continue
            with self.subTest(workflow=workflow.name):
                self.assertTrue(has_trigger(text, "merge_group"), "a required check never reports in the merge queue")

    def test_given_ci_when_a_pull_request_runs_then_only_the_ubuntu_and_freebsd_jobs_and_the_gate_run(self) -> None:
        for job_id, job in jobs(text_of("ci.yml")).items():
            with self.subTest(job=job_id):
                if job_id in CI_JOBS_ON_A_PULL_REQUEST:
                    self.assertNotIn(NOT_A_PULL_REQUEST, job_if(job))
                else:
                    self.assertIn(NOT_A_PULL_REQUEST, job_if(job), "this job should wait for the merge queue")

    def test_given_packages_when_a_pull_request_runs_then_every_job_skips_by_its_own_condition(self) -> None:
        # The ruleset requires the package checks, so the workflow must still trigger; a job skipped by `if:` passes.
        text = text_of("packages.yml")
        self.assertTrue(has_trigger(text, "pull_request"))
        for job_id, job in jobs(text).items():
            with self.subTest(job=job_id):
                condition = job_if(job)
                self.assertTrue(
                    NOT_A_PULL_REQUEST in condition or "github.event_name == 'push'" in condition,
                    "a package job must not run for a pull request",
                )

    def test_given_the_reproducible_build_when_read_then_it_runs_in_the_merge_queue_not_for_a_pull_request(self) -> None:
        text = text_of("reproducible-build.yml")
        self.assertFalse(has_trigger(text, "pull_request"))
        self.assertTrue(has_trigger(text, "merge_group"))
        self.assertTrue(has_trigger(text, "workflow_dispatch"))


class EveryRequiredCheckReportsForAPullRequestAndTheMergeQueue(unittest.TestCase):
    def test_given_the_required_checks_when_the_jobs_are_read_then_each_name_belongs_to_one_job(self) -> None:
        for name in REQUIRED_CHECKS:
            with self.subTest(check=name):
                self.assertEqual(len(check_producers(name)), 1, f"{name}: {check_producers(name)}")

    def test_given_the_required_checks_when_their_workflows_are_read_then_each_triggers_for_both_events(self) -> None:
        for name in REQUIRED_CHECKS:
            for workflow, _ in check_producers(name):
                with self.subTest(check=name, workflow=workflow):
                    text = text_of(workflow)
                    self.assertTrue(has_trigger(text, "pull_request"), "never reports for a pull request")
                    self.assertTrue(pull_request_admits_main(text), "a pull request to main never triggers it")
                    self.assertTrue(has_trigger(text, "merge_group"), "never reports in the merge queue")

    def test_given_a_required_check_when_a_pull_request_skips_its_job_then_the_job_is_not_a_matrix_job(self) -> None:
        # A matrix job that a job-level `if` skips reports one check under its unexpanded name, which matches
        # nothing, so the required name must come from a plain job (an aggregate) in that case.
        for name in REQUIRED_CHECKS:
            for workflow, job_id in check_producers(name):
                job = jobs(text_of(workflow))[job_id]
                if NOT_A_PULL_REQUEST in job_if(job):
                    with self.subTest(check=name):
                        self.assertNotRegex(job, r"(?m)^    strategy:")


class TheAnalysisStepsFailLoudly(unittest.TestCase):
    @staticmethod
    def step(workflow: str, name: str) -> str:
        steps = text_of(workflow).split("\n      - ")
        found = [step for step in steps if step.startswith(f"name: {name}")]
        assert len(found) == 1, f"{workflow}: expected one step named {name!r}"
        return found[0]

    def test_given_the_thread_sanitizer_step_when_read_then_tee_cannot_hide_a_failure(self) -> None:
        # GIVEN the step that builds and tests under ThreadSanitizer and pipes its output through tee.
        step = self.step("sanitizers.yml", "Build and test with ThreadSanitizer")

        # THEN it runs under bash, whose pipefail makes a failed build or test fail the step.
        self.assertIn("| tee tsan-ci-log.txt", step)
        self.assertRegex(step, r"(?m)^        shell: bash$")


class OnlyPullRequestRunsShareAConcurrencyGroup(unittest.TestCase):
    WORKFLOWS_WITH_THE_BLOCK = (
        "ci.yml",
        "codeql.yml",
        "dependency-vulnerability-triage.yml",
        "fuzz.yml",
        "packages.yml",
        "postgres-integration.yml",
        "sanitizers.yml",
        "secret-scan.yml",
        "static-analysis.yml",
    )

    def test_given_a_workflow_with_a_pull_request_trigger_when_read_then_it_cancels_only_superseded_pull_request_runs(
        self,
    ) -> None:
        for workflow in self.WORKFLOWS_WITH_THE_BLOCK:
            with self.subTest(workflow=workflow):
                text = text_of(workflow)
                stem = workflow.removesuffix(".yml")
                group = (
                    f"  group: {stem}-${{{{ github.event_name == 'pull_request' && "
                    "format('pr-{0}', github.event.pull_request.number) || github.run_id }}"
                )
                self.assertIn("concurrency:\n" + group + "\n", text)
                self.assertIn("  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n", text)


class NoPushTriggerNamesAnAgentBranch(unittest.TestCase):
    def test_given_the_workflows_when_their_triggers_are_read_then_none_lists_claude_or_codex_branches(self) -> None:
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            with self.subTest(workflow=workflow.name):
                self.assertNotRegex(triggers(workflow.read_text(encoding="utf-8")), r"claude/|codex/")

    def test_given_the_workflows_that_lost_those_branches_when_read_then_they_can_be_started_by_hand(self) -> None:
        for workflow in (
            "ci.yml",
            "dependency-vulnerability-triage.yml",
            "fuzz.yml",
            "packages.yml",
            "postgres-integration.yml",
            "sanitizers.yml",
            "secret-scan.yml",
            "static-analysis.yml",
        ):
            with self.subTest(workflow=workflow):
                self.assertTrue(has_trigger(text_of(workflow), "workflow_dispatch"))


class OnlyMainWritesTheCompilerCache(unittest.TestCase):
    def ccache_jobs(self) -> list[tuple[str, str, str]]:
        found = []
        for workflow in CCACHE_WORKFLOWS:
            for job_id, job in jobs(text_of(workflow)).items():
                if "hendrikmuhs/ccache-action@" in job:
                    found.append((workflow, job_id, job))
        return found

    def test_given_the_ccache_workflows_when_read_then_each_has_ccache_jobs(self) -> None:
        for workflow in CCACHE_WORKFLOWS:
            self.assertTrue([item for item in self.ccache_jobs() if item[0] == workflow], workflow)

    def test_given_a_job_with_ccache_when_it_sets_the_compiler_then_ccache_wraps_it(self) -> None:
        # build-linux.sh hands Meson CC and CXX, and Meson inserts ccache only when it picks the compiler itself.
        for workflow, job_id, job in self.ccache_jobs():
            with self.subTest(workflow=workflow, job=job_id):
                self.assertRegex(job, r"(?m)^      CC: ccache \S+$")
                self.assertRegex(job, r"(?m)^      CXX: ccache \S+$")

    def test_given_a_job_with_ccache_when_it_finishes_then_only_main_saves_the_cache_and_it_is_one_gigabyte(self) -> None:
        for workflow, job_id, job in self.ccache_jobs():
            with self.subTest(workflow=workflow, job=job_id):
                self.assertIn("          save: ${{ github.ref == 'refs/heads/main' }}\n", job)
                self.assertIn("          max-size: 1G\n", job)
                self.assertIn("hendrikmuhs/ccache-action@f09c25b45002a07be2955cbe52e8cee55643f89d # v1.2.24", job)

    def test_given_the_workflows_without_a_compiler_cache_when_read_then_none_uses_ccache(self) -> None:
        for workflow in NO_CCACHE_WORKFLOWS:
            with self.subTest(workflow=workflow):
                self.assertNotIn("ccache", text_of(workflow))


if __name__ == "__main__":
    unittest.main()
