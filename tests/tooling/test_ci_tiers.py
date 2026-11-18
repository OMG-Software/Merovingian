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


def without_comments(text: str) -> str:
    """The text with every YAML `#` comment removed, so a comment can never satisfy a match."""
    return re.sub(r"(?m)(?:^|[ \t])#.*$", "", text)


def pull_request_admits_main(text: str) -> bool:
    """The pull_request trigger admits main: no filter, `branches:` listing it, or `branches-ignore:` not naming it."""
    match = re.search(r"^  pull_request:[ \t]*\n((?:    .*\n|\s*\n)*)", without_comments(triggers(text)), flags=re.MULTILINE)
    if match is None:
        return False
    body = match.group(1)
    ignored = branch_filter(body, "branches-ignore")
    if ignored is not None and "main" in ignored:
        return False
    allowed = branch_filter(body, "branches")
    return allowed is None or "main" in allowed


def branch_filter(body: str, key: str) -> list[str] | None:
    """The complete value of the trigger's `key:` filter, inline or block list; None when it has no such filter."""
    filter_match = re.search(rf"(?m)^    {key}:[ \t]*(.*)$", body)
    if filter_match is None:
        return None
    inline = filter_match.group(1).strip()
    if inline:
        return [item.strip().strip("'\"") for item in inline.strip("[]").split(",")]
    block = re.match(r"((?:      - .*\n?|\s*\n)*)", body[filter_match.end() + 1 :])
    lines = (block.group(1) if block else "").splitlines()
    return [line.strip()[2:].strip().strip("'\"") for line in lines if line.strip()]


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


def producers_in(workflow: str, text: str, name: str, event: str = "pull_request") -> list[tuple[str, str]]:
    """One (workflow, job id) entry per check called exactly `name` that the workflow's jobs report for `event`.

    A matrix job yields one entry per rendered leg, so two legs that render the same required name count twice. A
    leg a job-level `if` skips for a pull request still runs, and reports, in the merge queue.
    """
    found = []
    for job_id, job in jobs(text).items():
        label = job_name(job_id, job)
        if label == name:
            found.append((workflow, job_id))
        elif "${{ matrix." in label and (event != "pull_request" or NOT_A_PULL_REQUEST not in job_if(job)):
            # A matrix leg reports its rendered name, which must be the check's own name, and only when the job is
            # not skipped: a job-level `if` that is false reports one check under the unexpanded template.
            found.extend((workflow, job_id) for rendered in rendered_names(label, job) if rendered == name)
    return found


def check_producers(name: str, event: str = "pull_request") -> list[tuple[str, str]]:
    """The (workflow, job id) pairs that report a check called exactly `name` for `event`."""
    found = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        if has_trigger(workflow.read_text(encoding="utf-8"), event):
            found.extend(producers_in(workflow.name, workflow.read_text(encoding="utf-8"), name, event))
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
    def test_given_the_required_checks_when_the_jobs_are_read_then_each_name_belongs_to_one_job_per_event(self) -> None:
        for name in REQUIRED_CHECKS:
            for event in ("pull_request", "merge_group"):
                with self.subTest(check=name, event=event):
                    # GIVEN a required check and an event.
                    # WHEN the jobs that report it for that event are collected.
                    found = check_producers(name, event)

                    # THEN exactly one job does.
                    self.assertEqual(len(found), 1, f"{name} on {event}: {found}")

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


class TheCheckHelpersRejectWhatTheyShouldNot(unittest.TestCase):
    @staticmethod
    def trigger_text(pull_request_body: str) -> str:
        return "on:\n  pull_request:\n" + pull_request_body + "  merge_group:\njobs:\n"

    @staticmethod
    def matrix_job(*labels: str, condition: str = "") -> str:
        legs = "".join(f"          - label: {label}\n" for label in labels)
        guard = f"    if: {condition}\n" if condition else ""
        return (
            "  build:\n    name: ${{ matrix.label }}\n" + guard + "    strategy:\n      matrix:\n        include:\n" + legs
        )

    def test_given_a_branches_filter_when_read_then_only_the_complete_value_main_admits_main(self) -> None:
        cases = {
            "no filter": ("    types: [opened]\n", True),
            "inline list": ("    branches: [main]\n", True),
            "block list": ("    branches:\n      - main\n", True),
            "list with others": ("    branches: [release, main]\n", True),
            "main-experimental inline": ("    branches: [main-experimental]\n", False),
            "main-experimental block": ("    branches:\n      - main-experimental\n", False),
            "main in a comment": ("    branches: [release] # main\n", False),
            "ignore main inline": ("    branches-ignore: [main]\n", False),
            "ignore main block": ("    branches-ignore:\n      - main\n", False),
            "ignore others inline": ("    branches-ignore: [release]\n", True),
            "ignore others block": ("    branches-ignore:\n      - release\n", True),
        }
        for label, (body, admits) in cases.items():
            with self.subTest(case=label):
                # GIVEN a pull_request trigger with this branches filter.
                text = self.trigger_text(body)

                # WHEN the trigger is asked whether a pull request to main runs it.
                result = pull_request_admits_main(text)

                # THEN only a filter that lists main itself, or none, admits it.
                self.assertEqual(result, admits)

    def test_given_two_matrix_legs_rendering_one_required_name_when_read_then_the_name_has_two_producers(self) -> None:
        # GIVEN a matrix job whose two legs both render the check name `suite`.
        text = "\njobs:\n" + self.matrix_job("suite", "suite")

        # WHEN the producers of `suite` are collected.
        found = producers_in("w.yml", text, "suite")

        # THEN each leg is a producer, so the uniqueness check fails.
        self.assertEqual(len(found), 2)

    def test_given_one_matrix_leg_rendering_a_required_name_when_read_then_the_name_has_one_producer(self) -> None:
        # GIVEN a matrix job with one leg called `suite` and one called `other`.
        text = "\njobs:\n" + self.matrix_job("suite", "other")

        # WHEN the producers of `suite` are collected.
        found = producers_in("w.yml", text, "suite")

        # THEN exactly one job reports it.
        self.assertEqual(found, [("w.yml", "build")])

    def test_given_a_pull_request_skipped_matrix_when_an_aggregate_has_the_name_then_only_the_aggregate_reports_it(self) -> None:
        # GIVEN a matrix job skipped for pull requests and a plain aggregate job that carries the required name.
        text = (
            "\njobs:\n"
            + self.matrix_job("suite", condition="github.event_name != 'pull_request'")
            + "  aggregate:\n    name: suite\n    runs-on: x\n"
        )

        # WHEN the producers of `suite` are collected.
        found = producers_in("w.yml", text, "suite")

        # THEN the aggregate alone reports it.
        self.assertEqual(found, [("w.yml", "aggregate")])

    def test_given_a_pull_request_skipped_matrix_and_an_aggregate_when_the_merge_queue_runs_then_two_jobs_report_it(
        self,
    ) -> None:
        # GIVEN a matrix leg skipped for pull requests and an aggregate, both rendering the required name `suite`.
        text = (
            "\njobs:\n"
            + self.matrix_job("suite", condition="github.event_name != 'pull_request'")
            + "  aggregate:\n    name: suite\n    runs-on: x\n"
        )

        # WHEN the producers of `suite` are collected for each event.
        pull_request = producers_in("w.yml", text, "suite", "pull_request")
        merge_group = producers_in("w.yml", text, "suite", "merge_group")

        # THEN a pull request has one producer, but the merge queue has two, which the uniqueness check rejects.
        self.assertEqual(len(pull_request), 1)
        self.assertEqual(len(merge_group), 2)


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

    def test_given_the_clang_tidy_step_when_read_then_it_checks_changed_lines_and_a_failed_diff_fails_it(self) -> None:
        # GIVEN the step that runs clang-tidy on what a change touched.
        step = self.step("static-analysis.yml", "Run clang-tidy on changed lines")
        active = "\n".join(line for line in step.splitlines() if not line.strip().startswith("#"))

        # WHEN its shell, base commit and commands are read.
        # THEN it runs under bash (pipefail) and compares with the pull request's or the merge queue's base commit.
        self.assertRegex(step, r"(?m)^        shell: bash$")
        self.assertRegex(
            step,
            r"(?m)^          BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \|\| github\.event\.merge_group\.base_sha \}\}$",
        )
        # AND the zero-context diff is a two-dot diff of the trees (a one-commit-deep checkout has no merge base) piped
        # into clang-tidy-diff, which filters diagnostics to the changed lines.
        self.assertIn("git diff -U0 --diff-filter=d FETCH_HEAD HEAD -- src tests | \\", active)
        self.assertIn('python3 "${clang_tidy_diff}" -p1 -path build', active)
        self.assertNotIn("FETCH_HEAD...HEAD", active)
        # AND a push compares with the tip it replaced, never with main, which for a push to main is the pushed commit.
        self.assertRegex(step, r"(?m)^          PUSH_BEFORE: \$\{\{ github\.event\.before \}\}$")
        self.assertIn('[ "${GITHUB_EVENT_NAME}" = "push" ]', active)
        self.assertIn('[ "${PUSH_BEFORE}" != "0000000000000000000000000000000000000000" ]', active)
        self.assertIn('base="${PUSH_BEFORE}"', active)
        self.assertNotIn("origin/main", active)
        # AND a manual run, or a push that created its branch, compares with the checked-out commit's parent.
        self.assertIn('git fetch --no-tags --deepen=1 origin "${GITHUB_SHA}"', active)
        self.assertIn('base="$(git rev-parse HEAD^)"', active)
        # AND nothing turns a failure into success.
        self.assertNotIn("|| true", active)

    def test_given_the_tests_clang_tidy_config_when_read_then_only_the_catch2_tripped_check_is_added_off(self) -> None:
        # GIVEN both clang-tidy configurations.
        root = (REPO_ROOT / ".clang-tidy").read_text(encoding="utf-8")
        tests = (REPO_ROOT / "tests" / ".clang-tidy").read_text(encoding="utf-8")

        # WHEN their check lists are compared.
        # THEN every Catch2 SCENARIO's static dummyFunction is not flagged in tests, and src keeps the check.
        self.assertIn("  -misc-use-anonymous-namespace,", tests)
        self.assertNotIn("misc-use-anonymous-namespace", root)
        self.assertIn("  misc-*,", root)


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
