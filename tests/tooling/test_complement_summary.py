#!/usr/bin/env python3
"""Behaviour of scripts/summarise_complement.py and the Complement skip list.

The summariser, not `go test`'s exit code, decides whether a Complement run is
green (ADR-0234). These tests feed it `go test -json` event streams and skip
lists and check the verdict, and check that the checked-in skip list is valid.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SUMMARISER = REPO_ROOT / "scripts" / "summarise_complement.py"
CHECKED_IN_SKIP_LIST = REPO_ROOT / "tests" / "complement" / "skip-list.toml"
MODULE = "github.com/matrix-org/complement"
TESTS = f"{MODULE}/tests"
CSAPI = f"{MODULE}/tests/csapi"
SPEC_REF = "docs/matrix-v1.19-spec/client-server-api.md#registration"
TODO_REF = "docs/todos/capability-gaps.md"
ROOM_VERSION_ADR = "docs/adr/0076-room-versions-1-and-2-are-not-supported.md"


def event(action: str, test: str | None = None, package: str = TESTS, output: str | None = None) -> dict:
    record: dict = {"Action": action, "Package": package}
    if test is not None:
        record["Test"] = test
    if output is not None:
        record["Output"] = output
    return record


def ran(test: str, result: str, package: str = TESTS) -> list[dict]:
    return [event("run", test, package), event(result, test, package)]


def listing(*names: str, package: str = TESTS) -> list[dict]:
    return [event("output", package=package, output=f"{name}\n") for name in names] + [
        event("output", package=package, output=f"ok  \t{package}\t0.010s\n"),
        event("pass", package=package),
    ]


class Summariser:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir

    def write_jsonl(self, name: str, events: list[dict]) -> Path:
        path = self.workdir / name
        path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
        return path

    def write_skip_list(self, text: str) -> Path:
        path = self.workdir / "skip-list.toml"
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return path

    def run(self, skip_list: str, log: list[dict], listing_events: list[dict] | None = None) -> tuple[subprocess.CompletedProcess[str], dict]:
        skip_path = self.write_skip_list(skip_list)
        log_path = self.write_jsonl("run.jsonl", log)
        listing_path = self.write_jsonl("listing.jsonl", listing_events or [])
        summary_path = self.workdir / "summary.json"
        result = subprocess.run(
            [sys.executable, "-I", str(SUMMARISER), "--repo-root", str(REPO_ROOT), "--skip-list", str(skip_path),
             "--log", str(log_path), "--listing", str(listing_path), "--output", str(summary_path)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
        return result, summary

    def skip_pattern(self, skip_list: str) -> subprocess.CompletedProcess[str]:
        skip_path = self.write_skip_list(skip_list)
        return subprocess.run(
            [sys.executable, "-I", str(SUMMARISER), "--repo-root", str(REPO_ROOT), "--skip-list", str(skip_path),
             "--skip-pattern"],
            capture_output=True, text=True, timeout=60, check=False,
        )


def expect_fail(test: str, package: str = "tests", extra: str = "") -> str:
    return f"""
    [[entry]]
    test = "{test}"
    package = "{package}"
    mode = "expect-fail"
    category = "known-gap"
    reason = "Not implemented yet."
    todo = "{TODO_REF}"
    {extra}
    """


def skip_entry(test: str, package: str = "tests") -> str:
    return f"""
    [[entry]]
    test = "{test}"
    package = "{package}"
    mode = "skip"
    category = "known-gap"
    reason = "Not implemented yet."
    todo = "{TODO_REF}"
    not_run_because = "It leaves the server unable to answer later tests."
    """


class SummaryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="complement-summary-"))
        self.summariser = Summariser(self.workdir)

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


class VerdictTests(SummaryCase):
    def test_a_run_where_everything_passes_is_green(self) -> None:
        # GIVEN a run in which every test passes, and an empty skip list.
        log = ran("TestA", "pass") + ran("TestB", "pass", CSAPI) + [event("pass", package=TESTS), event("pass", package=CSAPI)]
        # WHEN it is summarised.
        result, summary = self.summariser.run("", log)
        # THEN the verdict is pass, and the counts say what ran.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(summary["verdict"], "pass")
        self.assertEqual(summary["results"], {"pass": 2, "fail": 0, "skip": 0})

    def test_an_unlisted_failure_fails_the_run(self) -> None:
        # GIVEN a run with a failure the skip list does not name.
        log = ran("TestA", "pass") + ran("TestB", "fail") + [event("fail", package=TESTS)]
        # WHEN it is summarised.
        result, summary = self.summariser.run("", log)
        # THEN the run fails and names the test.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["verdict"], "fail")
        self.assertEqual(summary["unexpected_failures"], ["tests:TestB"])

    def test_a_listed_failure_is_expected(self) -> None:
        # GIVEN a run whose only failure is listed as expected to fail.
        log = ran("TestA", "pass") + ran("TestB", "fail") + [event("fail", package=TESTS)]
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestB"), log)
        # THEN the run is green, and the failure is counted as expected.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(summary["expected_failures"], ["tests:TestB"])

    def test_a_listed_test_that_now_passes_is_stale(self) -> None:
        # GIVEN a listed test that passes.
        log = ran("TestB", "pass") + [event("pass", package=TESTS)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(expect_fail("TestB"), log)
        # THEN the run fails until the entry is removed.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["stale_entries"], ["tests:TestB"])

    def test_a_listed_test_that_skips_itself_is_stale(self) -> None:
        # GIVEN a listed test that skipped itself rather than failing.
        log = ran("TestB", "skip") + [event("pass", package=TESTS)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(expect_fail("TestB"), log)
        # THEN the entry is stale: it no longer describes a failure.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["stale_entries"], ["tests:TestB"])

    def test_a_listed_test_that_no_longer_exists_fails_the_run(self) -> None:
        # GIVEN a listed test that the run never reports.
        log = ran("TestA", "pass") + [event("pass", package=TESTS)]
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestGone"), log)
        # THEN the run fails until the entry is removed.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["missing_entries"], ["tests:TestGone"])

    def test_a_parent_failing_only_through_listed_subtests_is_expected(self) -> None:
        # GIVEN a test that fails because one listed subtest fails.
        log = (
            [event("run", "TestP")]
            + ran("TestP/ok", "pass")
            + ran("TestP/broken", "fail")
            + [event("fail", "TestP"), event("fail", package=TESTS)]
        )
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestP/broken"), log)
        # THEN the parent's failure is explained and the run is green.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(summary["unexpected_failures"], [])

    def test_a_parent_is_explained_by_a_listed_subtest_whose_name_contains_a_slash(self) -> None:
        # GIVEN a test that fails because one listed subtest fails, the subtest's
        # name holding slashes as Complement's route names do
        # ("test /_matrix/media/v3 endpoint"), so it looks nested.
        log = (
            [event("run", "TestP")]
            + ran("TestP/test_/_matrix/client/v1/media_endpoint", "pass")
            + ran("TestP/test_/_matrix/media/v3_endpoint", "fail")
            + [event("fail", "TestP"), event("fail", package=TESTS)]
        )
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestP/test_/_matrix/media/v3_endpoint"), log)
        # THEN the parent's failure is explained and the run is green.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(summary["unexpected_failures"], [])

    def test_an_unlisted_subtest_whose_name_contains_a_slash_leaves_its_parent_unexplained(self) -> None:
        # GIVEN a parent with one listed failing subtest and one unlisted failing
        # subtest whose name holds slashes.
        log = (
            [event("run", "TestP")]
            + ran("TestP/listed", "fail")
            + ran("TestP/via__matrix/client/v1/media/download", "fail")
            + [event("fail", "TestP"), event("fail", package=TESTS)]
        )
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestP/listed"), log)
        # THEN the unlisted subtest and the parent it fails are both reported.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["unexpected_failures"],
                         ["tests:TestP", "tests:TestP/via__matrix/client/v1/media/download"])

    def test_an_unlisted_subtest_failure_is_reported_as_itself(self) -> None:
        # GIVEN a parent with one listed and one unlisted failing subtest.
        log = (
            [event("run", "TestP")]
            + ran("TestP/broken", "fail")
            + ran("TestP/also", "fail")
            + [event("fail", "TestP"), event("fail", package=TESTS)]
        )
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestP/broken"), log)
        # THEN the run fails, naming the unlisted subtest and its parent.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["unexpected_failures"], ["tests:TestP", "tests:TestP/also"])

    def test_subtests_of_a_listed_parent_are_covered_by_it(self) -> None:
        # GIVEN a listed test whose subtests fail.
        log = [event("run", "TestP")] + ran("TestP/one", "fail") + [event("fail", "TestP"), event("fail", package=TESTS)]
        # WHEN it is summarised.
        result, summary = self.summariser.run(expect_fail("TestP"), log)
        # THEN the listing covers them.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_test_that_never_finished_fails_the_run(self) -> None:
        # GIVEN a test that started and was never reported again, as when
        # `go test -timeout` kills a hung run.
        log = ran("TestA", "pass") + [event("run", "TestHang"), event("fail", package=TESTS)]
        # WHEN it is summarised.
        result, summary = self.summariser.run("", log)
        # THEN it is a failure, even if listed: a hang is never expected.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["unfinished"], ["tests:TestHang"])
        listed, listed_summary = self.summariser.run(expect_fail("TestHang"), log)
        self.assertEqual(listed.returncode, 1)
        self.assertEqual(listed_summary["unfinished"], ["tests:TestHang"])

    def test_a_package_that_fails_without_a_failing_test_fails_the_run(self) -> None:
        for failure in ([event("fail", package=CSAPI)], [event("build-fail", package=CSAPI)]):
            with self.subTest(action=failure[0]["Action"]):
                # GIVEN a package that fails with no test failing, as when it does not build.
                log = ran("TestA", "pass") + [event("pass", package=TESTS)] + failure
                # WHEN the run is summarised.
                result, summary = self.summariser.run("", log)
                # THEN the run fails, naming the package.
                self.assertEqual(result.returncode, 1)
                self.assertEqual(summary["package_failures"], ["tests/csapi"])

    def test_a_run_with_no_tests_fails(self) -> None:
        # GIVEN a log in which no test ran.
        # WHEN it is summarised.
        result, summary = self.summariser.run("", [])
        # THEN the run fails: an empty run proves nothing.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["verdict"], "fail")

    def test_an_entry_names_one_package(self) -> None:
        # GIVEN TestB listed for tests/csapi but failing in tests.
        log = ran("TestB", "fail") + ran("TestB", "fail", CSAPI) + [event("fail", package=TESTS), event("fail", package=CSAPI)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(expect_fail("TestB", "tests/csapi"), log)
        # THEN only the csapi failure is expected.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["unexpected_failures"], ["tests:TestB"])


class SkipModeTests(SummaryCase):
    def test_skip_entries_become_one_anchored_pattern(self) -> None:
        # GIVEN two entries that must not run.
        # WHEN the -skip pattern is asked for.
        result = self.summariser.skip_pattern(skip_entry("TestA") + skip_entry("TestB", "tests/csapi"))
        # THEN it matches those top-level names exactly.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "^(TestA|TestB)$")

    def test_no_skip_entries_print_nothing(self) -> None:
        # GIVEN only expected failures.
        # WHEN the -skip pattern is asked for.
        result = self.summariser.skip_pattern(expect_fail("TestA"))
        # THEN there is none.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_skipped_test_must_still_exist(self) -> None:
        # GIVEN a skip entry for a test the listing does not have.
        log = ran("TestA", "pass") + [event("pass", package=TESTS)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(skip_entry("TestGone"), log, listing("TestA"))
        # THEN the run fails until the entry is removed.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["missing_entries"], ["tests:TestGone"])

    def test_a_skipped_test_that_exists_is_accepted(self) -> None:
        # GIVEN a skip entry for a listed test that did not run.
        log = ran("TestA", "pass") + [event("pass", package=TESTS)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(skip_entry("TestB"), log, listing("TestA", "TestB"))
        # THEN the run is green and records the skip.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(summary["not_run"], ["tests:TestB"])

    def test_a_skipped_name_in_two_packages_is_refused(self) -> None:
        # GIVEN a skip entry whose name exists in another package too, which
        # -skip, applying to every package, would also skip.
        log = ran("TestA", "pass") + [event("pass", package=TESTS)]
        both = listing("TestA", "TestB") + listing("TestB", package=CSAPI)
        # WHEN the run is summarised.
        result, _ = self.summariser.run(skip_entry("TestB"), log, both)
        # THEN the skip list is refused.
        self.assertEqual(result.returncode, 2)

    def test_a_skipped_test_that_ran_fails_the_run(self) -> None:
        # GIVEN a skip entry for a test that ran anyway.
        log = ran("TestB", "pass") + [event("pass", package=TESTS)]
        # WHEN the run is summarised.
        result, summary = self.summariser.run(skip_entry("TestB"), log, listing("TestB"))
        # THEN the run fails: the skip was not applied.
        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["skip_not_applied"], ["tests:TestB"])


class SkipListValidationTests(SummaryCase):
    def assert_refused(self, skip_list: str) -> None:
        result = self.summariser.skip_pattern(skip_list)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(result.stderr.strip())

    def test_every_entry_needs_its_category_evidence(self) -> None:
        cases = {
            "spec without a spec reference": """
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "spec"
                reason = "The test contradicts the spec."
                """,
            "a spec reference outside the pinned spec": """
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "non-spec"
                reason = "The spec does not require this."
                spec = "docs/user-manual.md"
                """,
            "a spec reference to a missing file": """
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "spec"
                reason = "The test contradicts the spec."
                spec = "docs/matrix-v1.19-spec/no-such-file.md#x"
                """,
            "room-version without ADR-0076": f"""
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "room-version"
                reason = "Room version 1."
                adr = "{TODO_REF}"
                """,
            "known-gap without a todo": """
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "known-gap"
                reason = "Not implemented."
                """,
            "an unknown category": f"""
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "flaky"
                reason = "It fails sometimes."
                todo = "{TODO_REF}"
                """,
            "an empty reason": f"""
                [[entry]]
                test = "TestA"
                package = "tests"
                mode = "expect-fail"
                category = "known-gap"
                reason = " "
                todo = "{TODO_REF}"
                """,
        }
        for name, skip_list in cases.items():
            with self.subTest(case=name):
                # GIVEN an entry without the evidence its category needs.
                # WHEN the skip list is loaded.
                # THEN it is refused.
                self.assert_refused(skip_list)

    def test_entries_with_their_evidence_are_accepted(self) -> None:
        # GIVEN one valid entry of each category.
        skip_list = f"""
            [[entry]]
            test = "TestA"
            package = "tests"
            mode = "expect-fail"
            category = "spec"
            reason = "The test contradicts the spec."
            spec = "{SPEC_REF}"

            [[entry]]
            test = "TestB"
            package = "tests"
            mode = "expect-fail"
            category = "non-spec"
            reason = "The spec does not require this."
            spec = "{SPEC_REF}"

            [[entry]]
            test = "TestC/v1"
            package = "tests/csapi"
            mode = "expect-fail"
            category = "room-version"
            reason = "Room version 1."
            adr = "{ROOM_VERSION_ADR}"
            """ + expect_fail("TestD")
        # WHEN the skip list is loaded.
        result = self.summariser.skip_pattern(skip_list)
        # THEN it is accepted.
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_entries_are_refused(self) -> None:
        cases = {
            "an unknown field": expect_fail("TestA", extra='severity = "low"'),
            "a duplicate": expect_fail("TestA") + expect_fail("TestA"),
            "a name that is not a Go test": expect_fail("Bogus"),
            "a package outside tests": expect_fail("TestA", "internal"),
            "an unknown mode": expect_fail("TestA").replace("expect-fail", "flaky"),
            "a skipped subtest": skip_entry("TestA/sub"),
            "a skip without saying why it cannot run": skip_entry("TestA").replace(
                'not_run_because = "It leaves the server unable to answer later tests."', ""),
            "an unknown top-level table": '[settings]\nstrict = true\n',
        }
        for name, skip_list in cases.items():
            with self.subTest(case=name):
                # GIVEN a malformed skip list.
                # WHEN it is loaded.
                # THEN it is refused.
                self.assert_refused(skip_list)

    def test_hiding_an_auth_or_signature_test_needs_a_sign_off(self) -> None:
        for test in ("TestInboundFederationRejectsEventsWithRejectedAuthEvents", "TestFederationKeysSigned",
                     "TestOutboundFederationIgnoresMissingEventWithBadJSONForRoomVersion6_ACL"):
            with self.subTest(test=test):
                # GIVEN an entry hiding a test about auth, signatures, keys or ACLs.
                # WHEN it has no sign-off.
                # THEN the skip list is refused; with one, it is accepted.
                self.assert_refused(expect_fail(test))
                signed = self.summariser.skip_pattern(expect_fail(test, extra='signed_off_by = "James Chapman, 2026-10-26"'))
                self.assertEqual(signed.returncode, 0, signed.stderr)

    def test_the_checked_in_skip_list_is_valid(self) -> None:
        # GIVEN the skip list in tests/complement/.
        # WHEN it is loaded.
        result = subprocess.run(
            [sys.executable, "-I", str(SUMMARISER), "--repo-root", str(REPO_ROOT), "--skip-list",
             str(CHECKED_IN_SKIP_LIST), "--skip-pattern"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        # THEN it is accepted.
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
