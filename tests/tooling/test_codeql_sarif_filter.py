#!/usr/bin/env python3
"""Behaviour of scripts/filter_codeql_sarif.py, run on CodeQL's SARIF before upload.

Catch2's SCENARIO macro expands to a static function registered by a static
object, which CodeQL's cpp/unused-static-function cannot follow, so every test
scenario (and every helper only scenarios call) is reported as unreachable
(ADR-0226). The filter must drop exactly those results under tests/ and keep
everything else: the same rule on production code, other rules on tests, and
any result it cannot place. It must fail, leaving the file as it was, on input
that is not SARIF, so an unfiltered or damaged report is never uploaded silently.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "filter_codeql_sarif.py"
RULE = "cpp/unused-static-function"


def result(
    rule_id: str | None, uri: str | None, *, rule_index: int | None = None, base: str | None = "%SRCROOT%"
) -> dict:
    entry: dict = {"message": {"text": "finding"}}
    if rule_id is not None:
        entry["ruleId"] = rule_id
    if rule_index is not None:
        entry["rule"] = {"index": rule_index}
    if uri is not None:
        artifact = {"uri": uri}
        if base is not None:
            artifact["uriBaseId"] = base
        entry["locations"] = [{"physicalLocation": {"artifactLocation": artifact}}]
    return entry


def sarif(results: list[dict], rules: list[str] | None = None) -> dict:
    driver: dict = {"name": "CodeQL"}
    if rules is not None:
        driver["rules"] = [{"id": rule} for rule in rules]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}


def kept_locations(document: dict) -> list[tuple[str | None, str | None]]:
    kept = []
    for entry in document["runs"][0]["results"]:
        locations = entry.get("locations") or [{}]
        uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
        kept.append((entry.get("ruleId"), uri))
    return kept


class FilterCodeqlSarifTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="sarif-filter-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def run_filter(self, target: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(target)], capture_output=True, text=True, check=False
        )

    def write(self, name: str, document: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_drops_only_the_unused_static_function_rule_under_tests(self) -> None:
        # GIVEN a report with the rule on test code, the rule on production code,
        # and another rule on test code.
        path = self.write(
            "cpp.sarif",
            sarif(
                [
                    result(RULE, "tests/unit/test_database_schema.cpp"),
                    result(RULE, "tests/integration/test_database_upgrade_flow.cpp"),
                    result(RULE, "src/database/schema.cpp"),
                    result("cpp/uncontrolled-allocation-size", "tests/unit/test_crypto.cpp"),
                ]
            ),
        )

        # WHEN the report is filtered.
        completed = self.run_filter(path)

        # THEN only the rule's results under tests/ are gone, and the count is reported.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            kept_locations(json.loads(path.read_text(encoding="utf-8"))),
            [
                (RULE, "src/database/schema.cpp"),
                ("cpp/uncontrolled-allocation-size", "tests/unit/test_crypto.cpp"),
            ],
        )
        self.assertIn("dropped 2", completed.stdout)

    def test_a_rule_named_only_by_index_is_recognised(self) -> None:
        # GIVEN results that name their rule through the driver's rules array.
        path = self.write(
            "cpp.sarif",
            sarif(
                [result(None, "tests/unit/test_crypto.cpp", rule_index=1),
                 result(None, "tests/unit/test_crypto.cpp", rule_index=0)],
                rules=["cpp/path-injection", RULE],
            ),
        )

        # WHEN the report is filtered.
        completed = self.run_filter(path)

        # THEN the indexed unused-static-function result is dropped and the other kept.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        remaining = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"]
        self.assertEqual([entry["rule"]["index"] for entry in remaining], [0])

    def test_only_a_top_level_tests_directory_matches(self) -> None:
        # GIVEN the rule on paths that merely contain "tests", and on a result with no location.
        path = self.write(
            "cpp.sarif",
            sarif(
                [
                    result(RULE, "src/tests/helper.cpp"),
                    result(RULE, "contests/entry.cpp"),
                    result(RULE, "testsuite/main.cpp"),
                    result(RULE, None),
                    result(RULE, "./tests/unit/test_crypto.cpp"),
                ]
            ),
        )

        # WHEN the report is filtered.
        completed = self.run_filter(path)

        # THEN only the result in the repository's own tests/ directory is dropped.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [uri for _, uri in kept_locations(json.loads(path.read_text(encoding="utf-8")))],
            ["src/tests/helper.cpp", "contests/entry.cpp", "testsuite/main.cpp", None],
        )

    def test_a_location_that_may_not_resolve_under_tests_is_kept(self) -> None:
        # GIVEN the rule on locations that start with tests/ but may resolve elsewhere:
        # a parent segment (plain or percent-encoded), a backslash, a base other than
        # the source root, or no base at all; and two that plainly resolve under tests/.
        path = self.write(
            "cpp.sarif",
            sarif(
                [
                    result(RULE, "tests/../src/example.cpp"),
                    result(RULE, "tests/%2E%2E/src/example.cpp"),
                    result(RULE, "tests\\..\\src\\example.cpp"),
                    result(RULE, "tests/unit/a.cpp", base="%HOME%"),
                    result(RULE, "tests/unit/a.cpp", base=None),
                    result(RULE, "tests//unit/./b.cpp"),
                    result(RULE, "tests/unit/test%5Fc.cpp"),
                ]
            ),
        )

        # WHEN the report is filtered.
        completed = self.run_filter(path)

        # THEN only the two that resolve under the source root's tests/ are dropped.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [uri for _, uri in kept_locations(json.loads(path.read_text(encoding="utf-8")))],
            [
                "tests/../src/example.cpp",
                "tests/%2E%2E/src/example.cpp",
                "tests\\..\\src\\example.cpp",
                "tests/unit/a.cpp",
                "tests/unit/a.cpp",
            ],
        )

    def test_every_report_in_a_directory_is_filtered(self) -> None:
        # GIVEN a directory holding two reports, as codeql-action's output directory does.
        first = self.write("cpp.sarif", sarif([result(RULE, "tests/unit/a.cpp")]))
        second = self.write("other.sarif", sarif([result(RULE, "tests/unit/b.cpp"), result(RULE, "src/b.cpp")]))
        untouched = self.root / "notes.txt"
        untouched.write_text("not a report", encoding="utf-8")

        # WHEN the directory is filtered.
        completed = self.run_filter(self.root)

        # THEN both reports lose their test results and other files are left alone.
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(kept_locations(json.loads(first.read_text(encoding="utf-8"))), [])
        self.assertEqual(kept_locations(json.loads(second.read_text(encoding="utf-8"))), [(RULE, "src/b.cpp")])
        self.assertEqual(untouched.read_text(encoding="utf-8"), "not a report")

    def test_input_that_is_not_sarif_fails_and_is_left_as_it_was(self) -> None:
        # GIVEN a file that is not JSON, and JSON that has no runs.
        broken = self.root / "broken.sarif"
        broken.write_text("{not json", encoding="utf-8")
        no_runs = self.write("no-runs.sarif", {"version": "2.1.0"})

        for path in (broken, no_runs):
            with self.subTest(path=path.name):
                before = path.read_bytes()

                # WHEN it is filtered.
                completed = self.run_filter(path)

                # THEN the filter fails and the file is unchanged.
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(path.read_bytes(), before)

    def test_a_missing_target_or_an_empty_directory_fails(self) -> None:
        # GIVEN a path that does not exist, and a directory with no report.
        empty = self.root / "empty"
        empty.mkdir()

        for target in (self.root / "absent.sarif", empty):
            with self.subTest(target=target.name):
                # WHEN it is filtered.
                completed = self.run_filter(target)

                # THEN the filter fails rather than letting an upload proceed with nothing filtered.
                self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
