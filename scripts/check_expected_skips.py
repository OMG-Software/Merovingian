#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fails a CI job when a Catch2 test case skipped that the job does not expect to skip.

`meson test` reports a Catch2 test case that called SKIP() as passed, so a runner that lacks a
precondition (a kernel feature, a loopback alias, a libcurl with SMTP) would pass green with the test
silently not run. Each CI job names the skips it expects in tests/expected_skips.json; this script
reads the XML reports the test binaries wrote (tests/support/CatchReportArguments.hpp, enabled by
MEROVINGIAN_CATCH_REPORT_DIR) and fails on any skip that is not on the job's list. See ADR-0546.

Exit status: 0 every skip was expected; 1 at least one unexpected skip (or, with --strict-stale,
a listed skip that did not happen); 2 the input is unusable (no report, a report that does not
parse or is incomplete, a bad allow-list, an unknown job). Unusable input fails closed: a crashed
binary leaves a truncated report, which must never read as "no skips".
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ALLOWLIST = Path(__file__).resolve().parents[1] / "tests" / "expected_skips.json"
SCENARIO_PREFIX = "Scenario: "
NO_MESSAGE = "(skipped without a recorded message)"


class InputError(Exception):
    """The reports or the allow-list cannot be trusted; the gate fails closed."""


@dataclass(frozen=True)
class Skip:
    report: str
    test: str
    message: str
    location: str


@dataclass(frozen=True)
class Expected:
    test: str
    message: str
    reason: str
    unverified: bool

    def matches(self, skip: Skip) -> bool:
        return self.test == skip.test and self.message in skip.message


def normalise(name: str) -> str:
    """Catch2 registers SCENARIO("x") as "Scenario: x"; the allow-list names it "x"."""
    return name[len(SCENARIO_PREFIX):] if name.startswith(SCENARIO_PREFIX) else name


def load_expected(path: Path, job: str) -> list[Expected]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise InputError(f"cannot read allow-list {path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("groups"), dict) or not isinstance(
        document.get("jobs"), dict
    ):
        raise InputError(f"{path}: expected an object with 'groups' and 'jobs' objects")
    groups, jobs = document["groups"], document["jobs"]
    if job not in jobs:
        raise InputError(f"{path}: no job named '{job}' (known: {', '.join(sorted(jobs))})")
    if not isinstance(jobs[job], list) or not all(isinstance(name, str) for name in jobs[job]):
        raise InputError(f"{path}: job '{job}' must be a list of group names")
    expected: list[Expected] = []
    for group_name in jobs[job]:
        if group_name not in groups or not isinstance(groups[group_name], list):
            raise InputError(f"{path}: job '{job}' names group '{group_name}', which is not defined")
        for entry in groups[group_name]:
            if not isinstance(entry, dict):
                raise InputError(f"{path}: group '{group_name}' has an entry that is not an object")
            test, reason = entry.get("test"), entry.get("reason")
            message = entry.get("message", "")
            if not isinstance(test, str) or not test.strip():
                raise InputError(f"{path}: group '{group_name}' has an entry with no 'test'")
            if not isinstance(reason, str) or not reason.strip():
                raise InputError(f"{path}: entry '{test}' in group '{group_name}' has no 'reason'")
            if not isinstance(message, str):
                raise InputError(f"{path}: entry '{test}' in group '{group_name}' has a 'message' that is not text")
            expected.append(
                Expected(normalise(test), message, reason, bool(entry.get("unverified", False)))
            )
    return expected


def read_report(path: Path) -> list[Skip]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise InputError(f"{path.name}: unreadable or truncated report (did the binary crash?): {error}") from error
    if root.tag != "Catch2TestRun":
        raise InputError(f"{path.name}: not a Catch2 XML report (root element is '{root.tag}')")
    # Written when the run finishes; its absence means the process died part-way.
    if root.find("OverallResults") is None:
        raise InputError(f"{path.name}: report has no OverallResults, so the run did not finish")
    skips: list[Skip] = []
    for case in root.iter("TestCase"):
        test = normalise(case.get("name", ""))
        found = False
        for skip in case.iter("Skip"):
            found = True
            location = f"{skip.get('filename', '?')}:{skip.get('line', '?')}"
            skips.append(Skip(path.name, test, " ".join((skip.text or "").split()) or NO_MESSAGE, location))
        result = case.find("OverallResult")
        if not found and result is not None and result.get("skips", "0") not in ("0", ""):
            skips.append(Skip(path.name, test, NO_MESSAGE, "?"))
    return skips


def collect(reports: Path) -> list[Skip]:
    if not reports.is_dir():
        raise InputError(f"report directory {reports} does not exist (no Catch2 binary wrote a report)")
    files = sorted(reports.glob("*.xml"))
    if not files:
        raise InputError(f"report directory {reports} holds no .xml report (no Catch2 binary wrote one)")
    skips: list[Skip] = []
    for path in files:
        skips.extend(read_report(path))
    return skips


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--job", required=True, help="job name in the allow-list's 'jobs' object")
    parser.add_argument("--reports", required=True, type=Path, help="directory of Catch2 XML reports")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST, help="allow-list JSON file")
    parser.add_argument(
        "--strict-stale", action="store_true", help="also fail when a listed skip did not happen"
    )
    args = parser.parse_args(argv)
    try:
        expected = load_expected(args.allowlist, args.job)
        skips = collect(args.reports)
    except InputError as error:
        print(f"check_expected_skips: {error}", file=sys.stderr)
        return 2

    unexpected = [skip for skip in skips if not any(entry.matches(skip) for entry in expected)]
    stale = [entry for entry in expected if not any(entry.matches(skip) for skip in skips)]

    for skip in unexpected:
        print(f"UNEXPECTED SKIP in job '{args.job}': {skip.test}")
        print(f"    message: {skip.message}")
        print(f"    at {skip.location} ({skip.report})")
    for entry in stale:
        kind = "unverified expected skip" if entry.unverified else "expected skip"
        suffix = f" containing '{entry.message}'" if entry.message else ""
        print(
            f"warning: {kind} did not happen in job '{args.job}': {entry.test}{suffix} -- "
            "remove the entry (or its 'unverified' flag) if the runner no longer skips it",
            file=sys.stderr,
        )
    print(
        f"check_expected_skips: job '{args.job}': {len(skips)} skip(s), {len(unexpected)} unexpected, "
        f"{len(stale)} listed skip(s) not seen"
    )
    if unexpected:
        print(
            "A skipped test case passed without running. Fix the runner, or add the skip to "
            "tests/expected_skips.json with a reason (docs/testing-standards.md).",
            file=sys.stderr,
        )
        return 1
    if stale and args.strict_stale:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
