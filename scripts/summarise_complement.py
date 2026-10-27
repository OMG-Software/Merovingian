#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Decide whether a Complement run is green (ADR-0234).

    summarise_complement.py --skip-list FILE --skip-pattern
        Print the `go test -skip` pattern for the list's skip entries (nothing
        when there are none).

    summarise_complement.py --skip-list FILE --log RUN.jsonl --listing LIST.jsonl --output SUMMARY.json
        Judge a `go test -json` run against the skip list. LIST.jsonl is
        `go test -json -list '.*'` over the same packages, used to check that
        skip entries name tests that exist.

`go test`'s exit status is not consulted: it is non-zero whenever any test
fails, listed or not. A run is green only when it ran tests, every failure is
listed, every expect-fail entry still fails, every entry names a test that
exists, no test was left unfinished and no package failed on its own.

Exit status: 0 green, 1 not green, 2 invalid input (the skip list, or a file
that cannot be read).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


CATEGORIES = {"spec", "non-spec", "room-version", "known-gap"}
MODES = {"expect-fail", "skip"}
REQUIRED_FIELDS = {"test", "package", "mode", "category", "reason"}
OPTIONAL_FIELDS = {"spec", "adr", "todo", "signed_off_by", "not_run_because"}
TEST_NAME = re.compile(r"Test[A-Za-z0-9_]*(/\S+)*")
PACKAGE_NAME = re.compile(r"tests(/[A-Za-z0-9_.-]+)*")
SPEC_PREFIX = "docs/matrix-v1.19-spec/"
ROOM_VERSION_ADR = "docs/adr/0076-"
TODO_PREFIX = "docs/todos/"
# Hiding a test whose name mentions any of these needs the maintainer's
# sign-off. It deliberately over-matches (device keys, auth flows): a
# sign-off is cheap, and a hidden federation signature check is not.
NEEDS_SIGN_OFF = re.compile(r"auth|sign|key|acl", re.IGNORECASE)
TERMINAL = {"pass", "fail", "skip"}


class InvalidInput(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    package: str
    test: str
    mode: str

    @property
    def key(self) -> str:
        return f"{self.package}:{self.test}"


def load_skip_list(path: Path, repo_root: Path) -> list[Entry]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InvalidInput(f"{path}: {error}") from error
    unknown_tables = set(data) - {"entry"}
    if unknown_tables:
        raise InvalidInput(f"{path}: unknown top-level keys {sorted(unknown_tables)}")
    raw_entries = data.get("entry", [])
    if not isinstance(raw_entries, list):
        raise InvalidInput(f"{path}: 'entry' must be an array of tables ([[entry]])")
    entries: list[Entry] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries, start=1):
        entry = check_entry(raw, f"{path}: entry {index}", repo_root)
        if entry.key in seen:
            raise InvalidInput(f"{path}: entry {index}: {entry.key} is listed twice")
        seen.add(entry.key)
        entries.append(entry)
    return entries


def check_entry(raw: object, where: str, repo_root: Path) -> Entry:
    if not isinstance(raw, dict):
        raise InvalidInput(f"{where}: not a table")
    fields = set(raw)
    missing = REQUIRED_FIELDS - fields
    if missing:
        raise InvalidInput(f"{where}: missing {sorted(missing)}")
    unknown = fields - REQUIRED_FIELDS - OPTIONAL_FIELDS
    if unknown:
        raise InvalidInput(f"{where}: unknown fields {sorted(unknown)}")
    for name, value in raw.items():
        if not isinstance(value, str) or not value.strip():
            raise InvalidInput(f"{where}: '{name}' must be a non-empty string")

    test, package, mode, category = raw["test"], raw["package"], raw["mode"], raw["category"]
    if not TEST_NAME.fullmatch(test):
        raise InvalidInput(f"{where}: '{test}' is not a Go test name")
    if not PACKAGE_NAME.fullmatch(package):
        raise InvalidInput(f"{where}: package '{package}' is not under Complement's tests/")
    if mode not in MODES:
        raise InvalidInput(f"{where}: mode must be one of {sorted(MODES)}")
    if category not in CATEGORIES:
        raise InvalidInput(f"{where}: category must be one of {sorted(CATEGORIES)}")

    if category in ("spec", "non-spec"):
        reference(raw, "spec", SPEC_PREFIX, where, repo_root)
    elif category == "room-version":
        reference(raw, "adr", ROOM_VERSION_ADR, where, repo_root)
    else:
        reference(raw, "todo", TODO_PREFIX, where, repo_root)

    if mode == "skip":
        if "/" in test:
            raise InvalidInput(f"{where}: only a top-level test can be skipped; use expect-fail for '{test}'")
        if "not_run_because" not in raw:
            raise InvalidInput(f"{where}: a skip entry must say why the test cannot run (not_run_because)")
    if NEEDS_SIGN_OFF.search(test) and "signed_off_by" not in raw:
        raise InvalidInput(f"{where}: '{test}' concerns auth, signatures, keys or ACLs; it needs signed_off_by")
    return Entry(package=package, test=test, mode=mode)


def reference(raw: dict, field: str, prefix: str, where: str, repo_root: Path) -> None:
    value = raw.get(field)
    if value is None:
        raise InvalidInput(f"{where}: category '{raw['category']}' needs '{field}'")
    path = value.split("#", 1)[0]
    if not path.startswith(prefix) or ".." in Path(path).parts:
        raise InvalidInput(f"{where}: '{field}' must name a file under {prefix}")
    if not (repo_root / path).is_file():
        raise InvalidInput(f"{where}: '{field}' names {path}, which does not exist")


def skip_pattern(entries: list[Entry]) -> str:
    names = sorted({entry.test for entry in entries if entry.mode == "skip"})
    return f"^({'|'.join(names)})$" if names else ""


def read_events(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InvalidInput(f"{path}: {error}") from error
    events = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue  # go test can interleave plain text; only events count
        if isinstance(record, dict) and isinstance(record.get("Action"), str):
            events.append(record)
    return events


def package_suffix(package: str) -> str:
    """The package path from Complement's tests/ directory down."""
    index = package.find("/tests")
    if package == "tests" or package.startswith("tests/"):
        return package
    return package[index + 1:] if index >= 0 else package


def listed_tests(events: list[dict]) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for record in events:
        if record["Action"] != "output" or "Test" in record:
            continue
        line = record.get("Output", "").strip()
        if TEST_NAME.fullmatch(line) and "/" not in line:
            names.setdefault(line, set()).add(package_suffix(record.get("Package", "")))
    return names


def summarise(entries: list[Entry], run_events: list[dict], listing_events: list[dict]) -> dict:
    outcome: dict[str, str] = {}
    started: set[str] = set()
    failed_packages: set[str] = set()
    packages_with_failed_tests: set[str] = set()
    for record in run_events:
        package = package_suffix(record.get("Package", ""))
        action = record["Action"]
        test = record.get("Test")
        if test is None:
            if action in ("fail", "build-fail"):
                failed_packages.add(package)
            continue
        key = f"{package}:{test}"
        if action == "run":
            started.add(key)
        elif action in TERMINAL:
            outcome[key] = action
            if action == "fail":
                packages_with_failed_tests.add(package)

    expected = {entry.key for entry in entries if entry.mode == "expect-fail"}

    def covered(key: str) -> bool:
        package, test = key.split(":", 1)
        parts = test.split("/")
        return any(f"{package}:{'/'.join(parts[:depth])}" in expected for depth in range(1, len(parts) + 1))

    failed = sorted(key for key, action in outcome.items() if action == "fail")

    # A failing parent is explained when every failing leaf beneath it is listed.
    # A leaf is a failing test with no failing test beneath it. Leaves, not
    # direct children, because a subtest's name may itself hold slashes
    # ("test /_matrix/media/v3 endpoint"), so the depth of a name says nothing.
    def explained(key: str) -> bool:
        if covered(key):
            return True
        beneath = [other for other in failed if other.startswith(key + "/")]
        leaves = [other for other in beneath if not any(deeper.startswith(other + "/") for deeper in beneath)]
        return bool(leaves) and all(covered(leaf) for leaf in leaves)

    unexpected = [key for key in failed if not explained(key)]
    unfinished = sorted(started - set(outcome))

    stale, missing, not_run, skip_not_applied = [], [], [], []
    listing = listed_tests(listing_events)
    for entry in entries:
        if entry.mode == "expect-fail":
            if entry.key not in outcome and entry.key not in started:
                missing.append(entry.key)
            elif outcome.get(entry.key) in ("pass", "skip"):
                stale.append(entry.key)
            continue
        packages = listing.get(entry.test, set())
        if packages - {entry.package}:
            raise InvalidInput(
                f"skip entry {entry.key}: {entry.test} also exists in {sorted(packages - {entry.package})}, "
                "and go test -skip would skip it there too")
        if entry.key in outcome or entry.key in started:
            skip_not_applied.append(entry.key)
        elif entry.package not in packages:
            missing.append(entry.key)
        else:
            not_run.append(entry.key)

    package_failures = sorted(failed_packages - packages_with_failed_tests)
    counts = {"pass": 0, "fail": 0, "skip": 0}
    top_level = {"pass": 0, "fail": 0, "skip": 0}
    for key, action in outcome.items():
        counts[action] += 1
        if "/" not in key.split(":", 1)[1]:
            top_level[action] += 1

    problems = [unexpected, unfinished, stale, missing, skip_not_applied, package_failures]
    verdict = "pass" if outcome and not any(problems) else "fail"
    return {
        "verdict": verdict,
        "results": counts,
        "top_level_results": top_level,
        "expected_failures": sorted(key for key in failed if covered(key) and key in expected),
        "unexpected_failures": unexpected,
        "unfinished": unfinished,
        "stale_entries": sorted(stale),
        "missing_entries": sorted(missing),
        "not_run": sorted(not_run),
        "skip_not_applied": sorted(skip_not_applied),
        "package_failures": package_failures,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--skip-list", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-pattern", action="store_true")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--listing", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        entries = load_skip_list(args.skip_list, args.repo_root)
        if args.skip_pattern:
            pattern = skip_pattern(entries)
            if pattern:
                print(pattern)
            return 0
        if args.log is None or args.listing is None or args.output is None:
            parser.error("--log, --listing and --output are required unless --skip-pattern is given")
        summary = summarise(entries, read_events(args.log), read_events(args.listing))
    except InvalidInput as error:
        print(f"summarise_complement: {error}", file=sys.stderr)
        return 2

    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    results = summary["results"]
    print(f"Complement: {summary['verdict']} "
          f"(pass {results['pass']}, fail {results['fail']}, skip {results['skip']}; "
          f"{len(summary['expected_failures'])} expected failures)")
    for field in ("unexpected_failures", "unfinished", "stale_entries", "missing_entries", "skip_not_applied",
                  "package_failures"):
        for key in summary[field]:
            print(f"  {field.replace('_', ' ')}: {key}")
    return 0 if summary["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
