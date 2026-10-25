#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drop CodeQL results that are known false positives on Catch2 test sources (ADR-0226).

Catch2's SCENARIO macro expands to a static function that a static registrar
object hands to the test registry. CodeQL's cpp/unused-static-function does not
follow that registration, so it reports every scenario, and every file-local
helper only scenarios call, as unreachable. This removes exactly those results
for files under the repository's tests/ directory and keeps everything else:
the rule on production code, every other rule on test code, and any result it
cannot place.

usage: filter_codeql_sarif.py <report.sarif | directory of *.sarif>

Each report is rewritten in place. Input that is not SARIF, a missing path, or a
directory with no report is an error, and nothing is written, so the upload
step that follows fails instead of publishing an unfiltered report.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# (rule, top-level directory) pairs whose results are dropped.
EXCLUSIONS = (("cpp/unused-static-function", "tests"),)


class NotSarif(Exception):
    pass


def rule_of(result: dict, rules: list) -> str | None:
    if isinstance(result.get("ruleId"), str):
        return result["ruleId"]
    rule = result.get("rule")
    if isinstance(rule, dict):
        if isinstance(rule.get("id"), str):
            return rule["id"]
        index = rule.get("index")
        if isinstance(index, int) and 0 <= index < len(rules) and isinstance(rules[index], dict):
            identifier = rules[index].get("id")
            return identifier if isinstance(identifier, str) else None
    return None


def top_directory_of(result: dict) -> str | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    artifact = locations[0].get("physicalLocation", {}).get("artifactLocation", {})
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or "://" in uri or uri.startswith("/"):
        # Absolute or scheme-qualified locations are not under the source root
        # in a way this can check, so they are kept.
        return None
    parts = [part for part in uri.split("/") if part not in ("", ".")]
    return parts[0] if len(parts) > 1 else None


def filter_report(document: object) -> int:
    if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
        raise NotSarif("no runs array")
    dropped = 0
    for run in document["runs"]:
        if not isinstance(run, dict):
            raise NotSarif("a run is not an object")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise NotSarif("results is not an array")
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        rules = driver.get("rules", []) if isinstance(driver, dict) else []
        rules = rules if isinstance(rules, list) else []
        kept = []
        for result in results:
            excluded = isinstance(result, dict) and (rule_of(result, rules), top_directory_of(result)) in EXCLUSIONS
            if excluded:
                dropped += 1
            else:
                kept.append(result)
        run["results"] = kept
    return dropped


def reports_in(target: Path) -> list[Path]:
    if target.is_dir():
        return sorted(path for path in target.iterdir() if path.is_file() and path.suffix == ".sarif")
    return [target] if target.is_file() else []


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: filter_codeql_sarif.py <report.sarif | directory>", file=sys.stderr)
        return 64
    target = Path(arguments[0])
    reports = reports_in(target)
    if not reports:
        print(f"filter_codeql_sarif: no SARIF report at {target}", file=sys.stderr)
        return 1
    # Parse and filter every report before writing any, so a bad one leaves all untouched.
    filtered = []
    for report in reports:
        try:
            document = json.loads(report.read_text(encoding="utf-8"))
            filtered.append((report, document, filter_report(document)))
        except (OSError, ValueError, NotSarif) as error:
            print(f"filter_codeql_sarif: {report} is not a SARIF report: {error}", file=sys.stderr)
            return 1
    for report, document, dropped in filtered:
        report.write_text(json.dumps(document), encoding="utf-8")
        rules = ", ".join(f"{rule} under {directory}/" for rule, directory in EXCLUSIONS)
        print(f"{report}: dropped {dropped} result(s) of {rules}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
