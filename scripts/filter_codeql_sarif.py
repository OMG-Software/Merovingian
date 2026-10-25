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
from urllib.parse import unquote

# (rule, top-level directory) pairs whose results are dropped.
EXCLUSIONS = (("cpp/unused-static-function", "tests"),)

# The uriBaseId CodeQL gives locations relative to the checkout it analysed.
SOURCE_ROOT_BASE = "%SRCROOT%"


class NotSarif(Exception):
    pass


def component_rules(tool: dict, reference: object) -> list | None:
    """The rules array of the tool component `reference` names, or None.

    No reference means the driver. A reference is followed only by its index
    into tool.extensions (CodeQL's query packs); one that names a component any
    other way, or an index that is out of range, cannot be resolved here.
    """
    if reference is None:
        component = tool.get("driver")
    elif isinstance(reference, dict) and isinstance(reference.get("index"), int):
        extensions = tool.get("extensions")
        index = reference["index"]
        if not isinstance(extensions, list) or not 0 <= index < len(extensions):
            return None
        component = extensions[index]
    else:
        return None
    rules = component.get("rules") if isinstance(component, dict) else None
    return rules if isinstance(rules, list) else None


def rule_of(result: dict, tool: dict) -> str | None:
    """The result's rule ID, or None when it cannot be determined (the result is kept).

    SARIF 2.1.0 names a result's rule by ruleId, by rule.id, or by an index
    (rule.index, else ruleIndex) into the rules of the component rule.toolComponent
    names, the driver when it names none (3.27.5 to 3.27.7).
    """
    if isinstance(result.get("ruleId"), str):
        return result["ruleId"]
    rule = result.get("rule")
    rule = rule if isinstance(rule, dict) else {}
    if isinstance(rule.get("id"), str):
        return rule["id"]
    index = rule.get("index", result.get("ruleIndex"))
    rules = component_rules(tool, rule.get("toolComponent"))
    if not isinstance(index, int) or rules is None or not 0 <= index < len(rules):
        return None
    identifier = rules[index].get("id") if isinstance(rules[index], dict) else None
    return identifier if isinstance(identifier, str) else None


def top_directory_of(result: dict) -> str | None:
    """The first directory of a location relative to the source root, or None.

    None (the result is kept) unless the location is plainly inside the source
    root: CodeQL's %SRCROOT% base, a relative path, and after percent-decoding
    no parent segment or backslash that could make "tests/..." resolve elsewhere.
    """
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation")
    artifact = physical.get("artifactLocation") if isinstance(physical, dict) else None
    if not isinstance(artifact, dict) or artifact.get("uriBaseId") != SOURCE_ROOT_BASE:
        return None
    uri = artifact.get("uri")
    if not isinstance(uri, str):
        return None
    path = unquote(uri)
    if "://" in path or path.startswith("/") or "\\" in path:
        return None
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in parts:
        return None
    return parts[0] if len(parts) > 1 else None


def filter_report(document: object) -> int:
    # Validated before anything changes. An empty runs array is refused too:
    # uploading it would close every open alert as fixed.
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise NotSarif("not a SARIF 2.1.0 report")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise NotSarif("no runs")
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get("tool"), dict):
            raise NotSarif("a run is not an object with a tool")
        if not isinstance(run.get("results", []), list):
            raise NotSarif("results is not an array")
    dropped = 0
    for run in runs:
        kept = []
        for result in run.get("results", []):
            excluded = isinstance(result, dict) and (rule_of(result, run["tool"]), top_directory_of(result)) in EXCLUSIONS
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
