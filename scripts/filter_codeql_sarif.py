#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drop CodeQL results this project has decided not to act on, before upload.

Three kinds of result are removed, each by its own ADR, and everything else is kept:

* cpp/unused-static-function on files under tests/ (ADR-0226). Catch2's SCENARIO
  macro expands to a static function that a static registrar object hands to the
  test registry; the rule does not follow that registration, so it reports every
  scenario, and every file-local helper only scenarios call, as unreachable.
* Every result on a file under subprojects/ or build/ (ADR-0527): third-party
  sources Meson's wraps download, and the build directory's compiler probes. No
  code this project writes is compiled from either.
* cpp/path-injection when every source it names is a command-line argument
  (ADR-0528): a path the operator passes when starting the process. A result
  that also names any other source is kept.

Any result the filter cannot place, or whose sources it cannot read, is kept.

usage: filter_codeql_sarif.py <report.sarif | directory of *.sarif>

Each report is rewritten in place. Input that is not SARIF, a missing path, or a
directory with no report is an error, and nothing is written, so the upload
step that follows fails instead of publishing an unfiltered report.
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import unquote

# (rule, top-level directory) pairs whose results are dropped (ADR-0226).
EXCLUSIONS = (("cpp/unused-static-function", "tests"),)

# Top-level directories holding no code this project writes, whose results are
# all dropped (ADR-0527): Meson's wrap downloads of third-party sources, and the
# CI build directory (codeql.yml builds into build/), where Meson's compiler
# probes live. Never add a directory that holds project code.
VENDORED_DIRECTORIES = ("subprojects", "build")

# The rule dropped when every source CodeQL names is a command-line argument
# (ADR-0528), and the label its message and related locations give that source.
OPERATOR_ARGUMENT_RULE = "cpp/path-injection"
COMMAND_LINE_SOURCE = "user input (a command-line argument)"

# A source reference in a result message: "[label](related location id)".
SOURCE_LINK = re.compile(r"\[([^\[\]]*)\]\((\d+)\)")

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


def sources_are_command_line_arguments(result: dict) -> bool:
    """Whether every source the result names is a command-line argument.

    CodeQL's cpp/path-injection message names each source as a link,
    "[user input (<kind>)](<id>)", to the related location with that id, one line
    per path; every source that reaches one sink is in the one result. True only
    when the message names at least one source, every link is labelled as a
    command-line argument and resolves to a related location labelled the same,
    and no related location is labelled as anything else. Related locations with
    no label (the path's steps) are ignored. Anything malformed is False, so the
    result is kept.
    """
    message = result.get("message")
    text = message.get("text") if isinstance(message, dict) else None
    related = result.get("relatedLocations")
    if not isinstance(text, str) or not isinstance(related, list):
        return False
    labelled = set()
    for entry in related:
        if not isinstance(entry, dict):
            return False
        entry_message = entry.get("message")
        label = entry_message.get("text") if isinstance(entry_message, dict) else None
        if label is None or label == "":
            continue
        if label != COMMAND_LINE_SOURCE or not isinstance(entry.get("id"), int):
            return False
        labelled.add(entry["id"])
    links = SOURCE_LINK.findall(text)
    if not links:
        return False
    return all(label == COMMAND_LINE_SOURCE and int(identifier) in labelled for label, identifier in links)


def is_excluded(result: object, tool: dict) -> bool:
    if not isinstance(result, dict):
        return False
    rule = rule_of(result, tool)
    directory = top_directory_of(result)
    if (rule, directory) in EXCLUSIONS or directory in VENDORED_DIRECTORIES:
        return True
    return rule == OPERATOR_ARGUMENT_RULE and sources_are_command_line_arguments(result)


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
            if is_excluded(result, run["tool"]):
                dropped += 1
            else:
                kept.append(result)
        run["results"] = kept
    return dropped


class Refused(Exception):
    pass


def confined(path: str, base: str) -> str:
    """`path` resolved, provided it is a real file or directory under `base`.

    The script rewrites what it is given in place, so it touches nothing outside
    the directory it is run from (the checkout, in CI), and no symbolic link,
    which could point anywhere.
    """
    if os.path.islink(path):
        raise Refused(f"{path} is a symbolic link")
    resolved = os.path.realpath(path)
    try:
        inside = os.path.commonpath([resolved, base]) == base
    except ValueError:
        # Different drives (Windows), or a mix of absolute and relative paths.
        inside = False
    if not inside:
        raise Refused(f"{path} is outside the working directory {base}")
    return resolved


def reports_in(target: str, base: str) -> list[str]:
    resolved = confined(os.path.join(base, target), base)
    if not os.path.isdir(resolved):
        return [resolved] if os.path.isfile(resolved) else []
    reports = []
    for name in sorted(os.listdir(resolved)):
        entry = os.path.join(resolved, name)
        # A link is passed on so confined() refuses it; anything else that is not a file is skipped.
        if name.endswith(".sarif") and (os.path.islink(entry) or os.path.isfile(entry)):
            reports.append(confined(entry, base))
    return reports


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: filter_codeql_sarif.py <report.sarif | directory>", file=sys.stderr)
        return 64
    base = os.path.realpath(os.getcwd())
    try:
        reports = reports_in(arguments[0], base)
    except Refused as error:
        print(f"filter_codeql_sarif: refused: {error}", file=sys.stderr)
        return 1
    if not reports:
        print(f"filter_codeql_sarif: no SARIF report at {arguments[0]}", file=sys.stderr)
        return 1
    # Parse and filter every report before writing any, so a bad one leaves all untouched.
    filtered = []
    for report in reports:
        try:
            with open(report, encoding="utf-8") as source:
                document = json.load(source)
            filtered.append((report, document, filter_report(document)))
        except (OSError, ValueError, NotSarif) as error:
            print(f"filter_codeql_sarif: {report} is not a SARIF report: {error}", file=sys.stderr)
            return 1
    for report, document, dropped in filtered:
        with open(report, "w", encoding="utf-8") as output:
            json.dump(document, output)
        print(f"{report}: dropped {dropped} result(s) excluded by ADR-0226, ADR-0527 and ADR-0528")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
