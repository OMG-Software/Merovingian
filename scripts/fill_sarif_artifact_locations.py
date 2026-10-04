#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Give every result in Grype's SBOM-sourced SARIF a non-empty artifact location.

Grype scanning an SPDX SBOM has no file locations for the packages it matches,
so it writes `physicalLocation.artifactLocation.uri: ""`. GitHub code scanning
rejects the whole upload when any result has an empty location
("locationFromSarifResult: expected artifact location"), so a single finding
stops every finding from reaching code scanning.

The SBOM still records which manifest declared each package: syft links every
package to its manifest file with an SPDX `OTHER` relationship whose comment
starts `evident-by:`. This script follows those links from each result's purls
to the manifest (e.g. `requirements-docs.txt`, `.github/workflows/ci.yml`) and
uses it as the location. A result whose package has no linked manifest is
located at the scanned SBOM file instead. Results that already carry a
location are left alone. The input SARIF is never modified; the filled copy is
written to a separate file. See ADR-0103.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any


EVIDENT_BY_PREFIX = "evident-by:"


def safe_repository_path(name: str) -> str | None:
    """Return `name` as a repository-relative POSIX path, or None if it is not one.

    SBOM file names are data from a tool, not trusted paths: only plain
    relative paths that stay inside the repository become SARIF locations.
    """
    if not name or "\\" in name or "://" in name:
        return None
    if name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if not name or path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        return None
    return str(path)


def manifests_by_purl(sbom: dict[str, Any]) -> dict[str, list[str]]:
    """Map each package purl in an SPDX SBOM to the sorted manifests evidencing it."""
    file_names: dict[str, str] = {}
    for entry in sbom.get("files", []):
        path = safe_repository_path(str(entry.get("fileName", "")))
        if path is not None:
            file_names[str(entry.get("SPDXID", ""))] = path

    manifests_by_package: dict[str, set[str]] = {}
    for relationship in sbom.get("relationships", []):
        if relationship.get("relationshipType") != "OTHER":
            continue
        if not str(relationship.get("comment", "")).startswith(EVIDENT_BY_PREFIX):
            continue
        path = file_names.get(str(relationship.get("relatedSpdxElement", "")))
        if path is not None:
            package_id = str(relationship.get("spdxElementId", ""))
            manifests_by_package.setdefault(package_id, set()).add(path)

    result: dict[str, set[str]] = {}
    for package in sbom.get("packages", []):
        manifests = manifests_by_package.get(str(package.get("SPDXID", "")), set())
        for ref in package.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                result.setdefault(str(ref.get("referenceLocator", "")), set()).update(manifests)
    return {purl: sorted(paths) for purl, paths in result.items()}


def has_artifact_location(location: dict[str, Any]) -> bool:
    uri = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
    return isinstance(uri, str) and uri != ""


def physical_location(uri: str) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
        }
    }


def fill_artifact_locations(
    sarif: dict[str, Any], sbom: dict[str, Any], fallback_uri: str
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Return a copy of `sarif` with every empty location filled, and what was filled.

    Raises ValueError if `sarif` is not a SARIF log or `fallback_uri` is unsafe.
    """
    if not isinstance(sarif.get("runs"), list):
        raise ValueError("input is not a SARIF log: it has no 'runs' array")
    fallback = safe_repository_path(fallback_uri)
    if fallback is None:
        raise ValueError(f"fallback URI {fallback_uri!r} is not a repository-relative path")

    purl_manifests = manifests_by_purl(sbom)
    filled = copy.deepcopy(sarif)
    changes: list[tuple[str, str]] = []

    for run in filled["runs"]:
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        purls_by_rule = {
            str(rule.get("id", "")): list(rule.get("properties", {}).get("purls", [])) for rule in rules
        }
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if locations and all(has_artifact_location(location) for location in locations):
                continue

            rule_id = str(result.get("ruleId", ""))
            manifests = sorted(
                {path for purl in purls_by_rule.get(rule_id, []) for path in purl_manifests.get(purl, [])}
            )
            primary = manifests[0] if manifests else fallback

            if not locations:
                locations = [physical_location(primary)]
                result["locations"] = locations
            for location in locations:
                if not has_artifact_location(location):
                    location.setdefault("physicalLocation", {}).setdefault("artifactLocation", {})["uri"] = primary
            if len(manifests) > 1:
                result["relatedLocations"] = [physical_location(path) for path in manifests[1:]]

            message = result.get("message", {})
            text = message.get("text")
            if isinstance(text, str) and text.endswith("found at: "):
                message["text"] = text + primary

            changes.append((rule_id, primary))

    return filled, changes


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sarif", required=True, type=Path, help="Grype SARIF output to read")
    parser.add_argument("--sbom", required=True, type=Path, help="SPDX JSON SBOM that Grype scanned")
    parser.add_argument("--output", required=True, type=Path, help="where to write the filled SARIF")
    parser.add_argument(
        "--fallback-uri",
        required=True,
        help="location for findings whose package has no manifest in the SBOM",
    )
    args = parser.parse_args(argv)

    try:
        sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        if not isinstance(sarif, dict) or not isinstance(sbom, dict):
            raise ValueError("SARIF and SBOM must both be JSON objects")
        filled, changes = fill_artifact_locations(sarif, sbom, args.fallback_uri)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    args.output.write_text(json.dumps(filled, indent=2) + "\n", encoding="utf-8")
    for rule_id, uri in changes:
        print(f"filled location: {rule_id} -> {uri}")
    print(f"{len(changes)} result(s) located; wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
