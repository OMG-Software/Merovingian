#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write the release SBOM, as SPDX 2.3 and CycloneDX 1.5 JSON (ADR-0598).

The inventory comes from two files the project already keeps accurate:

- docs/dependencies/licenses.md names every third-party component a shipped
  binary contains or links, with its SPDX licence;
- subprojects/*.wrap pin the vendored components to a source URL and SHA-256.

Components linked from the build platform's OS packages carry no version: each
package links whatever its platform supplies, and one SBOM covers every
package of a release. Vendored components carry the pinned version and hash.

The generator fails closed. A row in a shipped licences table, or a wrap file,
that it has no mapping for stops it with exit status 2, so a new dependency
cannot be left out of the SBOM silently.

Usage: generate_sbom.py --spdx OUT.spdx.json --cyclonedx OUT.cdx.json
                        [--commit SHA] [--repository OWNER/NAME]

The creation time is SOURCE_DATE_EPOCH when set, else the commit's committer
time, so the same commit always produces the same files.
"""

from __future__ import annotations

import argparse
import configparser
import importlib.util
import json
import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LICENSES_MD = REPO_ROOT / "docs" / "dependencies" / "licenses.md"
SUBPROJECTS = REPO_ROOT / "subprojects"
MESON_BUILD = REPO_ROOT / "meson.build"
LICENSE_SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "generate-license-summary.py"

# The licences.md sections whose rows are shipped in, or linked by, a binary.
SHIPPED_SECTIONS = ("Direct dependencies", "Transitive image codec dependencies")

# The licences.md sections that are never shipped. Any other section stops the
# generator, so a new section has to be classified here first.
UNSHIPPED_SECTIONS = ("Documentation tooling",)

PLATFORM = "platform"
VENDORED = "vendored"
PLATFORM_OR_VENDORED = "platform-or-vendored"


@dataclass(frozen=True)
class Mapping:
    """How one licences.md row becomes an SBOM component."""

    name: str
    linkage: str
    wrap: str | None = None


# Keyed by the licences.md "Dependency" cell.
COMPONENTS: dict[str, Mapping] = {
    "LibSodium": Mapping("libsodium", PLATFORM),
    "OpenSSL": Mapping("openssl", PLATFORM),
    "PostgreSQL libpq": Mapping("libpq", PLATFORM),
    "libcurl": Mapping("libcurl", PLATFORM_OR_VENDORED, wrap="curl.wrap"),
    "SQLite": Mapping("sqlite", VENDORED, wrap="sqlite3.wrap"),
    "yyjson": Mapping("yyjson", VENDORED, wrap="yyjson.wrap"),
    "libpng": Mapping("libpng", PLATFORM),
    "libjpeg-turbo": Mapping("libjpeg-turbo", PLATFORM),
}

# Shipped-section rows that are never linked into a production binary, and the
# wraps that build only them.
NOT_SHIPPED = {"Catch2"}
UNSHIPPED_WRAPS = {"catch2.wrap"}

COMMENTS = {
    PLATFORM: (
        "Taken from the build platform's OS package: linked dynamically by the "
        "distribution packages and statically by the static Linux tarball. The "
        "version is the one that platform supplies, so it is not stated here."
    ),
    VENDORED: "Built from the pinned Meson wrap and statically linked into every package.",
    PLATFORM_OR_VENDORED: (
        "The static Linux tarball statically links the pinned Meson wrap described "
        "here; every other package links the build platform's OS package "
        "dynamically, at the version that platform supplies."
    ),
}


class Refused(Exception):
    """The inputs do not describe every shipped component."""


@dataclass(frozen=True)
class Component:
    name: str
    linkage: str
    licence: str
    comment: str
    version: str | None = None
    source_url: str | None = None
    sha256: str | None = None

    @property
    def purl(self) -> str:
        return f"pkg:generic/{self.name}@{self.version}" if self.version else f"pkg:generic/{self.name}"


def load_license_tables() -> dict[str, list[dict[str, str | bool]]]:
    spec = importlib.util.spec_from_file_location("license_summary", LICENSE_SUMMARY_SCRIPT)
    if spec is None or spec.loader is None:
        raise Refused(f"cannot load {LICENSE_SUMMARY_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_tables(LICENSES_MD.read_text(encoding="utf-8"))


def project_version() -> str:
    # A version argument on its own line, with or without a trailing comma or comment.
    match = re.search(r"^\s*version:\s*'([0-9]+(?:\.[0-9]+)*)'\s*,?\s*(?:#.*)?$",
                      MESON_BUILD.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise Refused("cannot read the project version from meson.build")
    return match.group(1)


def read_wrap(filename: str) -> tuple[str, str, str]:
    """The pinned version, source URL and source SHA-256 of a wrap file."""
    path = SUBPROJECTS / filename
    if not path.is_file():
        raise Refused(f"{path} is missing")
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding="utf-8")
    if not parser.has_section("wrap-file"):
        raise Refused(f"{filename} is not a [wrap-file] entry")
    wrap = parser["wrap-file"]
    url = wrap.get("source_url", "")
    sha256 = wrap.get("source_hash", "")
    if not url or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise Refused(f"{filename} has no source_url or no SHA-256 source_hash")
    # A wrapdb version (3.54.1-1) names the upstream release before its last
    # dash; otherwise the unpacked directory ends in it (curl-8.23.0).
    version_match = re.fullmatch(r"([0-9][0-9.]*)-[0-9]+", wrap.get("wrapdb_version", ""))
    if version_match is None:
        version_match = re.search(r"-([0-9]+(?:\.[0-9]+)+)$", wrap.get("directory", ""))
    if version_match is None:
        raise Refused(f"cannot read a version from {filename}")
    return version_match.group(1), url, sha256


def inventory() -> list[Component]:
    tables = load_license_tables()
    unknown_sections = set(tables) - set(SHIPPED_SECTIONS) - set(UNSHIPPED_SECTIONS)
    if unknown_sections:
        raise Refused(f"licenses.md has unclassified sections: {', '.join(sorted(unknown_sections))}")
    missing_sections = [section for section in SHIPPED_SECTIONS if section not in tables]
    if missing_sections:
        raise Refused(f"licenses.md has no table for: {', '.join(missing_sections)}")

    components: list[Component] = []
    seen: set[str] = set()
    for section in SHIPPED_SECTIONS:
        for row in tables[section]:
            dependency = str(row.get("dependency", ""))
            if dependency in NOT_SHIPPED:
                continue
            mapping = COMPONENTS.get(dependency)
            if mapping is None:
                raise Refused(f"licenses.md row '{dependency}' has no SBOM mapping in {Path(__file__).name}")
            licence = str(row.get("spdx", ""))
            if not licence:
                raise Refused(f"licenses.md row '{dependency}' has no SPDX licence")
            seen.add(dependency)
            if mapping.wrap is None:
                components.append(Component(mapping.name, mapping.linkage, licence, COMMENTS[mapping.linkage]))
                continue
            version, url, sha256 = read_wrap(mapping.wrap)
            components.append(
                Component(mapping.name, mapping.linkage, licence, COMMENTS[mapping.linkage], version, url, sha256)
            )

    unlisted = set(COMPONENTS) - seen
    if unlisted:
        raise Refused(f"mapped components missing from licenses.md: {', '.join(sorted(unlisted))}")
    mapped_wraps = {mapping.wrap for mapping in COMPONENTS.values() if mapping.wrap}
    for wrap in sorted(path.name for path in SUBPROJECTS.glob("*.wrap")):
        if wrap not in mapped_wraps and wrap not in UNSHIPPED_WRAPS:
            raise Refused(f"subprojects/{wrap} is not mapped to an SBOM component")
    return components


def spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def spdx_document(components: list[Component], version: str, commit: str, repository: str, created: str) -> dict:
    root_id = spdx_id("merovingian")
    root = {
        "SPDXID": root_id,
        "name": "merovingian",
        "versionInfo": version,
        "downloadLocation": f"git+https://github.com/{repository}.git@{commit}",
        "filesAnalyzed": False,
        "licenseConcluded": "GPL-3.0-or-later",
        "licenseDeclared": "GPL-3.0-or-later",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:github/{repository}@v{version}",
            }
        ],
    }
    packages = [root]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}
    ]
    for component in components:
        package = {
            "SPDXID": spdx_id(component.name),
            "name": component.name,
            "downloadLocation": component.source_url or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": component.licence,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "comment": component.comment,
            "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component.purl}
            ],
        }
        if component.version:
            package["versionInfo"] = component.version
        if component.sha256:
            package["checksums"] = [{"algorithm": "SHA256", "checksumValue": component.sha256}]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "STATIC_LINK" if component.linkage == VENDORED else "DEPENDS_ON",
                "relatedSpdxElement": spdx_id(component.name),
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"merovingian-{version}",
        "documentNamespace": f"https://github.com/{repository}/sbom/merovingian-{version}-{commit}",
        "creationInfo": {"created": created, "creators": ["Tool: merovingian-generate_sbom"]},
        "packages": packages,
        "relationships": relationships,
    }


def cyclonedx_document(components: list[Component], version: str, commit: str, repository: str, created: str) -> dict:
    root_ref = f"merovingian@{version}"
    entries = []
    for component in components:
        entry = {
            "type": "library",
            "bom-ref": component.purl,
            "name": component.name,
            "description": component.comment,
            "licenses": [{"license": {"id": component.licence}}],
            "purl": component.purl,
        }
        if component.version:
            entry["version"] = component.version
        if component.sha256:
            entry["hashes"] = [{"alg": "SHA-256", "content": component.sha256}]
        if component.source_url:
            entry["externalReferences"] = [{"type": "distribution", "url": component.source_url}]
        entries.append(entry)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/{repository}/sbom/{version}/{commit}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": created,
            "tools": {"components": [{"type": "application", "name": "merovingian-generate_sbom"}]},
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "merovingian",
                "version": version,
                "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
                "purl": f"pkg:github/{repository}@v{version}",
                "externalReferences": [{"type": "vcs", "url": f"https://github.com/{repository}"}],
            },
        },
        "components": entries,
        "dependencies": [{"ref": root_ref, "dependsOn": [component.purl for component in components]}],
    }


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Refused(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def creation_time(commit: str) -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not epoch:
        epoch = git("log", "-1", "--format=%ct", commit)
    if not epoch.isdigit():
        raise Refused(f"creation time '{epoch}' is not a Unix timestamp")
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--spdx", type=Path, required=True)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--commit", default=None, help="source commit (default: HEAD)")
    parser.add_argument("--repository", default="OMG-Software/Merovingian")
    args = parser.parse_args(argv)

    try:
        commit = args.commit or git("rev-parse", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise Refused(f"commit '{commit}' is not a full SHA-1")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
            raise Refused(f"repository '{args.repository}' is not OWNER/NAME")
        version = project_version()
        components = inventory()
        created = creation_time(commit)
    except Refused as error:
        print(f"generate_sbom.py: {error}", file=sys.stderr)
        return 2

    write_json(args.spdx, spdx_document(components, version, commit, args.repository, created))
    write_json(args.cyclonedx, cyclonedx_document(components, version, commit, args.repository, created))
    print(f"SBOM for merovingian {version} at {commit[:12]}: {len(components)} components "
          f"-> {args.spdx}, {args.cyclonedx}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
