#!/usr/bin/env python3
"""scripts/generate_sbom.py describes every shipped component and refuses an inventory it cannot map (ADR-0598)."""
from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts" / "generate_sbom.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SHIPPED_SECTIONS = ("Direct dependencies", "Transitive image codec dependencies")
TEST_ONLY = {"Catch2"}


def licence_rows() -> dict[str, list[tuple[str, str]]]:
    """(dependency, SPDX) rows of each licenses.md section, read independently of the generator."""
    rows: dict[str, list[tuple[str, str]]] = {}
    section = None
    for line in (REPO_ROOT / "docs" / "dependencies" / "licenses.md").read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## (.+)$", line)
        if heading:
            section = heading.group(1)
            continue
        cells = [cell.strip().strip("`") for cell in line.split("|")[1:-1]]
        if section and len(cells) >= 3 and cells[0] not in ("Dependency",) and not set(cells[0]) <= {"-"}:
            rows.setdefault(section, []).append((cells[0], cells[2]))
    return rows


def wrap(name: str) -> configparser.SectionProxy:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(REPO_ROOT / "subprojects" / name, encoding="utf-8")
    return parser["wrap-file"]


class GeneratorTree:
    """A copy of the files the generator reads, so a test can change them."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for relative in ("scripts/generate_sbom.py", "scripts/generate-license-summary.py",
                         "docs/dependencies/licenses.md", "meson.build"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO_ROOT / relative, target)
        (self.root / "subprojects").mkdir()
        for wrap_file in (REPO_ROOT / "subprojects").glob("*.wrap"):
            shutil.copyfile(wrap_file, self.root / "subprojects" / wrap_file.name)

    def run(self, epoch: str = "1700000000") -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        spdx = self.root / "out.spdx.json"
        cyclonedx = self.root / "out.cdx.json"
        env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
        result = subprocess.run(
            [sys.executable, "-I", str(self.root / "scripts" / "generate_sbom.py"),
             "--spdx", str(spdx), "--cyclonedx", str(cyclonedx), "--commit", COMMIT],
            capture_output=True, text=True, env=env, check=False,
        )
        return result, spdx, cyclonedx

    def close(self) -> None:
        self._tmp.cleanup()


class GenerateSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = GeneratorTree()
        self.addCleanup(self.tree.close)

    def generate(self) -> tuple[dict, dict]:
        result, spdx, cyclonedx = self.tree.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(spdx.read_text(encoding="utf-8")), json.loads(cyclonedx.read_text(encoding="utf-8"))

    def test_every_shipped_licence_row_is_a_component_with_its_licence(self) -> None:
        # GIVEN the shipped tables of licenses.md, less the test-only rows.
        rows = licence_rows()
        shipped = [row for section in SHIPPED_SECTIONS for row in rows[section] if row[0] not in TEST_ONLY]
        self.assertGreaterEqual(len(shipped), 8)

        # WHEN the SBOM is generated.
        spdx, cyclonedx = self.generate()

        # THEN each format names exactly that many components besides the root,
        # with the licence the table records, and nothing test-only.
        spdx_licences = sorted(p["licenseDeclared"] for p in spdx["packages"] if p["name"] != "merovingian")
        cdx_licences = sorted(c["licenses"][0]["license"]["id"] for c in cyclonedx["components"])
        self.assertEqual(spdx_licences, sorted(spdx for _, spdx in shipped))
        self.assertEqual(cdx_licences, sorted(spdx for _, spdx in shipped))
        names = {p["name"] for p in spdx["packages"]}
        self.assertNotIn("catch2", {name.lower() for name in names})
        self.assertIn("libsodium", names)
        self.assertIn("openssl", names)
        self.assertIn("libpq", names)

    def test_vendored_components_carry_the_wrap_pin(self) -> None:
        # GIVEN the pinned wraps of the statically linked components.
        pins = {"sqlite": wrap("sqlite3.wrap"), "yyjson": wrap("yyjson.wrap"), "libcurl": wrap("curl.wrap")}

        # WHEN the SBOM is generated.
        spdx, cyclonedx = self.generate()

        # THEN each carries the wrap's source URL and SHA-256 in both formats,
        # and a version that the wrap's directory or wrapdb version names.
        packages = {p["name"]: p for p in spdx["packages"]}
        components = {c["name"]: c for c in cyclonedx["components"]}
        for name, pin in pins.items():
            with self.subTest(component=name):
                package = packages[name]
                self.assertEqual(package["downloadLocation"], pin["source_url"])
                self.assertEqual(package["checksums"], [{"algorithm": "SHA256", "checksumValue": pin["source_hash"]}])
                self.assertIn(package["versionInfo"].replace(".", ""), pin["directory"].replace(".", "")
                              + pin.get("wrapdb_version", "").replace(".", ""))
                self.assertEqual(components[name]["hashes"], [{"alg": "SHA-256", "content": pin["source_hash"]}])
                self.assertEqual(components[name]["version"], package["versionInfo"])
        self.assertEqual(packages["sqlite"]["versionInfo"], "3.54.1")

    def test_platform_components_claim_no_version(self) -> None:
        # GIVEN libsodium, which every package links from its platform.
        # WHEN the SBOM is generated.
        spdx, cyclonedx = self.generate()

        # THEN it carries no version or hash, since one SBOM covers packages
        # whose platforms supply different versions.
        package = next(p for p in spdx["packages"] if p["name"] == "libsodium")
        self.assertNotIn("versionInfo", package)
        self.assertNotIn("checksums", package)
        self.assertEqual(package["downloadLocation"], "NOASSERTION")
        component = next(c for c in cyclonedx["components"] if c["name"] == "libsodium")
        self.assertNotIn("version", component)

    def test_documents_describe_this_version_and_commit(self) -> None:
        # GIVEN the project version in meson.build.
        version = re.search(r"^\s*version:\s*'([0-9.]+)',$", (REPO_ROOT / "meson.build").read_text(encoding="utf-8"),
                            re.MULTILINE).group(1)

        # WHEN the SBOM is generated for a commit.
        spdx, cyclonedx = self.generate()

        # THEN the SPDX document describes merovingian at that version and
        # commit, every component is related to it, and the CycloneDX root and
        # dependency graph say the same.
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx["dataLicense"], "CC0-1.0")
        root = next(p for p in spdx["packages"] if p["name"] == "merovingian")
        self.assertEqual(root["versionInfo"], version)
        self.assertTrue(root["downloadLocation"].endswith(f"@{COMMIT}"))
        self.assertIn(COMMIT, spdx["documentNamespace"])
        related = {r["relatedSpdxElement"] for r in spdx["relationships"] if r["spdxElementId"] == root["SPDXID"]}
        self.assertEqual(related, {p["SPDXID"] for p in spdx["packages"]} - {root["SPDXID"]})
        self.assertEqual(spdx["creationInfo"]["created"], "2023-11-14T22:13:20Z")

        self.assertEqual(cyclonedx["bomFormat"], "CycloneDX")
        self.assertEqual(cyclonedx["specVersion"], "1.5")
        self.assertEqual(cyclonedx["metadata"]["component"]["version"], version)
        self.assertRegex(cyclonedx["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        depends = cyclonedx["dependencies"][0]
        self.assertEqual(depends["ref"], cyclonedx["metadata"]["component"]["bom-ref"])
        self.assertEqual(sorted(depends["dependsOn"]), sorted(c["bom-ref"] for c in cyclonedx["components"]))

    def test_the_same_commit_gives_the_same_files(self) -> None:
        # GIVEN one commit and creation time.
        first, spdx, cyclonedx = self.tree.run()
        self.assertEqual(first.returncode, 0, first.stderr)
        before = (spdx.read_bytes(), cyclonedx.read_bytes())

        # WHEN the SBOM is generated again.
        second, spdx, cyclonedx = self.tree.run()

        # THEN both files are byte for byte the same.
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((spdx.read_bytes(), cyclonedx.read_bytes()), before)

    def test_an_unmapped_licence_row_is_refused(self) -> None:
        # GIVEN a shipped dependency the generator has no mapping for.
        licences = self.tree.root / "docs" / "dependencies" / "licenses.md"
        text = licences.read_text(encoding="utf-8")
        text = text.replace("| yyjson |", "| zlib | zlib | `Zlib` | Yes | Compression. |\n| yyjson |", 1)
        licences.write_text(text, encoding="utf-8")

        # WHEN the SBOM is generated.
        result, spdx, _ = self.tree.run()

        # THEN it refuses with status 2, names the row, and writes nothing.
        self.assertEqual(result.returncode, 2)
        self.assertIn("zlib", result.stderr)
        self.assertFalse(spdx.exists())

    def test_an_unmapped_wrap_is_refused(self) -> None:
        # GIVEN a vendored wrap that no component maps.
        shutil.copyfile(self.tree.root / "subprojects" / "yyjson.wrap", self.tree.root / "subprojects" / "zlib.wrap")

        # WHEN the SBOM is generated.
        result, spdx, _ = self.tree.run()

        # THEN it refuses with status 2 and names the wrap.
        self.assertEqual(result.returncode, 2)
        self.assertIn("zlib.wrap", result.stderr)
        self.assertFalse(spdx.exists())

    def test_an_unclassified_licence_section_is_refused(self) -> None:
        # GIVEN a licenses.md section the generator does not know to be shipped or not.
        licences = self.tree.root / "docs" / "dependencies" / "licenses.md"
        licences.write_text(
            licences.read_text(encoding="utf-8")
            + "\n## Bundled fonts\n\n| Dependency | License | SPDX | Compatible | Notes |\n| --- | --- | --- | --- | --- |\n"
            "| DejaVu | Bitstream Vera | `Bitstream-Vera` | Yes | x |\n",
            encoding="utf-8",
        )

        # WHEN the SBOM is generated.
        result, _, _ = self.tree.run()

        # THEN it refuses with status 2 and names the section.
        self.assertEqual(result.returncode, 2)
        self.assertIn("Bundled fonts", result.stderr)

    def test_a_wrap_without_a_source_hash_is_refused(self) -> None:
        # GIVEN the SQLite wrap with its source hash removed.
        wrap_file = self.tree.root / "subprojects" / "sqlite3.wrap"
        wrap_file.write_text(re.sub(r"^source_hash = .*\n", "", wrap_file.read_text(encoding="utf-8"),
                                    flags=re.MULTILINE), encoding="utf-8")

        # WHEN the SBOM is generated.
        result, _, _ = self.tree.run()

        # THEN it refuses with status 2 rather than describe an unpinned component.
        self.assertEqual(result.returncode, 2)
        self.assertIn("sqlite3.wrap", result.stderr)


if __name__ == "__main__":
    unittest.main()
