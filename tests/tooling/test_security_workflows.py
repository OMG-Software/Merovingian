#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "secret-scan.yml"
DEPENDENCY_TRIAGE_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "dependency-vulnerability-triage.yml"
)
SBOM_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sbom.yml"
SANITIZERS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sanitizers.yml"
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
DEPENDENCY_REVIEW_CONFIG = REPO_ROOT / ".github" / "dependency-review-config.yml"
RELEASE_READINESS_SCRIPT = REPO_ROOT / "scripts" / "check-release-readiness.sh"
SERVER_MAIN = REPO_ROOT / "src" / "main.cpp"
SMOKE_TESTS = REPO_ROOT / "tests" / "smoke" / "meson.build"
SARIF_LOCATION_SCRIPT = REPO_ROOT / "scripts" / "fill_sarif_artifact_locations.py"

SBOM_NAME = "dependency-triage.spdx.json"


def load_sarif_location_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "fill_sarif_artifact_locations", SARIF_LOCATION_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def grype_sarif(*findings: tuple[str, str, str]) -> dict[str, Any]:
    """Grype SARIF as produced from an SPDX SBOM: every location URI is empty.

    Each finding is (rule id, package name, purl), shaped like run 37116890711.
    """
    rules = []
    results = []
    for rule_id, package, purl in findings:
        rules.append(
            {
                "id": rule_id,
                "name": "PythonMatcherExactDirectMatch",
                "shortDescription": {"text": f"{rule_id} vulnerability for {package} package"},
                "properties": {"purls": [purl], "security-severity": "5.4"},
            }
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": f"A medium vulnerability in python package: {package}, "
                    "version 9.6.20 was found at: "
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": ""},
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "endLine": 1,
                                "endColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": "81bb826e:1"},
            }
        )
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "grype", "rules": rules}},
                "results": results,
            }
        ],
    }


def spdx_sbom() -> dict[str, Any]:
    """An SPDX SBOM as written by anchore/sbom-action for the repository root."""

    def package(spdx_id: str, name: str, purl: str) -> dict[str, Any]:
        return {
            "name": name,
            "SPDXID": spdx_id,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ],
        }

    def evident_by(package_id: str, file_id: str) -> dict[str, Any]:
        return {
            "spdxElementId": package_id,
            "relatedSpdxElement": file_id,
            "relationshipType": "OTHER",
            "comment": "evident-by: indicates the package's existence is evident by the given file",
        }

    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            package("SPDXRef-Package-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20"),
            package("SPDXRef-Package-checkout", "actions/checkout", "pkg:github/actions/checkout@v4"),
            package("SPDXRef-Package-orphan", "orphan", "pkg:generic/orphan@1.0"),
        ],
        "files": [
            {"fileName": "requirements-docs.txt", "SPDXID": "SPDXRef-File-requirements-docs"},
            {"fileName": ".github/workflows/pages.yml", "SPDXID": "SPDXRef-File-pages"},
            {"fileName": ".github/workflows/ci.yml", "SPDXID": "SPDXRef-File-ci"},
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DocumentRoot-Directory-.",
                "relatedSpdxElement": "SPDXRef-Package-mkdocs-material",
                "relationshipType": "CONTAINS",
            },
            evident_by("SPDXRef-Package-mkdocs-material", "SPDXRef-File-requirements-docs"),
            evident_by("SPDXRef-Package-checkout", "SPDXRef-File-pages"),
            evident_by("SPDXRef-Package-checkout", "SPDXRef-File-ci"),
        ],
    }


def first_location(result: dict[str, Any]) -> dict[str, Any]:
    return result["locations"][0]["physicalLocation"]["artifactLocation"]


class SecurityWorkflowTests(unittest.TestCase):
    def test_secret_scan_workflow_uses_gitleaks_and_uploads_sarif(self) -> None:
        # GIVEN the repository secret-scan workflow.
        self.assertTrue(SECRET_SCAN_WORKFLOW.is_file(), "secret scan workflow is missing")
        workflow = SECRET_SCAN_WORKFLOW.read_text(encoding="utf-8")

        # WHEN repository history is scanned for leaked credentials.
        # THEN the workflow runs Gitleaks and publishes SARIF results.
        self.assertIn("ghcr.io/gitleaks/gitleaks:v8.30.0", workflow)
        self.assertIn("--report-format sarif", workflow)
        self.assertIn("github/codeql-action/upload-sarif@v4", workflow)
        self.assertIn("security-events: write", workflow)

    def test_secret_scan_uses_a_repository_allowlist_for_known_test_fixtures(self) -> None:
        # GIVEN the repository Gitleaks configuration.
        self.assertTrue(GITLEAKS_CONFIG.is_file(), "gitleaks config is missing")
        config = GITLEAKS_CONFIG.read_text(encoding="utf-8")

        # WHEN test fixtures and CI placeholders are scanned.
        # THEN the allowlist keeps those reviewed placeholders from breaking the gate.
        self.assertIn("useDefault = true", config)
        self.assertIn("(^|/)tests/", config)
        self.assertIn("^\\.github/workflows/postgres-integration\\.yml$", config)

    def test_dependency_triage_reviews_pull_requests_and_uploads_scan_results(self) -> None:
        # GIVEN the repository dependency-triage workflow.
        self.assertTrue(DEPENDENCY_TRIAGE_WORKFLOW.is_file(), "dependency triage workflow is missing")
        workflow = DEPENDENCY_TRIAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN dependency changes or scheduled triage runs occur.
        # THEN the workflow reviews PR dependency diffs and uploads SBOM-backed SARIF results.
        self.assertIn("actions/dependency-review-action@v5", workflow)
        self.assertIn("anchore/sbom-action@v0", workflow)
        self.assertIn("anchore/scan-action@v7", workflow)
        self.assertIn("github/codeql-action/upload-sarif@v4", workflow)
        self.assertIn("output-format: sarif", workflow)

    def test_dependency_triage_keeps_its_gate_and_scans_the_archived_sbom(self) -> None:
        # GIVEN the repository dependency-triage workflow.
        workflow = DEPENDENCY_TRIAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Grype scans the dependency inventory.
        # THEN it scans the SBOM that is archived with the run, reports only
        # fixable findings, treats high as the cutoff, and never fails the build.
        self.assertIn("sbom: dependency-triage.spdx.json", workflow)
        self.assertNotIn("path: .\n          fail-build", workflow)
        self.assertIn("fail-build: false", workflow)
        self.assertIn("only-fixed: true", workflow)
        self.assertIn("severity-cutoff: high", workflow)

    def test_dependency_triage_fills_sarif_locations_before_upload(self) -> None:
        # GIVEN the repository dependency-triage workflow.
        workflow = DEPENDENCY_TRIAGE_WORKFLOW.read_text(encoding="utf-8")

        # WHEN Grype's SBOM-sourced SARIF reaches code scanning.
        # THEN the workflow fills empty artifact locations between the scan and
        # the upload, and uploads the filled file rather than the raw output.
        scan = workflow.index("uses: anchore/scan-action@v7")
        fill = workflow.index("scripts/fill_sarif_artifact_locations.py")
        upload = workflow.index("uses: github/codeql-action/upload-sarif@v4")
        self.assertLess(scan, fill)
        self.assertLess(fill, upload)
        self.assertIn("sarif_file: dependency-triage.code-scanning.sarif", workflow)
        self.assertNotIn("sarif_file: ${{ steps.dependency-scan.outputs.sarif }}", workflow)

        # AND both SARIF files are archived with the SBOM for audit.
        self.assertIn("            dependency-triage.sarif\n", workflow)
        self.assertIn("            dependency-triage.code-scanning.sarif\n", workflow)

    def test_dependency_triage_passes_step_outputs_through_the_environment(self) -> None:
        # GIVEN the step that post-processes the scan output.
        workflow = DEPENDENCY_TRIAGE_WORKFLOW.read_text(encoding="utf-8")
        fill_step = workflow[workflow.index("- name: Fill dependency SARIF artifact locations"):]
        fill_step = fill_step[: fill_step.index("\n      - name:")]

        # WHEN the step's shell command is rendered.
        # THEN no expression is interpolated into the script body; the scan
        # output path arrives as an environment variable.
        run_body = fill_step[fill_step.index("run:"):]
        self.assertNotIn("${{", run_body)
        self.assertIn("SCAN_SARIF: ${{ steps.dependency-scan.outputs.sarif }}", fill_step)

    def test_dependency_review_configuration_enables_license_checks(self) -> None:
        # GIVEN the dependency-review action configuration.
        self.assertTrue(DEPENDENCY_REVIEW_CONFIG.is_file(), "dependency review config is missing")
        config = DEPENDENCY_REVIEW_CONFIG.read_text(encoding="utf-8")

        # WHEN pull requests add vulnerable or incompatible dependencies.
        # THEN the repository fails on high-severity vulnerability introductions,
        # reports patched versions, and checks license compatibility.
        self.assertIn("fail-on-severity: high", config)
        self.assertIn("vulnerability-check: true", config)
        self.assertIn("license-check: true", config)
        self.assertIn("show-patched-versions: true", config)

    def test_sbom_workflow_generates_spdx_and_cyclonedx_outputs(self) -> None:
        # GIVEN the repository SBOM workflow.
        self.assertTrue(SBOM_WORKFLOW.is_file(), "sbom workflow is missing")
        workflow = SBOM_WORKFLOW.read_text(encoding="utf-8")

        # WHEN CI or a published release requests an inventory.
        # THEN the workflow emits both SPDX and CycloneDX JSON SBOMs.
        self.assertIn("release:", workflow)
        self.assertIn("published", workflow)
        self.assertIn("format: spdx-json", workflow)
        self.assertIn("format: cyclonedx-json", workflow)
        self.assertIn("artifact-name: merovingian-sbom-spdx", workflow)
        self.assertIn("artifact-name: merovingian-sbom-cyclonedx", workflow)

    def test_sanitizer_workflow_runs_threadsanitizer_with_project_suppressions(self) -> None:
        # GIVEN the repository sanitizer workflow.
        self.assertTrue(SANITIZERS_WORKFLOW.is_file(), "sanitizers workflow is missing")
        workflow = SANITIZERS_WORKFLOW.read_text(encoding="utf-8")

        # WHEN concurrency regressions are checked in CI.
        # THEN the workflow keeps a dedicated ThreadSanitizer job wired to the
        # repository suppressions file instead of relying only on ASan/UBSan.
        self.assertIn("asan-ubsan:", workflow)
        self.assertIn("tsan:", workflow)
        self.assertIn("TSAN_OPTIONS: suppressions=${{ github.workspace }}/tests/sanitizer/tsan.supp", workflow)
        self.assertIn("sh scripts/build-linux.sh --builddir build-tsan --buildtype debug --sanitize thread", workflow)

    def test_release_readiness_requires_security_workflow_assets(self) -> None:
        # GIVEN the release-readiness script.
        self.assertTrue(RELEASE_READINESS_SCRIPT.is_file(), "release readiness script is missing")
        script = RELEASE_READINESS_SCRIPT.read_text(encoding="utf-8")

        # WHEN alpha release metadata is checked.
        # THEN the secret-scan, dependency-triage, SBOM, and their configs must exist.
        self.assertIn(".github/workflows/secret-scan.yml", script)
        self.assertIn(".github/workflows/dependency-vulnerability-triage.yml", script)
        self.assertIn(".github/workflows/sbom.yml", script)
        self.assertIn(".gitleaks.toml", script)
        self.assertIn(".github/dependency-review-config.yml", script)

    def test_admin_bootstrap_is_an_explicit_operator_startup_path(self) -> None:
        # GIVEN public registration must not implicitly create admin users.
        self.assertTrue(SERVER_MAIN.is_file(), "server main is missing")
        self.assertTrue(SMOKE_TESTS.is_file(), "smoke tests are missing")
        server_main = SERVER_MAIN.read_text(encoding="utf-8")
        smoke_tests = SMOKE_TESTS.read_text(encoding="utf-8")

        # WHEN an operator needs to provision the first administrator.
        # THEN the server exposes an explicit startup flag pair wired to the
        # reviewed bootstrap_admin_user path and covered by help smoke tests.
        self.assertIn("--bootstrap-admin", server_main)
        self.assertIn("--bootstrap-admin-password-file", server_main)
        self.assertIn("bootstrap_admin_user(runtime_result.runtime", server_main)
        self.assertIn("server-admin-bootstrap-help-smoke-test", smoke_tests)


class SarifArtifactLocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(SARIF_LOCATION_SCRIPT.is_file(), "SARIF location script is missing")
        self.module = load_sarif_location_module()

    def fill(self, sarif: dict[str, Any], sbom: dict[str, Any]) -> dict[str, Any]:
        filled, _ = self.module.fill_artifact_locations(sarif, sbom, SBOM_NAME)
        return filled

    def test_sbom_finding_is_located_at_the_manifest_that_declares_the_package(self) -> None:
        # GIVEN Grype's SARIF for an SBOM-sourced finding with an empty URI,
        # as uploaded by run 37116890711 for GHSA-xvg9-69gf-fjrf.
        sarif = grype_sarif(
            ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
        )

        # WHEN its artifact locations are filled from the SBOM.
        result = self.fill(sarif, spdx_sbom())["runs"][0]["results"][0]

        # THEN the result points at the manifest the SBOM says declares the
        # package, and the message names it instead of ending in "found at: ".
        self.assertEqual(first_location(result)["uri"], "requirements-docs.txt")
        self.assertTrue(result["message"]["text"].endswith("was found at: requirements-docs.txt"))

    def test_package_declared_by_several_manifests_is_located_deterministically(self) -> None:
        # GIVEN a finding for an action that two workflows use.
        sarif = grype_sarif(("GHSA-aaaa-checkout", "actions/checkout", "pkg:github/actions/checkout@v4"))

        # WHEN its artifact locations are filled twice.
        first = self.fill(sarif, spdx_sbom())["runs"][0]["results"][0]
        second = self.fill(sarif, spdx_sbom())["runs"][0]["results"][0]

        # THEN the primary location is the same manifest each time, so the
        # code-scanning alert keeps its identity across runs, and every other
        # manifest is kept as a related location.
        self.assertEqual(first_location(first)["uri"], ".github/workflows/ci.yml")
        self.assertEqual(first, second)
        related = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in first["relatedLocations"]]
        self.assertEqual(related, [".github/workflows/pages.yml"])

    def test_package_without_a_manifest_falls_back_to_the_sbom(self) -> None:
        # GIVEN a finding for a package the SBOM links to no manifest file.
        sarif = grype_sarif(("GHSA-bbbb-orphan", "orphan", "pkg:generic/orphan@1.0"))

        # WHEN its artifact locations are filled.
        result = self.fill(sarif, spdx_sbom())["runs"][0]["results"][0]

        # THEN it is still given a non-empty location: the scanned SBOM.
        self.assertEqual(first_location(result)["uri"], SBOM_NAME)

    def test_unsafe_manifest_names_are_never_used_as_locations(self) -> None:
        # GIVEN an SBOM whose manifest file names escape the repository or are URLs.
        for unsafe in ("../outside.txt", "/etc/passwd", "https://example.org/x", "dir\\..\\x", ""):
            with self.subTest(file_name=unsafe):
                sbom = spdx_sbom()
                sbom["files"][0]["fileName"] = unsafe
                sarif = grype_sarif(
                    ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
                )

                # WHEN its artifact locations are filled.
                result = self.fill(sarif, sbom)["runs"][0]["results"][0]

                # THEN the unsafe name is rejected in favour of the SBOM fallback.
                self.assertEqual(first_location(result)["uri"], SBOM_NAME)

    def test_leading_dot_slash_in_sbom_file_names_is_normalised(self) -> None:
        # GIVEN an SBOM that writes a manifest name with a "./" prefix.
        sbom = spdx_sbom()
        sbom["files"][0]["fileName"] = "./requirements-docs.txt"
        sarif = grype_sarif(
            ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
        )

        # WHEN its artifact locations are filled.
        result = self.fill(sarif, sbom)["runs"][0]["results"][0]

        # THEN the location is the repository-relative path.
        self.assertEqual(first_location(result)["uri"], "requirements-docs.txt")

    def test_results_that_already_have_a_location_are_left_alone(self) -> None:
        # GIVEN a finding that already carries a real file location.
        sarif = grype_sarif(
            ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
        )
        first_location(sarif["runs"][0]["results"][0])["uri"] = "docs/requirements.txt"
        original = copy.deepcopy(sarif)

        # WHEN its artifact locations are filled.
        filled, changed = self.module.fill_artifact_locations(sarif, spdx_sbom(), SBOM_NAME)

        # THEN nothing changes and nothing is reported as filled.
        self.assertEqual(filled, original)
        self.assertEqual(changed, [])

    def test_results_without_any_location_are_given_one(self) -> None:
        # GIVEN a finding with no locations array at all.
        sarif = grype_sarif(
            ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
        )
        del sarif["runs"][0]["results"][0]["locations"]

        # WHEN its artifact locations are filled.
        result = self.fill(sarif, spdx_sbom())["runs"][0]["results"][0]

        # THEN it gains a location that code scanning can process.
        self.assertEqual(first_location(result)["uri"], "requirements-docs.txt")

    def test_no_result_is_left_without_an_artifact_location(self) -> None:
        # GIVEN a scan with located, unlocated and orphaned findings together.
        sarif = grype_sarif(
            ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20"),
            ("GHSA-aaaa-checkout", "actions/checkout", "pkg:github/actions/checkout@v4"),
            ("GHSA-bbbb-orphan", "orphan", "pkg:generic/orphan@1.0"),
            ("GHSA-cccc-unknown-rule", "unknown", "pkg:generic/unknown@1.0"),
        )
        sarif["runs"][0]["results"][3]["ruleId"] = "rule-not-in-the-driver"

        # WHEN its artifact locations are filled.
        filled = self.fill(sarif, spdx_sbom())

        # THEN every location of every result has a non-empty URI, which is the
        # condition code scanning's locationFromSarifResult enforces.
        for result in filled["runs"][0]["results"]:
            for location in result["locations"]:
                self.assertNotEqual(location["physicalLocation"]["artifactLocation"]["uri"], "")

    def test_command_line_writes_a_filled_copy_and_keeps_the_raw_scan(self) -> None:
        # GIVEN raw Grype SARIF and the SBOM it scanned, on disk.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            raw = directory / "dependency-triage.sarif"
            sbom = directory / SBOM_NAME
            output = directory / "dependency-triage.code-scanning.sarif"
            raw_text = json.dumps(
                grype_sarif(
                    ("GHSA-xvg9-69gf-fjrf-mkdocs-material", "mkdocs-material", "pkg:pypi/mkdocs-material@9.6.20")
                )
            )
            raw.write_text(raw_text, encoding="utf-8")
            sbom.write_text(json.dumps(spdx_sbom()), encoding="utf-8")

            # WHEN the script is run as the workflow runs it.
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SARIF_LOCATION_SCRIPT),
                    "--sarif",
                    str(raw),
                    "--sbom",
                    str(sbom),
                    "--output",
                    str(output),
                    "--fallback-uri",
                    SBOM_NAME,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            # THEN it succeeds, reports what it filled, writes the located copy,
            # and leaves the raw scan output untouched for the audit artifact.
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("GHSA-xvg9-69gf-fjrf-mkdocs-material -> requirements-docs.txt", completed.stdout)
            located = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(first_location(located["runs"][0]["results"][0])["uri"], "requirements-docs.txt")
            self.assertEqual(raw.read_text(encoding="utf-8"), raw_text)

    def test_command_line_rejects_input_that_is_not_sarif(self) -> None:
        # GIVEN a scan output that is not a SARIF log.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            raw = directory / "dependency-triage.sarif"
            sbom = directory / SBOM_NAME
            output = directory / "out.sarif"
            raw.write_text(json.dumps({"matches": []}), encoding="utf-8")
            sbom.write_text(json.dumps(spdx_sbom()), encoding="utf-8")

            # WHEN the script is run on it.
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SARIF_LOCATION_SCRIPT),
                    "--sarif",
                    str(raw),
                    "--sbom",
                    str(sbom),
                    "--output",
                    str(output),
                    "--fallback-uri",
                    SBOM_NAME,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            # THEN it fails closed and writes nothing for code scanning.
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
