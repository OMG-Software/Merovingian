#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path


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

    def test_dependency_review_configuration_is_repository_local(self) -> None:
        # GIVEN the dependency-review action configuration.
        self.assertTrue(DEPENDENCY_REVIEW_CONFIG.is_file(), "dependency review config is missing")
        config = DEPENDENCY_REVIEW_CONFIG.read_text(encoding="utf-8")

        # WHEN pull requests add vulnerable dependencies.
        # THEN the repository fails on high-severity introductions and reports patched versions.
        self.assertIn("fail-on-severity: high", config)
        self.assertIn("license-check: false", config)
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


if __name__ == "__main__":
    unittest.main()
