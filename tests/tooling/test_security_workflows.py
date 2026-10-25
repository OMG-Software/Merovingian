#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "secret-scan.yml"
DEPENDENCY_TRIAGE_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "dependency-vulnerability-triage.yml"
)
SBOM_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sbom.yml"
SANITIZERS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sanitizers.yml"
CODEQL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "codeql.yml"
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
DEPENDENCY_REVIEW_CONFIG = REPO_ROOT / ".github" / "dependency-review-config.yml"
RELEASE_READINESS_SCRIPT = REPO_ROOT / "scripts" / "check-release-readiness.sh"
SERVER_MAIN = REPO_ROOT / "src" / "main.cpp"
SMOKE_TESTS = REPO_ROOT / "tests" / "smoke" / "meson.build"


def workflow_steps(workflow: str) -> list[dict[str, object]]:
    """Each step of every job: its top-level `key: value` pairs, plus a `with` dict.

    A deliberately small reader for this repository's workflows (no PyYAML on
    every CI image): steps are the `- ` items under a `steps:` key, comment
    lines are ignored, and values keep their text with surrounding quotes removed.
    """
    steps: list[dict[str, object]] = []
    steps_key_indent = None  # indentation of the `steps:` key being read, if any
    step_indent = None  # indentation of that key's `- ` items
    current: dict[str, object] | None = None
    in_with = False
    for raw in workflow.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()
        if text == "steps:":
            steps_key_indent, step_indent, current, in_with = indent, None, None, False
            continue
        if steps_key_indent is None:
            continue
        if indent <= steps_key_indent:
            # Left the steps list (a sibling of `steps:` or a parent key).
            steps_key_indent, step_indent, current, in_with = None, None, None, False
            continue
        if step_indent is None and text.startswith("- "):
            step_indent = indent
        if step_indent is None:
            continue
        if indent == step_indent and text.startswith("- "):
            current = {"with": {}}
            steps.append(current)
            text, indent, in_with = text[2:], indent + 2, False
        if current is None:
            continue
        key, separator, value = text.partition(":")
        if not separator:
            continue
        value = value.strip().strip("'\"")
        if indent == step_indent + 2:
            in_with = key == "with"
            if not in_with:
                current[key] = value
        elif in_with and indent == step_indent + 4:
            current["with"][key] = value  # type: ignore[index]
    return steps


def codeql_upload_problems(workflow: str) -> list[str]:
    """What is wrong with how codeql.yml analyses, filters and uploads (ADR-0226)."""
    steps = workflow_steps(workflow)

    def find(predicate) -> list[int]:
        return [index for index, step in enumerate(steps) if predicate(step)]

    analyze = find(lambda step: step.get("uses") == "github/codeql-action/analyze@v4")
    filtered = find(lambda step: step.get("run") == "python3 scripts/filter_codeql_sarif.py codeql-results")
    upload = find(lambda step: step.get("uses") == "github/codeql-action/upload-sarif@v4")
    problems = []
    for name, found in (("analyze", analyze), ("filter", filtered), ("upload", upload)):
        if len(found) != 1:
            problems.append(f"expected one {name} step, found {len(found)}")
    if problems:
        return problems
    analyze_with = steps[analyze[0]]["with"]
    upload_with = steps[upload[0]]["with"]
    if not analyze[0] < filtered[0] < upload[0]:
        problems.append("steps are not analyze, then filter, then upload")
    if analyze_with.get("upload") != "never":  # type: ignore[union-attr]
        problems.append("the analyze step uploads its own results")
    if analyze_with.get("output") != "codeql-results":  # type: ignore[union-attr]
        problems.append("the analyze step does not write codeql-results")
    if upload_with.get("sarif_file") != "codeql-results":  # type: ignore[union-attr]
        problems.append("the upload step does not upload codeql-results")
    if analyze_with.get("category") != "/language:c-cpp" or upload_with.get("category") != "/language:c-cpp":  # type: ignore[union-attr]
        problems.append("analyze and upload do not share the /language:c-cpp category")
    for index, step in enumerate(steps):
        if index != upload[0] and step.get("uses", "").startswith("github/codeql-action/upload-sarif"):  # type: ignore[union-attr]
            problems.append("another step uploads SARIF")
        if "query-filters" in step["with"] or "config" in step["with"]:  # type: ignore[operator]
            problems.append("a CodeQL step filters queries; the rule must stay on for production code")
    return problems


def move_step_after(workflow: str, moved: str, anchor: str) -> str:
    """`workflow` with the step named `moved` cut out and pasted after the step named `anchor`."""
    lines = workflow.splitlines(keepends=True)

    def span(name: str) -> tuple[int, int]:
        start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {name}")
        end = start + 1
        while end < len(lines) and not lines[end].lstrip().startswith("- name:") and not (
            lines[end].strip().startswith("#") and lines[end].startswith("      #")
        ):
            end += 1
        return start, end

    start, end = span(moved)
    block = lines[start:end]
    del lines[start:end]
    _, anchor_end = span(anchor)
    lines[anchor_end:anchor_end] = block
    return "".join(lines)


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

    def test_codeql_filters_catch2_false_positives_before_upload(self) -> None:
        # GIVEN the repository CodeQL workflow.
        self.assertTrue(CODEQL_WORKFLOW.is_file(), "codeql workflow is missing")
        workflow = CODEQL_WORKFLOW.read_text(encoding="utf-8")

        # WHEN its steps are read, each with its own `with:` values.
        problems = codeql_upload_problems(workflow)

        # THEN the analyze step writes SARIF without uploading it, the filter
        # (ADR-0226) rewrites it, and only then is it uploaded under the same category.
        self.assertEqual(problems, [])

    def test_codeql_upload_check_binds_each_value_to_its_step(self) -> None:
        # GIVEN workflows that keep every expected string but put one in the wrong
        # place: upload: never on another step or only in a comment, the categories
        # swapped onto other steps, or the filter after the upload.
        workflow = CODEQL_WORKFLOW.read_text(encoding="utf-8")
        never = "          upload: never\n"
        sarif = "          sarif_file: codeql-results\n"
        variants = {
            "upload: never moved to the upload step": workflow.replace(never, "", 1).replace(sarif, sarif + never, 1),
            "upload: never only in a comment": workflow.replace(never, "          # upload: never\n", 1),
            "upload category differs": workflow.replace(
                sarif + "          category: '/language:c-cpp'", sarif + "          category: '/language:other'", 1
            ),
            "filter after upload": move_step_after(workflow, "Filter Catch2 false positives", "Upload CodeQL results"),
        }

        for name, variant in variants.items():
            with self.subTest(variant=name):
                self.assertNotEqual(variant, workflow, "the variant did not change the workflow")

                # WHEN the check reads it.
                problems = codeql_upload_problems(variant)

                # THEN it reports the misplaced value.
                self.assertNotEqual(problems, [])

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
        self.assertTrue(
            re.search(r"\bbootstrap_admin_user\s*\(\s*runtime_result\.runtime\.homeserver\b", server_main),
            "operator bootstrap must call the reviewed admin creation path",
        )
        self.assertIn("server-admin-bootstrap-help-smoke-test", smoke_tests)


if __name__ == "__main__":
    unittest.main()
