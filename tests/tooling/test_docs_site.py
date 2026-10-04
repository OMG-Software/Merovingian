#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = REPO_ROOT / "docs"
PAGES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pages.yml"
MKDOCS_CONFIG = REPO_ROOT / "mkdocs.yml"
DOCS_REQUIREMENTS = REPO_ROOT / "requirements-docs.txt"
DOCS_REQUIREMENTS_INPUT = REPO_ROOT / "requirements-docs.in"
SITE_HOOKS = REPO_ROOT / "scripts" / "mkdocs_site_hooks.py"

# The first mkdocs-material release with the fix for GHSA-xvg9-69gf-fjrf
# (DOM XSS in search suggestions via a query parameter).
FIRST_SAFE_MATERIAL_VERSION = (9, 7, 7)

# Architecture Decision Records are reached from the ADR index rather than
# listed one by one in the navigation.
ADR_RECORD = re.compile(r"^adr/\d{4}-.+\.md$")


def load_site_hooks():
    spec = importlib.util.spec_from_file_location("mkdocs_site_hooks", SITE_HOOKS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def exclude_patterns(config: str) -> list[str]:
    match = re.search(r"^exclude_docs: \|\n((?:  .*\n)+)", config, re.MULTILINE)
    assert match is not None, "mkdocs.yml has no exclude_docs block"
    return [line.strip() for line in match.group(1).splitlines() if line.strip()]


def is_excluded(relative_path: str, patterns: list[str]) -> bool:
    # A minimal reading of the gitignore syntax MkDocs uses for exclude_docs:
    # a leading slash anchors the pattern to docs/, a trailing slash names a
    # directory, and anything else matches a file name at any depth.
    for pattern in patterns:
        if pattern.startswith("/"):
            anchored = pattern[1:]
            if anchored.endswith("/"):
                if relative_path.startswith(anchored):
                    return True
            elif fnmatch.fnmatchcase(relative_path, anchored):
                return True
        elif fnmatch.fnmatchcase(Path(relative_path).name, pattern):
            return True
    return False


def nav_targets(config: str) -> list[str]:
    nav = config.split("\nnav:\n", 1)[1].split("\n\n", 1)[0]
    return re.findall(r"(?:^\s*-\s+|:\s+)([\w./-]+\.md)\s*$", nav, re.MULTILINE)


class PagesWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(PAGES_WORKFLOW.is_file(), "pages workflow is missing")
        self.workflow = PAGES_WORKFLOW.read_text(encoding="utf-8")

    def test_site_builds_strictly_on_every_branch_and_pull_request(self) -> None:
        # GIVEN the documentation site workflow.
        # WHEN any branch is pushed or any pull request is opened.
        triggers = self.workflow.split("\npermissions:", 1)[0]

        # THEN the site is built with broken links and warnings treated as
        # failures, with no path filter that would let a branch skip it.
        self.assertRegex(triggers, r"push:\n\s+branches:\n\s+- \"\*\*\"")
        self.assertIn("pull_request:", triggers)
        self.assertNotIn("paths:", triggers)
        self.assertIn("mkdocs build --strict", self.workflow)

    def test_every_build_uploads_the_rendered_site_for_review(self) -> None:
        # GIVEN the documentation site workflow.
        # WHEN a branch that is not main builds the site.
        # THEN the rendered site is kept as a downloadable artifact.
        self.assertIn("actions/upload-artifact@v4", self.workflow)
        self.assertRegex(self.workflow, r"name: docs-site\n\s+path: site/")

    def test_only_main_deploys_to_github_pages(self) -> None:
        # GIVEN the documentation site workflow.
        build, deploy = self.workflow.split("\n  deploy:\n", 1)

        # WHEN the deploy job is considered.
        # THEN it runs only for a push or manual run on main, and is the only
        # job holding the Pages and OIDC token permissions.
        self.assertIn("github.ref == 'refs/heads/main'", deploy)
        self.assertIn("github.event_name != 'pull_request'", deploy)
        self.assertIn("actions/deploy-pages@v4", deploy)
        self.assertIn("pages: write", deploy)
        self.assertIn("id-token: write", deploy)
        self.assertNotIn("pages: write", build)
        self.assertNotIn("id-token: write", build)

    def test_dependencies_are_installed_against_hashes(self) -> None:
        # GIVEN the documentation site workflow.
        # WHEN it installs MkDocs.
        # THEN pip refuses any package whose hash is not in the lock file.
        self.assertIn("--require-hashes", self.workflow)
        self.assertIn("requirements-docs.txt", self.workflow)


class DocumentationDependencyTests(unittest.TestCase):
    def test_every_locked_requirement_is_pinned_with_a_hash(self) -> None:
        # GIVEN the documentation dependency lock file.
        self.assertTrue(DOCS_REQUIREMENTS.is_file(), "requirements-docs.txt is missing")
        self.assertTrue(DOCS_REQUIREMENTS_INPUT.is_file(), "requirements-docs.in is missing")
        lock = DOCS_REQUIREMENTS.read_text(encoding="utf-8")

        # WHEN each requirement is read.
        requirements = re.findall(r"^([A-Za-z0-9_.-]+)(\S*)", lock, re.MULTILINE)

        # THEN every one, direct or transitive, is an exact pin with a hash.
        self.assertGreater(len(requirements), 2)
        for name, specifier in requirements:
            with self.subTest(requirement=name):
                self.assertRegex(specifier, r"^==\S+$")
                self.assertRegex(
                    lock,
                    rf"(?m)^{re.escape(name)}{re.escape(specifier)}.*\\\n(?:\s+--hash=sha256:[0-9a-f]{{64}}.*\n)+",
                )

    def test_material_theme_is_not_a_version_with_the_search_xss(self) -> None:
        # GIVEN the documentation dependency lock file.
        lock = DOCS_REQUIREMENTS.read_text(encoding="utf-8")

        # WHEN the pinned mkdocs-material version is read.
        match = re.search(r"^mkdocs-material==(\d+)\.(\d+)\.(\d+)", lock, re.MULTILINE)
        self.assertIsNotNone(match, "mkdocs-material is not pinned")
        assert match is not None
        version = tuple(int(part) for part in match.groups())

        # THEN it includes the fix for GHSA-xvg9-69gf-fjrf.
        self.assertGreaterEqual(version, FIRST_SAFE_MATERIAL_VERSION)


class SiteNavigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = MKDOCS_CONFIG.read_text(encoding="utf-8")
        self.patterns = exclude_patterns(self.config)

    def test_agent_instructions_and_vendored_spec_are_not_published(self) -> None:
        # GIVEN the site configuration.
        # WHEN docs/ is collected for the site.
        # THEN agent instruction files and the vendored Matrix spec mirror are
        # left out, while project documentation is kept.
        for path in (
            "AGENTS.md",
            "CLAUDE.md",
            "matrix-v1.19-spec/client-server-api.md",
            "matrix-v1.18-spec/index.md",
            "adr/template.md",
        ):
            with self.subTest(path=path):
                self.assertTrue(is_excluded(path, self.patterns))
        for path in ("index.md", "architecture.md", "adr/index.md", "dependencies/sqlite.md"):
            with self.subTest(path=path):
                self.assertFalse(is_excluded(path, self.patterns))

    def test_every_published_document_is_reachable_from_the_navigation(self) -> None:
        # GIVEN every Markdown document under docs/ that the site publishes.
        published = sorted(
            path.relative_to(DOCS_DIR).as_posix()
            for path in DOCS_DIR.rglob("*.md")
            if not is_excluded(path.relative_to(DOCS_DIR).as_posix(), self.patterns)
        )

        # WHEN the navigation is read.
        navigation = set(nav_targets(self.config))

        # THEN each document has a navigation entry, except ADR records, which
        # the ADR index links to.
        missing = [
            path for path in published if path not in navigation and not ADR_RECORD.match(path)
        ]
        self.assertEqual(missing, [], "add these documents to the nav in mkdocs.yml")

    def test_every_navigation_entry_names_a_published_document(self) -> None:
        # GIVEN the navigation in the site configuration.
        # WHEN each entry is resolved.
        # THEN it names a document that exists and is not excluded, or the
        # changelog page the site hooks generate from CHANGELOG.md.
        for target in nav_targets(self.config):
            with self.subTest(target=target):
                if target == "changelog.md":
                    self.assertTrue((REPO_ROOT / "CHANGELOG.md").is_file())
                    self.assertFalse((DOCS_DIR / target).exists())
                    continue
                self.assertTrue((DOCS_DIR / target).is_file())
                self.assertFalse(is_excluded(target, self.patterns))

    def test_site_hooks_are_registered(self) -> None:
        # GIVEN the site configuration.
        # WHEN MkDocs loads it.
        # THEN the project hooks run, and links are validated as warnings so
        # the strict build fails on them.
        self.assertIn("scripts/mkdocs_site_hooks.py", self.config)
        self.assertRegex(self.config, r"validation:\n(?:\s+.*\n)*?\s+not_found: warn")


class SiteHookLinkTests(unittest.TestCase):
    REPO_URL = "https://github.com/OMG-Software/Merovingian"

    @classmethod
    def setUpClass(cls) -> None:
        cls.hooks = load_site_hooks()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        for path in (
            "include/merovingian/core/error.hpp",
            "src/sync/AGENTS.md",
            "docs/architecture.md",
            "docs/adr/0001-example.md",
            "docs/matrix-v1.19-spec/server-server-api.md",
            "docs/matrix-v1.19-spec/rooms/index.md",
        ):
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_text("x\n", encoding="utf-8")
        self.published = {"architecture.md", "adr/0001-example.md", "changelog.md"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def rewrite(self, markdown: str, *, origin_dir: str, page_dir: str) -> str:
        return self.hooks.rewrite_links(
            markdown,
            origin_dir=origin_dir,
            page_dir=page_dir,
            published=self.published,
            repo_root=self.repo,
            repo_url=self.REPO_URL,
            ref="abc123",
        )

    def test_link_to_source_outside_docs_points_at_the_repository(self) -> None:
        # GIVEN a document in docs/adr linking to a header outside docs/.
        markdown = "See [error](../../include/merovingian/core/error.hpp#L10)."

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs/adr", page_dir="adr")

        # THEN the link opens that file on GitHub at the built commit.
        self.assertEqual(
            rewritten,
            f"See [error]({self.REPO_URL}/blob/abc123/include/merovingian/core/error.hpp#L10).",
        )

    def test_link_to_a_directory_outside_docs_opens_the_tree_view(self) -> None:
        # GIVEN a document linking to a directory outside docs/.
        markdown = "[sync](../src/sync/)"

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN the link opens the directory listing on GitHub.
        self.assertEqual(rewritten, f"[sync]({self.REPO_URL}/tree/abc123/src/sync)")

    def test_link_to_a_published_document_is_left_for_mkdocs(self) -> None:
        # GIVEN a document linking to another published document.
        markdown = "[ADR](adr/0001-example.md#context) and [arch](architecture.md)"

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN the links are unchanged, so MkDocs resolves and validates them.
        self.assertEqual(rewritten, markdown)

    def test_repository_root_links_resolve_to_site_pages(self) -> None:
        # GIVEN changelog text, whose links are relative to the repository root.
        markdown = "[ADR](docs/adr/0001-example.md) and [src](src/sync/AGENTS.md)"

        # WHEN it is rewritten for the changelog page at the site root.
        rewritten = self.rewrite(markdown, origin_dir="", page_dir="")

        # THEN documentation links become site links and the rest go to GitHub.
        self.assertEqual(
            rewritten,
            f"[ADR](adr/0001-example.md) and [src]({self.REPO_URL}/blob/abc123/src/sync/AGENTS.md)",
        )

    def test_link_into_the_spec_mirror_points_at_the_published_spec(self) -> None:
        # GIVEN a document linking into the vendored Matrix spec mirror.
        markdown = (
            "[auth](../matrix-v1.19-spec/server-server-api.md#authorisation-rules) "
            "[rooms](../matrix-v1.19-spec/rooms/index.md)"
        )

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs/adr", page_dir="adr")

        # THEN they open the same section of the official v1.19 specification.
        self.assertEqual(
            rewritten,
            "[auth](https://spec.matrix.org/v1.19/server-server-api/#authorisation-rules) "
            "[rooms](https://spec.matrix.org/v1.19/rooms/)",
        )

    def test_link_to_a_missing_file_is_left_for_the_strict_build_to_reject(self) -> None:
        # GIVEN a document linking to a file that exists nowhere in the repository.
        markdown = "[gone](../src/missing.cpp) [gone doc](missing.md)"

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN the link is unchanged, so the strict build reports it as broken.
        self.assertEqual(rewritten, markdown)

    def test_links_inside_code_are_left_alone(self) -> None:
        # GIVEN links that appear inside a fenced block and an inline code span.
        markdown = (
            "```markdown\n[x](../src/sync/AGENTS.md)\n```\n"
            "Write `[x](../src/sync/AGENTS.md)` literally.\n"
        )

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN code is reproduced exactly.
        self.assertEqual(rewritten, markdown)

    def test_external_and_fragment_links_are_left_alone(self) -> None:
        # GIVEN absolute URLs, mail links, and in-page anchors.
        markdown = "[a](https://example.org/x.md) [b](mailto:x@example.org) [c](#section)"

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN they are unchanged.
        self.assertEqual(rewritten, markdown)

    def test_reference_definitions_are_rewritten(self) -> None:
        # GIVEN a reference-style link definition pointing outside docs/.
        markdown = "[sync agents]: ../src/sync/AGENTS.md\n"

        # WHEN its links are rewritten.
        rewritten = self.rewrite(markdown, origin_dir="docs", page_dir="")

        # THEN the definition points at GitHub.
        self.assertEqual(
            rewritten, f"[sync agents]: {self.REPO_URL}/blob/abc123/src/sync/AGENTS.md\n"
        )


class SiteHookVersionTests(unittest.TestCase):
    def test_project_version_is_read_from_the_meson_project_call(self) -> None:
        # GIVEN the hooks and the repository's meson.build.
        hooks = load_site_hooks()
        meson_build = (REPO_ROOT / "meson.build").read_text(encoding="utf-8")
        expected = re.search(r"version: '([0-9]+\.[0-9]+\.[0-9]+)'", meson_build)
        assert expected is not None

        # WHEN the project version is read.
        version = hooks.project_version(meson_build)

        # THEN it is the version declared in project(), so every built site says
        # which release its documentation describes.
        self.assertEqual(version, expected.group(1))


if __name__ == "__main__":
    unittest.main()
