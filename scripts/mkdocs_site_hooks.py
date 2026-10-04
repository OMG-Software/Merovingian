#!/usr/bin/env python3
"""MkDocs hooks for the Merovingian documentation site.

The documents under docs/ are written to be read in the repository, so they
link freely to source files, workflows, module AGENTS.md files and the vendored
Matrix spec mirror, none of which the site publishes. These hooks:

- rewrite each link to a file outside the published site so it opens on GitHub
  at the commit the site was built from, and each link into the spec mirror so
  it opens the same section of https://spec.matrix.org/v1.19/;
- publish the repository CHANGELOG.md as the changelog page;
- stamp the footer with the project version and commit the site was built from.

A link whose target exists nowhere in the repository is left untouched, so the
strict build still reports it as broken.
"""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parents[1]
CHANGELOG_PAGE = "changelog.md"
SPEC_MIRROR = "docs/matrix-v1.19-spec/"
SPEC_BASE = "https://spec.matrix.org/v1.19/"

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"(`+)(?:.+?)\1")
_INLINE_TARGET = re.compile(r"(\]\(\s*)(<[^>]+>|[^)\s]+)")
_REFERENCE_TARGET = re.compile(r"^( {0,3}\[[^\]]+\]:\s*)(<[^>]+>|\S+)")
_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_PROJECT_VERSION = re.compile(r"project\(.*?\bversion:\s*'([^']+)'", re.DOTALL)


def project_version(meson_build: str) -> str:
    """Return the version declared in the project() call of meson.build."""
    match = _PROJECT_VERSION.search(meson_build)
    if match is None:
        raise ValueError("meson.build declares no project version")
    return match.group(1)


def _spec_url(mirror_path: str, anchor: str) -> str:
    # Inverse of scripts/repoint_spec_links.py: "rooms/v12.md" -> "rooms/v12/",
    # "rooms/index.md" -> "rooms/", "index.md" -> "".
    page = mirror_path.removesuffix(".md")
    if page == "index" or page.endswith("/index"):
        page = page.removesuffix("index")
    else:
        page += "/"
    return SPEC_BASE + page + anchor


def _rewrite_target(
    target: str,
    *,
    origin_dir: str,
    page_dir: str,
    published: set[str],
    repo_root: Path,
    repo_url: str,
    ref: str,
) -> str:
    bracketed = target.startswith("<") and target.endswith(">")
    raw = target[1:-1] if bracketed else target
    if not raw or raw.startswith(("#", "/")) or _URL_SCHEME.match(raw):
        return target

    path, hash_mark, fragment = raw.partition("#")
    anchor = hash_mark + fragment
    repo_path = posixpath.normpath(posixpath.join(origin_dir, unquote(path)))
    if repo_path == ".." or repo_path.startswith("../"):
        return target

    if repo_path.startswith("docs/"):
        docs_path = repo_path.removeprefix("docs/")
        if docs_path in published:
            if origin_dir == "docs" or origin_dir.startswith("docs/"):
                return target
            relative = posixpath.relpath(docs_path, page_dir or ".")
            return f"<{relative}{anchor}>" if bracketed else relative + anchor

    if repo_path.startswith(SPEC_MIRROR) and repo_path.endswith(".md"):
        if (repo_root / repo_path).is_file():
            url = _spec_url(repo_path.removeprefix(SPEC_MIRROR), anchor)
            return f"<{url}>" if bracketed else url

    location = repo_root / repo_path
    if location.is_file():
        url = f"{repo_url}/blob/{ref}/{repo_path}{anchor}"
    elif location.is_dir():
        url = f"{repo_url}/tree/{ref}/{repo_path}{anchor}"
    else:
        return target
    return f"<{url}>" if bracketed else url


def rewrite_links(
    markdown: str,
    *,
    origin_dir: str,
    page_dir: str,
    published: set[str],
    repo_root: Path,
    repo_url: str,
    ref: str,
) -> str:
    """Rewrite relative link targets that the site does not publish.

    origin_dir is the repository directory the links were written relative to,
    page_dir the docs/-relative directory the page is published from, and
    published the docs/-relative paths of every page the site contains.
    Fenced code blocks and inline code spans are reproduced unchanged.
    """

    def replace(match: re.Match[str]) -> str:
        rewritten = _rewrite_target(
            match.group(2),
            origin_dir=origin_dir,
            page_dir=page_dir,
            published=published,
            repo_root=repo_root,
            repo_url=repo_url,
            ref=ref,
        )
        return match.group(1) + rewritten

    def rewrite_prose(line: str) -> str:
        pieces = []
        position = 0
        for span in _CODE_SPAN.finditer(line):
            pieces.append(_INLINE_TARGET.sub(replace, line[position : span.start()]))
            pieces.append(span.group(0))
            position = span.end()
        pieces.append(_INLINE_TARGET.sub(replace, line[position:]))
        return _REFERENCE_TARGET.sub(replace, "".join(pieces))

    output = []
    fence = ""
    for line in markdown.splitlines(keepends=True):
        opening = _FENCE.match(line)
        if fence:
            if opening and opening.group(1)[0] == fence[0] and len(opening.group(1)) >= len(fence):
                fence = ""
            output.append(line)
        elif opening:
            fence = opening.group(1)
            output.append(line)
        else:
            output.append(rewrite_prose(line))
    return "".join(output)


# --- MkDocs event handlers ---------------------------------------------------


def _build_ref() -> str:
    return os.environ.get("GITHUB_SHA") or "main"


def on_config(config):
    version = project_version((REPO_ROOT / "meson.build").read_text(encoding="utf-8"))
    commit = os.environ.get("GITHUB_SHA", "")
    built_from = f"Merovingian {version}"
    if commit:
        built_from += f" at {commit[:12]}"
    config.copyright = f"{config.copyright}<br>Documentation for {built_from}"
    return config


def on_files(files, config):
    from mkdocs.structure.files import File

    changelog = File.generated(
        config, CHANGELOG_PAGE, abs_src_path=str(REPO_ROOT / "CHANGELOG.md")
    )
    changelog.edit_uri = "../CHANGELOG.md"
    files.append(changelog)
    return files


def on_page_markdown(markdown, page, config, files):
    src_uri = page.file.src_uri
    page_dir = posixpath.dirname(src_uri)
    if src_uri == CHANGELOG_PAGE:
        origin_dir = ""
    else:
        origin_dir = posixpath.join("docs", page_dir) if page_dir else "docs"
    published = {file.src_uri for file in files.documentation_pages()}
    return rewrite_links(
        markdown,
        origin_dir=origin_dir,
        page_dir=page_dir,
        published=published,
        repo_root=REPO_ROOT,
        repo_url=config.repo_url.rstrip("/"),
        ref=_build_ref(),
    )
