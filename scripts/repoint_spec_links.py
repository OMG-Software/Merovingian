#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Replaces spec.matrix.org/v1.18 URLs in docs and source comments with
# relative paths to the local copy in docs/matrix-v1.18-spec/.
#
# Run from project root:  python3 scripts/repoint_spec_links.py

import os
import re
import sys

# ---------------------------------------------------------------------------
# URL → local file mapping (relative to docs/matrix-v1.18-spec/)
# ---------------------------------------------------------------------------
# Ordered longest-prefix-first for unambiguous matching.
URL_PATH_MAP = [
    ("client-server-api/",       "client-server-api.md"),
    ("server-server-api/",       "server-server-api.md"),
    ("application-service-api/", "application-service-api.md"),
    ("identity-service-api/",    "identity-service-api.md"),
    ("push-gateway-api/",        "push-gateway-api.md"),
    ("rooms/v12/",               "rooms/v12.md"),
    ("rooms/v11/",               "rooms/v11.md"),
    ("rooms/v10/",               "rooms/v10.md"),
    ("rooms/v9/",                "rooms/v9.md"),
    ("rooms/v8/",                "rooms/v8.md"),
    ("rooms/v7/",                "rooms/v7.md"),
    ("rooms/v6/",                "rooms/v6.md"),
    ("rooms/v5/",                "rooms/v5.md"),
    ("rooms/v4/",                "rooms/v4.md"),
    ("rooms/v3/",                "rooms/v3.md"),
    ("rooms/v2/",                "rooms/v2.md"),
    ("rooms/v1/",                "rooms/v1.md"),
    ("rooms/",                   "rooms/index.md"),
    ("appendices/",              "appendices.md"),
    ("",                         "index.md"),          # bare base URL
]

SPEC_BASE = "https://spec.matrix.org/v1.18/"
LOCAL_SPEC_DIR = "docs/matrix-v1.18-spec"   # relative to project root

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def url_to_local_abs(url: str):
    """Return (abs_local_path, anchor) for a spec URL, or None if no match."""
    if not url.startswith(SPEC_BASE):
        return None, None
    rest = url[len(SPEC_BASE):]
    anchor = ""
    if "#" in rest:
        rest, anchor = rest.split("#", 1)
    for prefix, local_name in URL_PATH_MAP:
        if rest.startswith(prefix) or (prefix == "" and rest == ""):
            abs_path = os.path.join(PROJECT_ROOT, LOCAL_SPEC_DIR, local_name)
            return abs_path, anchor
    return None, None


def local_rel_path(source_file: str, abs_local: str, anchor: str) -> str:
    """Compute relative path from source_file's directory to abs_local."""
    source_dir = os.path.dirname(os.path.abspath(source_file))
    rel = os.path.relpath(abs_local, source_dir).replace("\\", "/")
    return (rel + "#" + anchor) if anchor else rel


def rewrite_url(url: str, source_file: str) -> str:
    """Return the replacement string for a spec URL, or the original if unknown."""
    abs_local, anchor = url_to_local_abs(url)
    if abs_local is None:
        return url
    return local_rel_path(source_file, abs_local, anchor)


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------
# Matches:
#   [some text](https://spec.matrix.org/v1.18/...)  — markdown link
#   https://spec.matrix.org/v1.18/...               — bare URL (not inside a link)
#
# The regex captures the optional [text]( ... ) wrapper so we can preserve
# the link text while replacing only the URL part.

SPEC_URL_RE = re.compile(
    r"(\[([^\]]*)\]\()"            # group 1: [text]( prefix; group 2: link text
    r"(https://spec\.matrix\.org/v1\.18/[^\s)\">]*)"  # group 3: URL
    r"(\))"                        # group 4: closing )
    r"|"
    r"(https://spec\.matrix\.org/v1\.18/[^\s\)\">\']*)"  # group 5: bare URL
)


def rewrite_content(text: str, source_file: str) -> str:
    def replacer(m):
        if m.group(1):
            # Markdown link: [text](url)
            link_text = m.group(2)
            url = m.group(3)
            new_url = rewrite_url(url, source_file)
            return f"[{link_text}]({new_url})"
        else:
            # Bare URL
            url = m.group(5)
            return rewrite_url(url, source_file)

    return SPEC_URL_RE.sub(replacer, text)


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------
EXCLUDE_PREFIXES = [
    os.path.join(PROJECT_ROOT, "docs", "matrix-v1.18-spec"),
    os.path.join(PROJECT_ROOT, ".claude"),
    os.path.join(PROJECT_ROOT, "build"),
]
INCLUDE_EXTS = {".md", ".cpp", ".hpp"}


def is_included(path: str) -> bool:
    for exc in EXCLUDE_PREFIXES:
        if path.startswith(exc + os.sep) or path == exc:
            return False
    # also exclude build-* dirs
    rel = os.path.relpath(path, PROJECT_ROOT)
    parts = rel.replace("\\", "/").split("/")
    if parts[0].startswith("build"):
        return False
    return True


def scan_files():
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # prune excluded dirs in-place
        dirs[:] = [
            d for d in dirs
            if is_included(os.path.join(root, d))
            and not d.startswith(".")
            and not d.startswith("build")
        ]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in INCLUDE_EXTS:
                continue
            full = os.path.join(root, fname)
            if is_included(full):
                yield full


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    changed = []
    skipped = 0

    for path in sorted(scan_files()):
        with open(path, encoding="utf-8", errors="replace") as f:
            original = f.read()

        if "spec.matrix.org/v1.18" not in original:
            continue

        rewritten = rewrite_content(original, path)
        if rewritten == original:
            skipped += 1
            continue

        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(rewritten)

        rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
        changed.append(rel)
        print(f"  updated  {rel}")

    print(f"\n{len(changed)} file(s) updated, {skipped} unchanged.")
    return 0 if changed or skipped >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
