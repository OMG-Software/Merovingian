#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


FORMATTED_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}
PATCH_PREFIXES = (
    "*** Add File: ",
    "*** Update File: ",
)


def candidate_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]

    if isinstance(value, dict):
        values: list[str] = []
        for child in value.values():
            values.extend(candidate_strings(child))
        return values

    if isinstance(value, list):
        values: list[str] = []
        for child in value:
            values.extend(candidate_strings(child))
        return values

    return []


def extract_paths(payload: dict[str, Any]) -> set[Path]:
    paths: set[Path] = set()

    def maybe_add(raw: str) -> None:
        path = raw.strip().strip('"')
        if Path(path).suffix in FORMATTED_SUFFIXES:
            paths.add(Path(path))

    for raw in candidate_strings(payload):
        maybe_add(raw)

        for line in raw.splitlines():
            stripped = line.strip()
            for prefix in PATCH_PREFIXES:
                if stripped.startswith(prefix):
                    maybe_add(stripped[len(prefix) :])

    return paths


def inside_repo(path: Path, repo_root: Path) -> bool:
    try:
        path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return False
    return True


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    repo_root = Path.cwd()
    paths = extract_paths(payload)

    for path in sorted(paths):
        target = path if path.is_absolute() else repo_root / path
        if not target.is_file() or not inside_repo(target, repo_root):
            continue

        subprocess.run(["clang-format", "-i", str(target)], check=False)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
