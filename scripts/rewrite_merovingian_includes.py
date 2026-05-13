#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_PATHS = ("include", "src", "tests")
DEFAULT_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".ipp",
        ".tpp",
    }
)
SKIPPED_DIRECTORIES = frozenset(
    {
        ".clwb",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "subprojects",
        "venv",
    }
)
INCLUDE_PATTERN = re.compile(
    r"^(?P<prefix>[ \t]*#[ \t]*include[ \t]*)"
    r"<(?P<path>merovingian/[^>\r\n]+)>"
    r"(?P<suffix>[^\r\n]*)"
    r"(?P<newline>\r?\n?)$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class RewriteResult:
    path: Path
    replacements: int


def rewrite_include_text(text: str) -> tuple[str, int]:
    def replace_include(match: re.Match[str]) -> str:
        return (
            f'{match.group("prefix")}"{match.group("path")}"'
            f'{match.group("suffix")}{match.group("newline")}'
        )

    return INCLUDE_PATTERN.subn(replace_include, text)


def parse_extensions(raw_extensions: str) -> frozenset[str]:
    extensions = {
        extension.strip() if extension.strip().startswith(".") else f".{extension.strip()}"
        for extension in raw_extensions.split(",")
        if extension.strip()
    }
    if not extensions:
        raise argparse.ArgumentTypeError("at least one extension is required")
    return frozenset(extensions)


def is_skipped_directory(name: str) -> bool:
    return name in SKIPPED_DIRECTORIES or name == "build" or name.startswith("build-")


def has_skipped_directory(path: Path) -> bool:
    return any(is_skipped_directory(part) for part in path.parts)


def default_paths() -> list[Path]:
    return [Path(path) for path in DEFAULT_PATHS if Path(path).exists()]


def iter_source_files(paths: Iterable[Path], extensions: frozenset[str]) -> Iterable[Path]:
    for path in paths:
        if has_skipped_directory(path):
            continue

        if path.is_file():
            if path.suffix in extensions:
                yield path
            continue

        if not path.is_dir():
            print(f"warning: skipping missing path: {path}", file=sys.stderr)
            continue

        for root, directories, files in os.walk(path):
            directories[:] = sorted(
                directory for directory in directories if not is_skipped_directory(directory)
            )
            root_path = Path(root)
            for filename in sorted(files):
                source_path = root_path / filename
                if source_path.suffix in extensions and not has_skipped_directory(source_path):
                    yield source_path


def rewrite_file(path: Path, *, write: bool) -> RewriteResult:
    data = path.read_bytes()
    text = data.decode("utf-8")
    rewritten, replacements = rewrite_include_text(text)
    if write and replacements > 0:
        path.write_bytes(rewritten.encode("utf-8"))
    return RewriteResult(path=path, replacements=replacements)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            'Rewrite #include <merovingian/...> statements to '
            '#include "merovingian/..." quotes.'
        )
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Files or directories to scan. Defaults to include, src, and tests when present.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report files that need rewriting without modifying them. Exits 1 when changes are needed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print files that would change without modifying them.",
    )
    parser.add_argument(
        "--extensions",
        type=parse_extensions,
        default=DEFAULT_EXTENSIONS,
        help="Comma-separated source extensions to scan.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = args.paths if args.paths else default_paths()
    should_write = not args.check and not args.dry_run

    changed_files: list[RewriteResult] = []
    try:
        for source_path in iter_source_files(paths, args.extensions):
            result = rewrite_file(source_path, write=should_write)
            if result.replacements > 0:
                changed_files.append(result)
                action = "rewrote" if should_write else "would rewrite"
                print(f"{action} {result.path} ({result.replacements} include(s))")
    except UnicodeDecodeError as error:
        print(f"error: source file is not valid UTF-8: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.check and changed_files:
        print(f"{len(changed_files)} file(s) need include rewriting", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
