#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def format_files(root: Path, dry_run: bool = False) -> int:
    extensions = {".h", ".hpp", ".cpp"}
    count = 0

    for path in root.rglob("*"):
        if path.is_file() and path.suffix in extensions:
            count += 1
            print(f"Formatting: {path}")

            if not dry_run:
                subprocess.run(
                    ["clang-format", "-i", str(path)],
                    check=True,
                )

    return count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recursively run clang-format on .h and .cpp files."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory to walk. Defaults to current directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print files that would be formatted without modifying them.",
    )

    args = parser.parse_args()
    root = Path(args.directory).resolve()

    if not root.is_dir():
        raise SystemExit(f"Error: not a directory: {root}")

    try:
        count = format_files(root, args.dry_run)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"clang-format failed on command: {exc.cmd}") from exc

    print(f"Done. Processed {count} file(s).")


if __name__ == "__main__":
    main()
