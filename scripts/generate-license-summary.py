#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a machine-readable license summary from docs/dependencies/licenses.md.

The summary is written as JSON to the path supplied on the command line, or to
stdout when no path is provided. The JSON is derived from the markdown tables in
licenses.md so the human-readable and machine-readable artifacts stay in sync.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LICENSES_MD = REPO_ROOT / "docs" / "dependencies" / "licenses.md"


def _split_table_row(line: str) -> list[str]:
    """Split a markdown table row into trimmed cells."""
    cells = [cell.strip().strip("`") for cell in line.split("|")]
    # The first and last cells are empty because markdown table rows start and end
    # with a pipe.
    return [cell for cell in cells if cell]


def parse_tables(markdown: str) -> dict[str, list[dict[str, str | bool]]]:
    """Extract named tables from the license markdown document."""
    tables: dict[str, list[dict[str, str | bool]]] = {}
    current_section: str | None = None
    header: list[str] | None = None

    for line in markdown.splitlines():
        section_match = re.match(r"^## (.+)$", line)
        if section_match:
            current_section = section_match.group(1)
            header = None
            continue

        if not line.startswith("|"):
            header = None
            continue

        cells = _split_table_row(line)
        if not cells:
            continue

        # A separator row looks like | --- | --- | ...
        if all(re.match(r"^-+$", cell.strip()) for cell in cells):
            continue

        if header is None:
            header = [cell.lower().replace(" ", "_") for cell in cells]
            # Normalize the compatibility column name to a stable key.
            header = [
                "compatible" if "compatible" in cell else cell for cell in header
            ]
            continue

        if current_section is None:
            continue

        row: dict[str, str | bool] = {}
        for key, value in zip(header, cells):
            if key == "compatible":
                row[key] = value.lower() in ("yes", "true")
            else:
                row[key] = value

        tables.setdefault(current_section, []).append(row)

    return tables


def main(argv: list[str]) -> int:
    if not LICENSES_MD.is_file():
        print(f"error: missing license document {LICENSES_MD}", file=sys.stderr)
        return 1

    markdown = LICENSES_MD.read_text(encoding="utf-8")
    tables = parse_tables(markdown)

    # Flatten all tables into one array with a category tag. Sections that do not
    # contain dependency tables are skipped.
    summary: list[dict[str, str | bool]] = []
    for category, rows in tables.items():
        for row in rows:
            entry = dict(row)
            entry["category"] = category
            summary.append(entry)

    if not summary:
        print("error: no license rows parsed from licenses.md", file=sys.stderr)
        return 1

    output = json.dumps(summary, indent=2, sort_keys=True)

    if len(argv) > 1:
        output_path = Path(argv[1])
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        sys.stdout.write(output + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
