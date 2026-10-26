#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sign Complement evidence and attach it to a release (ADR-0235).

    publish_complement_evidence.py --results complement-results-<v>.json \\
        --log complement-<v>.jsonl --tag v<v>-alpha.N

Run by the maintainer after the release workflow has published the tag's
release. It refuses, before signing anything:

- results that are not release evidence (record_complement_evidence.py says
  which are);
- a log other than the one the results name;
- a tag for another version: the tag must be v<version> or v<version>-...;
- a file that already has a signature beside it;
- a tag with no release.

It signs both files with the maintainer key in tests/complement/run.toml
(detached, ASCII-armoured), checks each signature verifies to that key, and
uploads the four files with `gh release upload`. Existing release assets are
never replaced (no --clobber).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_CONFIG = REPO_ROOT / "tests" / "complement" / "run.toml"


class Refused(Exception):
    pass


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True, check=False)


def signed_by(path: Path, signature: Path) -> set[str]:
    result = run("gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(path))
    statuses = [line.split()[1:] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    names = {status[0] for status in statuses if status}
    if result.returncode != 0 or "GOODSIG" not in names or names & {"BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG"}:
        return set()
    return {status[-1].upper() for status in statuses if status and status[0] == "VALIDSIG"}


def publish(results_path: Path, log_path: Path, tag: str) -> None:
    config = tomllib.loads(RUN_CONFIG.read_text(encoding="utf-8"))["release"]
    key = config["maintainer_key"].upper()
    repository = config["repository"]

    results = json.loads(results_path.read_text(encoding="utf-8"))
    if results.get("release_evidence") is not True:
        raise Refused(f"{results_path.name} is not release evidence: {results.get('not_evidence_because')}")
    version = results["version"]
    if tag != f"v{version}" and not tag.startswith(f"v{version}-"):
        raise Refused(f"{results_path.name} is evidence for {version}, not for tag {tag}")
    if log_path.name != results["log"]["name"] or \
            hashlib.sha256(log_path.read_bytes()).hexdigest() != results["log"]["sha256"]:
        raise Refused(f"{log_path.name} is not the log {results_path.name} records")
    files = [results_path, log_path]
    signatures = [path.with_name(path.name + ".asc") for path in files]
    existing = [signature.name for signature in signatures if signature.exists()]
    if existing:
        raise Refused(f"already signed: {', '.join(existing)}; signatures are never overwritten")
    if run("gh", "release", "view", tag, "--repo", repository).returncode != 0:
        raise Refused(f"{repository} has no release for {tag}; publish after the release workflow has run")

    for path, signature in zip(files, signatures):
        signed = run("gpg", "--batch", "--armor", "--detach-sign", "--local-user", key,
                      "--output", str(signature), str(path))
        if signed.returncode != 0:
            raise Refused(f"gpg could not sign {path.name}: {signed.stderr.strip()}")
        if key not in signed_by(path, signature):
            raise Refused(f"the signature on {path.name} does not verify to the maintainer key {key}")

    uploaded = run("gh", "release", "upload", tag, *(str(path) for pair in zip(files, signatures) for path in pair),
                   "--repo", repository)
    if uploaded.returncode != 0:
        raise Refused(f"gh release upload failed: {uploaded.stderr.strip()}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        publish(args.results, args.log, args.tag)
    except (Refused, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"publish_complement_evidence: {error}", file=sys.stderr)
        return 1
    print(f"publish_complement_evidence: {args.results.name} and {args.log.name}, signed, attached to {args.tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
