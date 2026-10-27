#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sign Complement evidence and attach it, with the tested package, to a release (ADR-0235).

    publish_complement_evidence.py --results complement-results-<v>.json \\
        --log complement-<v>.jsonl \\
        --package merovingian_<v>_amd64-debian.deb \\
        --package-signature merovingian_<v>_amd64-debian.deb.asc \\
        --tag v<v>-alpha.N

Run by the maintainer after the release workflow has published the tag's
release. It refuses, before signing anything:

- results that are not release evidence (record_complement_evidence.py says
  which are);
- a log other than the one the results name;
- a package other than the one the results name;
- a tag for another version: the tag must be v<version> or v<version>-...;
- a file that already has a signature beside it;
- a tag with no release;
- a tag that does not point at the commit the package was built from (the
  results' source commit, read from the package's build provenance);
- a package signature that does not verify to the maintainer key.

It signs the results and the log with the maintainer key in
tests/complement/run.toml (detached, ASCII-armoured), checks each signature
verifies to that key, and uploads them with their signatures, the tested
package and the package's own signature with `gh release upload`. A reader
then has, from the release alone, the bytes that were tested and the record
that says so. Existing release assets are never replaced (no --clobber).
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


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signed_by(path: Path, signature: Path) -> set[str]:
    result = run("gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(path))
    statuses = [line.split()[1:] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    names = {status[0] for status in statuses if status}
    if result.returncode != 0 or "GOODSIG" not in names or names & {"BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG"}:
        return set()
    return {status[-1].upper() for status in statuses if status and status[0] == "VALIDSIG"}


def publish(args: argparse.Namespace) -> None:
    config = tomllib.loads(RUN_CONFIG.read_text(encoding="utf-8"))["release"]
    key = config["maintainer_key"].upper()
    repository = config["repository"]
    tag = args.tag

    results = json.loads(args.results.read_text(encoding="utf-8"))
    if results.get("release_evidence") is not True:
        raise Refused(f"{args.results.name} is not release evidence: {results.get('not_evidence_because')}")
    version = results["version"]
    if tag != f"v{version}" and not tag.startswith(f"v{version}-"):
        raise Refused(f"{args.results.name} is evidence for {version}, not for tag {tag}")
    if args.log.name != results["log"]["name"] or sha256_of(args.log) != results["log"]["sha256"]:
        raise Refused(f"{args.log.name} is not the log {args.results.name} records")
    if args.package.name != results["package"]["name"] or sha256_of(args.package) != results["package"]["sha256"]:
        raise Refused(f"{args.package.name} is not the package {args.results.name} records")
    source_commit = (results.get("source") or {}).get("commit")
    if not source_commit:
        raise Refused(f"{args.results.name} names no source commit")
    signed = [args.results, args.log]
    signatures = [path.with_name(path.name + ".asc") for path in signed]
    existing = [signature.name for signature in signatures if signature.exists()]
    if existing:
        raise Refused(f"already signed: {', '.join(existing)}; signatures are never overwritten")

    if run("gh", "release", "view", tag, "--repo", repository).returncode != 0:
        raise Refused(f"{repository} has no release for {tag}; publish after the release workflow has run")
    tag_commit = run("gh", "api", f"repos/{repository}/commits/{tag}", "--jq", ".sha")
    if tag_commit.returncode != 0 or tag_commit.stdout.strip() != source_commit:
        raise Refused(f"{tag} points at {tag_commit.stdout.strip() or 'nothing readable'}, "
                      f"not {source_commit}, the commit the tested package was built from")
    if key not in signed_by(args.package, args.package_signature):
        raise Refused(f"{args.package_signature.name} does not verify {args.package.name} to the maintainer key {key}")

    for path, signature in zip(signed, signatures):
        made = run("gpg", "--batch", "--armor", "--detach-sign", "--local-user", key,
                   "--output", str(signature), str(path))
        if made.returncode != 0:
            raise Refused(f"gpg could not sign {path.name}: {made.stderr.strip()}")
        if key not in signed_by(path, signature):
            raise Refused(f"the signature on {path.name} does not verify to the maintainer key {key}")

    assets = [str(path) for pair in zip(signed, signatures) for path in pair]
    assets += [str(args.package), str(args.package_signature)]
    uploaded = run("gh", "release", "upload", tag, *assets, "--repo", repository)
    if uploaded.returncode != 0:
        raise Refused(f"gh release upload failed: {uploaded.stderr.strip()}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True, help="the tested Debian trixie package")
    parser.add_argument("--package-signature", type=Path, required=True,
                        help="its detached maintainer signature, from the rolling latest release")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        publish(args)
    except (Refused, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"publish_complement_evidence: {error}", file=sys.stderr)
        return 1
    print(f"publish_complement_evidence: {args.results.name}, {args.log.name} and {args.package.name}, "
          f"signed, attached to {args.tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
