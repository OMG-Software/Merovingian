#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run Complement against a Merovingian Debian trixie package (ADR-0234).

    run_complement.py --package merovingian_<v>_amd64-debian.deb \\
        --sha256sums SHA256SUMS --signature SHA256SUMS.asc --work-dir DIR

    run_complement.py --package local.deb --unsigned --work-dir DIR

1. Verify the package: its SHA-256 must be in a SHA256SUMS that the
   maintainer key in tests/complement/run.toml signed. --unsigned skips this
   for a package built locally; such a run is never release evidence.
2. Build tests/complement into an image, from a copy under DIR (the source
   tree is not written), and read the server binary's SHA-256 back out of it.
3. Fetch Complement at the pinned commit into DIR/complement.
4. List its tests, run `go test -json ./tests/...` against the image, and
   hand both to summarise_complement.py, whose verdict is this script's exit
   status: 0 green, 1 not green, 2 refused before running.

DIR must not exist or be empty. It ends up holding complement.jsonl (the raw
run), listing.jsonl, the skip list the run was judged by, summary.json and
run-metadata.json, which record_complement_evidence.py turns into release
evidence.

The run needs Docker, Go (at least the pinned version), git, gpg (unless
--unsigned) and network access for Complement and its Go modules. Inherited
COMPLEMENT_* variables are dropped, so the caller's shell cannot change what
is tested.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIR = REPO_ROOT / "tests" / "complement"
SUMMARISER = REPO_ROOT / "scripts" / "summarise_complement.py"
SHARED_PREFIX = "MEROVINGIAN_COMPLEMENT_SHARED_"
SPAWN_TIMEOUT_SECONDS = "60"
GO_VERSION = re.compile(r"go(\d+)\.(\d+)(?:\.(\d+))?")
SHA256 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
REFUSED_STATUS = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"}


class Refused(Exception):
    pass


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def run(*command: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(list(command), cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise Refused(f"`{' '.join(command)}` failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def version_tuple(text: str) -> tuple[int, int, int]:
    match = GO_VERSION.fullmatch(text.strip()) or GO_VERSION.fullmatch("go" + text.strip())
    if match is None:
        raise Refused(f"cannot read a Go version from '{text.strip()}'")
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def verify_signature(sums: Path, signature: Path, maintainer_key: str) -> None:
    result = subprocess.run(
        ["gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(sums)],
        capture_output=True, text=True, check=False,
    )
    statuses = [line.split()[1:] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] ")]
    names = {status[0] for status in statuses if status}
    if result.returncode != 0 or names & REFUSED_STATUS or "GOODSIG" not in names:
        raise Refused(f"{sums.name} is not validly signed (gpg: {sorted(names) or result.stderr.strip()}). "
                      f"Import the maintainer key {maintainer_key} (docs/release-process.md) and check the files.")
    primaries = {status[-1].upper() for status in statuses if status and status[0] == "VALIDSIG" and len(status) >= 2}
    if maintainer_key not in primaries:
        raise Refused(f"{sums.name} is signed by {sorted(primaries)}, not the maintainer key {maintainer_key}")


def listed_digest(sums: Path, package_name: str) -> str:
    matches = []
    for line in sums.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and Path(parts[1].lstrip("*")).name == package_name:
            matches.append(parts[0].lower())
    if len(matches) != 1:
        raise Refused(f"{sums.name} lists {package_name} {len(matches)} times; expected once")
    return matches[0]


def complement_environment(image_tag: str, allow_without_landlock: bool) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("COMPLEMENT_") and not key.startswith(SHARED_PREFIX)}
    env["COMPLEMENT_BASE_IMAGE"] = image_tag
    env["COMPLEMENT_SPAWN_HS_TIMEOUT_SECS"] = SPAWN_TIMEOUT_SECONDS
    if allow_without_landlock:
        env["COMPLEMENT_SHARE_ENV_PREFIX"] = SHARED_PREFIX
        env[f"{SHARED_PREFIX}MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK"] = "true"
    return env


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--package", type=Path, required=True, help="the Debian trixie .deb to test")
    parser.add_argument("--sha256sums", type=Path, help="the release's SHA256SUMS")
    parser.add_argument("--signature", type=Path, help="its detached signature, SHA256SUMS.asc")
    parser.add_argument("--unsigned", action="store_true", help="a locally built package; never release evidence")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--skip-list", type=Path, default=IMAGE_DIR / "skip-list.toml")
    parser.add_argument("--run-config", type=Path, default=IMAGE_DIR / "run.toml")
    parser.add_argument("--allow-without-landlock", action="store_true",
                        help="waive Landlock for the federation worker; recorded in the evidence")
    parser.add_argument("--run", help="go test -run filter; a filtered run is never release evidence")
    parser.add_argument("--timeout", default="3h", help="go test -timeout (default 3h)")
    args = parser.parse_args(argv)
    signed_inputs = args.sha256sums is not None or args.signature is not None
    if args.unsigned and signed_inputs:
        parser.error("--unsigned cannot be combined with --sha256sums or --signature")
    if not args.unsigned and (args.sha256sums is None or args.signature is None):
        parser.error("give --sha256sums and --signature, or --unsigned for a locally built package")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    work = args.work_dir.resolve()
    if work.exists() and (not work.is_dir() or any(work.iterdir())):
        print(f"run_complement: {work} is not an empty directory; refusing to mix two runs", file=sys.stderr)
        return 2
    try:
        return execute(args, work)
    except Refused as error:
        print(f"run_complement: {error}", file=sys.stderr)
        return 2


def execute(args: argparse.Namespace, work: Path) -> int:
    config = tomllib.loads(args.run_config.read_text(encoding="utf-8"))
    repository = config["complement"]["repository"]
    commit = config["complement"]["commit"]
    minimum_go = config["complement"]["go"]
    maintainer_key = config["release"]["maintainer_key"].upper()
    if not FINGERPRINT.fullmatch(maintainer_key):
        raise Refused(f"{args.run_config}: maintainer_key is not a 40-digit fingerprint")

    tools = ["docker", "go", "git"] + ([] if args.unsigned else ["gpg"])
    absent = [tool for tool in tools if shutil.which(tool) is None]
    if absent:
        raise Refused(f"not on PATH: {', '.join(absent)}")
    go_version = run("go", "env", "GOVERSION").strip()
    if version_tuple(go_version) < version_tuple(minimum_go):
        raise Refused(f"{go_version} is older than go{minimum_go}, which Complement {commit[:12]} needs")

    package = args.package.resolve()
    digest = sha256_of(package)
    if args.unsigned:
        verification = {"method": "unsigned"}
    else:
        verify_signature(args.sha256sums, args.signature, maintainer_key)
        if listed_digest(args.sha256sums, package.name) != digest:
            raise Refused(f"{package.name} does not match its digest in {args.sha256sums.name}")
        verification = {"method": "gpg", "key": maintainer_key}
    print(f"run_complement: {package.name} {digest} ({verification['method']})")

    work.mkdir(parents=True, exist_ok=True)
    context = work / "image"
    shutil.copytree(IMAGE_DIR, context, ignore=shutil.ignore_patterns("artifact", "__pycache__"))
    (context / "artifact").mkdir()
    shutil.copyfile(package, context / "artifact" / "merovingian.deb")
    image_tag = f"merovingian-complement:{digest[:16]}"
    run("docker", "build", "--build-arg", f"MEROVINGIAN_DEB_SHA256={digest}", "--tag", image_tag, str(context))
    image_id = run("docker", "image", "inspect", "--format", "{{.Id}}", image_tag).strip()
    in_image = run("docker", "run", "--rm", "--entrypoint", "sha256sum", image_tag, "/usr/bin/merovingian-server")
    in_image_server_sha256 = in_image.split()[0] if in_image.split() else ""
    if not SHA256.fullmatch(in_image_server_sha256):
        raise Refused(f"cannot read the server's SHA-256 from the image: '{in_image.strip()}'")
    docker_version = run("docker", "version", "--format", "{{.Server.Version}}").strip()

    checkout = work / "complement"
    checkout.mkdir()
    run("git", "-C", str(checkout), "init", "--quiet")
    run("git", "-C", str(checkout), "remote", "add", "origin", repository)
    run("git", "-C", str(checkout), "fetch", "--depth", "1", "origin", commit)
    run("git", "-C", str(checkout), "checkout", "--quiet", "FETCH_HEAD")
    head = run("git", "-C", str(checkout), "rev-parse", "HEAD").strip()
    if head != commit:
        raise Refused(f"the checkout is at {head}, not the pinned {commit}")

    # The run is judged by this copy, and the evidence carries it.
    skip_list = work / "skip-list.toml"
    shutil.copyfile(args.skip_list, skip_list)
    skip_list_sha256 = sha256_of(skip_list)

    env = complement_environment(image_tag, args.allow_without_landlock)
    listing = work / "listing.jsonl"
    listing.write_text(run("go", "test", "-json", "-list", ".*", "./tests/...", cwd=checkout, env=env), encoding="utf-8")
    pattern = run(sys.executable, "-I", str(SUMMARISER), "--repo-root", str(REPO_ROOT),
                  "--skip-list", str(skip_list), "--skip-pattern").strip()

    command = ["go", "test", "-json", "-count=1", "-timeout", args.timeout]
    if pattern:
        command += ["-skip", pattern]
    if args.run:
        command += ["-run", args.run]
    command.append("./tests/...")
    log = work / "complement.jsonl"
    started_at = now()
    print(f"run_complement: {' '.join(command)} (image {image_tag})")
    with log.open("w", encoding="utf-8") as stdout, (work / "go-test.stderr.log").open("w", encoding="utf-8") as stderr:
        go_test = subprocess.run(command, cwd=checkout, env=env, stdout=stdout, stderr=stderr, check=False)
    finished_at = now()

    summary = subprocess.run(
        [sys.executable, "-I", str(SUMMARISER), "--repo-root", str(REPO_ROOT), "--skip-list", str(skip_list),
         "--log", str(log), "--listing", str(listing), "--output", str(work / "summary.json")],
        check=False,
    )
    metadata = {
        "schema": 1,
        "package": {"name": package.name, "sha256": digest},
        "verification": verification,
        "image_tag": image_tag,
        "image_id": image_id,
        "in_image_server_sha256": in_image_server_sha256,
        "complement": {"repository": repository, "commit": commit},
        "go_version": go_version,
        "docker_version": docker_version,
        "landlock_waived": args.allow_without_landlock,
        "run_filter": args.run,
        "timeout": args.timeout,
        "skip_pattern": pattern or None,
        "skip_list_sha256": skip_list_sha256,
        "go_test_exit_code": go_test.returncode,
        "summariser_exit_code": summary.returncode,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    (work / "run-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
