#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
"""Turn a Complement run into release evidence (ADR-0235).

    record_complement_evidence.py --work-dir RUN_DIR --package PACKAGE.deb --output-dir OUT

RUN_DIR is a work directory run_complement.py filled. OUT receives:

    complement-results-<version>.json   what was tested, how, and the verdict
    complement-<version>.jsonl          the raw `go test -json` log

Before writing anything, the record must hold together. The package must be
the one the run tested (same SHA-256). The server binary inside the package
must be the one the run's image ran (same SHA-256, read from the image during
the run). The skip list snapshot must be the one the run was judged by. A
mismatch means the run tested other bytes, and nothing is written.

The results are release evidence only when the package was verified against
the maintainer-signed SHA256SUMS, the whole suite ran (no --run filter) and
the summariser judged it green. Otherwise they are written with
"release_evidence": false and say why.

Exit status: 0 evidence written, 1 written but not release evidence, 2 refused
(nothing written).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import shutil
import sys
import tarfile
from pathlib import Path


SERVER_PATH = "usr/bin/merovingian-server"
AR_MAGIC = b"!<arch>\n"
AR_HEADER = 60


class Refused(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(AR_MAGIC):
        raise Refused("the package is not a Debian package (no ar header)")
    members: dict[str, bytes] = {}
    offset = len(AR_MAGIC)
    while offset + AR_HEADER <= len(data):
        header = data[offset:offset + AR_HEADER]
        if header[58:60] != b"`\n":
            raise Refused("the package's ar archive is malformed")
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as error:
            raise Refused("the package's ar archive is malformed") from error
        start = offset + AR_HEADER
        if start + size > len(data):
            raise Refused("the package's ar archive is truncated")
        members[name] = data[start:start + size]
        offset = start + size + (size % 2)
    return members


def open_tar(members: dict[str, bytes], stem: str) -> tarfile.TarFile:
    for name, content in members.items():
        if name.startswith(stem + "."):
            if name.endswith(".zst"):
                raise Refused(f"{name} is zstd-compressed, which this script cannot read")
            try:
                return tarfile.open(fileobj=io.BytesIO(content), mode="r:*")
            except (tarfile.TarError, lzma.LZMAError, EOFError) as error:
                raise Refused(f"cannot read {name}: {error}") from error
    raise Refused(f"the package has no {stem} member")


def regular_file(archive: tarfile.TarFile, path: str) -> bytes:
    for member in archive.getmembers():
        if member.name.removeprefix("./") == path:
            if not member.isreg():
                raise Refused(f"{path} in the package is not a regular file")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise Refused(f"cannot read {path} from the package")
            return extracted.read()
    raise Refused(f"the package has no {path}")


def package_facts(data: bytes) -> tuple[str, str]:
    """The package's Version and the SHA-256 of the server binary it ships."""
    members = ar_members(data)
    with open_tar(members, "control.tar") as control_tar:
        control = regular_file(control_tar, "control").decode("utf-8", "replace")
    version = next((line.split(":", 1)[1].strip() for line in control.splitlines() if line.startswith("Version:")), "")
    if not version or any(character in version for character in "/\\ \t") or version.startswith("."):
        raise Refused(f"the package's Version '{version}' cannot name an evidence file")
    with open_tar(members, "data.tar") as data_tar:
        server = regular_file(data_tar, SERVER_PATH)
    return version, sha256(server)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Refused(f"{path}: {error}") from error


def build(work: Path, package: Path) -> tuple[str, dict, bytes]:
    metadata = load_json(work / "run-metadata.json")
    summary = load_json(work / "summary.json")
    package_data = package.read_bytes()
    if sha256(package_data) != metadata["package"]["sha256"]:
        raise Refused(f"{package.name} is not the package the run tested")
    version, server_sha256 = package_facts(package_data)
    if server_sha256 != metadata["in_image_server_sha256"]:
        raise Refused("the image ran a server binary other than the one this package ships")
    skip_list = (work / "skip-list.toml").read_bytes()
    if sha256(skip_list) != metadata["skip_list_sha256"]:
        raise Refused("the skip list in the work directory is not the one the run was judged by")
    log = (work / "complement.jsonl").read_bytes()

    not_evidence_because = []
    if metadata["verification"].get("method") != "gpg":
        not_evidence_because.append("the package was not verified against the maintainer-signed SHA256SUMS")
    if metadata.get("run_filter"):
        not_evidence_because.append(f"only tests matching '{metadata['run_filter']}' ran")
    if summary.get("verdict") != "pass" or metadata.get("summariser_exit_code") != 0:
        not_evidence_because.append("the summariser did not judge the run green")

    results = {
        "schema": 1,
        "version": version,
        "release_evidence": not not_evidence_because,
        "not_evidence_because": not_evidence_because,
        "package": metadata["package"],
        "server_sha256": server_sha256,
        "verification": metadata["verification"],
        "image": {"tag": metadata["image_tag"], "id": metadata["image_id"]},
        "complement": metadata["complement"],
        "go_version": metadata["go_version"],
        "docker_version": metadata["docker_version"],
        "landlock_waived": metadata["landlock_waived"],
        "run_filter": metadata.get("run_filter"),
        "timeout": metadata.get("timeout"),
        "skip_pattern": metadata.get("skip_pattern"),
        "skip_list": {"sha256": sha256(skip_list), "content": skip_list.decode("utf-8")},
        "go_test_exit_code": metadata.get("go_test_exit_code"),
        "started_at": metadata["started_at"],
        "finished_at": metadata["finished_at"],
        "summary": summary,
        "log": {"name": f"complement-{version}.jsonl", "sha256": sha256(log)},
    }
    return version, results, log


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        version, results, log = build(args.work_dir, args.package)
        results_path = args.output_dir / f"complement-results-{version}.json"
        log_path = args.output_dir / results["log"]["name"]
        if results_path.exists() or log_path.exists():
            raise Refused(f"evidence for {version} already exists in {args.output_dir}; it is never overwritten")
    except (Refused, KeyError, OSError) as error:
        print(f"record_complement_evidence: {error}", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(log)
    results_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if results["release_evidence"]:
        print(f"record_complement_evidence: release evidence for {version} in {results_path}")
        return 0
    print(f"record_complement_evidence: {results_path} is not release evidence:", file=sys.stderr)
    for reason in results["not_evidence_because"]:
        print(f"  {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
