#!/usr/bin/env python3
"""Behaviour of scripts/record_complement_evidence.py and publish_complement_evidence.py.

A Complement run is release evidence only when the binary it tested is the
binary the package ships, the package was verified against the maintainer's
signed SHA256SUMS, and the whole suite ran green (ADR-0235). The recorder is
tested against Debian packages built here; the publisher against fake gpg and
gh, because it signs with the maintainer key and uploads to GitHub.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RECORDER = REPO_ROOT / "scripts" / "record_complement_evidence.py"
PUBLISHER = REPO_ROOT / "scripts" / "publish_complement_evidence.py"
RUN_CONFIG = tomllib.loads((REPO_ROOT / "tests" / "complement" / "run.toml").read_text(encoding="utf-8"))
MAINTAINER_KEY = RUN_CONFIG["release"]["maintainer_key"]
REPOSITORY = RUN_CONFIG["release"]["repository"]
VERSION = "0.12.55"
PACKAGE_NAME = f"merovingian_{VERSION}_amd64-debian.deb"
SERVER = b"\x7fELF the shipped server"


def tar_xz(members: dict[str, tuple[bytes, int]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for name, (content, kind) in members.items():
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = content.decode()
            else:
                info.size = len(content)
            archive.addfile(info, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


def ar_archive(members: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, content in members:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(content):<10}`\n".encode()
        out += header + content + (b"\n" if len(content) % 2 else b"")
    return bytes(out)


def debian_package(server: bytes | None = SERVER, version: str = VERSION, server_kind: int = tarfile.REGTYPE) -> bytes:
    control = f"Package: merovingian\nVersion: {version}\nArchitecture: amd64\n".encode()
    data = {"./usr/": (b"", tarfile.DIRTYPE), "./usr/bin/": (b"", tarfile.DIRTYPE)}
    if server is not None:
        data["./usr/bin/merovingian-server"] = (server, server_kind)
    return ar_archive([
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", tar_xz({"./control": (control, tarfile.REGTYPE)})),
        ("data.tar.xz", tar_xz(data)),
    ])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RecorderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="complement-evidence-"))
        self.run_dir = self.workdir / "run"
        self.run_dir.mkdir()
        self.out = self.workdir / "evidence"
        self.package = self.workdir / PACKAGE_NAME
        self.write_package(debian_package())
        self.skip_list = b"# empty\n"
        (self.run_dir / "skip-list.toml").write_bytes(self.skip_list)
        self.log = b'{"Action":"pass","Package":"github.com/matrix-org/complement/tests","Test":"TestA"}\n'
        (self.run_dir / "complement.jsonl").write_bytes(self.log)
        self.metadata = {
            "schema": 1,
            "package": {"name": PACKAGE_NAME, "sha256": sha256(self.package.read_bytes())},
            "verification": {"method": "gpg", "key": MAINTAINER_KEY},
            "image_tag": "merovingian-complement:0123456789abcdef",
            "image_id": "sha256:" + "cd" * 32,
            "in_image_server_sha256": sha256(SERVER),
            "complement": {"repository": "https://github.com/matrix-org/complement", "commit": "df42e70900b45789b72e3ba91771cd26933d5008"},
            "go_version": "go1.26.2",
            "docker_version": "27.1.0",
            "landlock_waived": False,
            "run_filter": None,
            "timeout": "3h",
            "skip_pattern": None,
            "skip_list_sha256": sha256(self.skip_list),
            "go_test_exit_code": 0,
            "summariser_exit_code": 0,
            "started_at": "2026-10-26T20:00:00+00:00",
            "finished_at": "2026-10-26T21:30:00+00:00",
        }
        self.summary = {"verdict": "pass", "results": {"pass": 1, "fail": 0, "skip": 0},
                        "top_level_results": {"pass": 1, "fail": 0, "skip": 0}, "expected_failures": [],
                        "unexpected_failures": [], "unfinished": [], "stale_entries": [], "missing_entries": [],
                        "not_run": [], "skip_not_applied": [], "package_failures": []}

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def write_package(self, data: bytes) -> None:
        self.package.write_bytes(data)

    def record(self) -> subprocess.CompletedProcess[str]:
        (self.run_dir / "run-metadata.json").write_text(json.dumps(self.metadata), encoding="utf-8")
        (self.run_dir / "summary.json").write_text(json.dumps(self.summary), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", str(RECORDER), "--work-dir", str(self.run_dir), "--package", str(self.package),
             "--output-dir", str(self.out)],
            capture_output=True, text=True, timeout=60, check=False,
        )

    def results(self) -> dict:
        return json.loads((self.out / f"complement-results-{VERSION}.json").read_text(encoding="utf-8"))

    def test_a_signed_full_green_run_is_release_evidence(self) -> None:
        # GIVEN a green, unfiltered run of a signed package whose image ran the package's server.
        # WHEN it is recorded.
        result = self.record()
        # THEN the results name the version, the binary and what tested it, and are evidence.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        results = self.results()
        self.assertTrue(results["release_evidence"])
        self.assertEqual(results["not_evidence_because"], [])
        self.assertEqual(results["version"], VERSION)
        self.assertEqual(results["package"]["sha256"], sha256(self.package.read_bytes()))
        self.assertEqual(results["server_sha256"], sha256(SERVER))
        self.assertEqual(results["complement"]["commit"], self.metadata["complement"]["commit"])
        self.assertEqual(results["summary"]["verdict"], "pass")
        self.assertEqual(results["skip_list"], {"sha256": sha256(self.skip_list), "content": self.skip_list.decode()})

    def test_the_raw_log_travels_with_the_results(self) -> None:
        # GIVEN a recorded run.
        result = self.record()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # WHEN the evidence directory is read.
        log = self.out / f"complement-{VERSION}.jsonl"
        # THEN it holds the run's log byte for byte, and the results name its digest.
        self.assertEqual(log.read_bytes(), self.log)
        self.assertEqual(self.results()["log"], {"name": log.name, "sha256": sha256(self.log)})

    def test_an_image_that_ran_another_server_is_refused(self) -> None:
        # GIVEN a run whose image held a server other than the package's.
        self.metadata["in_image_server_sha256"] = sha256(b"something else")
        # WHEN it is recorded.
        result = self.record()
        # THEN nothing is written: the run tested other bytes.
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.out.exists())

    def test_a_package_other_than_the_one_run_is_refused(self) -> None:
        # GIVEN a package whose digest differs from the run's.
        self.write_package(debian_package(server=b"rebuilt"))
        self.metadata["in_image_server_sha256"] = sha256(b"rebuilt")
        # WHEN it is recorded.
        result = self.record()
        # THEN it is refused.
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.out.exists())

    def test_a_package_without_a_regular_server_binary_is_refused(self) -> None:
        for name, package in {"no server": debian_package(server=None),
                              "a linked server": debian_package(server=b"/bin/true", server_kind=tarfile.SYMTYPE)}.items():
            with self.subTest(case=name):
                # GIVEN a package with no regular /usr/bin/merovingian-server.
                self.write_package(package)
                self.metadata["package"]["sha256"] = sha256(package)
                # WHEN the run is recorded.
                result = self.record()
                # THEN it is refused.
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.out.exists())

    def test_a_skip_list_changed_since_the_run_is_refused(self) -> None:
        # GIVEN a skip list snapshot that no longer matches the run's digest.
        (self.run_dir / "skip-list.toml").write_bytes(b"# edited after the run\n")
        # WHEN the run is recorded.
        result = self.record()
        # THEN it is refused.
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.out.exists())

    def test_runs_that_are_not_evidence_are_recorded_as_such(self) -> None:
        cases = {
            "unsigned": ("verification", {"method": "unsigned"}),
            "filtered": ("run_filter", "TestA"),
        }
        for name, (field, value) in cases.items():
            with self.subTest(case=name):
                # GIVEN a run that was unsigned or filtered.
                original = self.metadata[field]
                self.metadata[field] = value
                shutil.rmtree(self.out, ignore_errors=True)
                # WHEN it is recorded.
                result = self.record()
                self.metadata[field] = original
                # THEN the results are written but are not release evidence, and say why.
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                results = self.results()
                self.assertFalse(results["release_evidence"])
                self.assertTrue(results["not_evidence_because"])

    def test_a_red_run_is_not_evidence(self) -> None:
        # GIVEN a run the summariser judged not green.
        self.summary["verdict"] = "fail"
        self.summary["unexpected_failures"] = ["tests:TestA"]
        self.metadata["summariser_exit_code"] = 1
        # WHEN it is recorded.
        result = self.record()
        # THEN the results record the failure and are not evidence.
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.results()["release_evidence"])

    def test_a_landlock_waiver_is_recorded_but_does_not_disqualify(self) -> None:
        # GIVEN a green run that waived Landlock for the federation worker.
        self.metadata["landlock_waived"] = True
        # WHEN it is recorded.
        result = self.record()
        # THEN it is evidence, and says so on its face.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.results()["landlock_waived"])

    def test_existing_evidence_is_never_overwritten(self) -> None:
        # GIVEN evidence already recorded for this version.
        self.assertEqual(self.record().returncode, 0)
        before = (self.out / f"complement-results-{VERSION}.json").read_bytes()
        # WHEN another run is recorded into the same directory.
        result = self.record()
        # THEN it is refused and the first record is untouched.
        self.assertEqual(result.returncode, 2)
        self.assertEqual((self.out / f"complement-results-{VERSION}.json").read_bytes(), before)


FAKE_GPG = """\
    #!/bin/sh
    echo "gpg $*" >> "$FAKE_OUT/calls"
    output=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --output) shift; output=$1 ;;
            --verify) printf '%b' "$FAKE_GPG_STATUS"; exit 0 ;;
        esac
        shift
    done
    [ -n "$output" ] && echo "signature" > "$output"
    exit 0
    """

FAKE_GH = """\
    #!/bin/sh
    echo "gh $*" >> "$FAKE_OUT/calls"
    case "$1 $2" in
        "release view") exit "${FAKE_GH_VIEW_EXIT:-0}" ;;
    esac
    exit 0
    """


def valid_status(fingerprint: str = MAINTAINER_KEY) -> str:
    return (f"[GNUPG:] GOODSIG 92A3A264F0A7BE20 Maintainer\\n"
            f"[GNUPG:] VALIDSIG {fingerprint} 2026-10-26 1793000000 0 4 0 22 10 00 {fingerprint}\\n")


@unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "the fake tools are POSIX shell")
class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="complement-publish-"))
        self.bin = self.workdir / "bin"
        self.calls_dir = self.workdir / "out"
        self.bin.mkdir()
        self.calls_dir.mkdir()
        for name, body in {"gpg": FAKE_GPG, "gh": FAKE_GH}.items():
            tool = self.bin / name
            tool.write_text(textwrap.dedent(body), encoding="utf-8")
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        self.log = self.workdir / f"complement-{VERSION}.jsonl"
        self.log.write_bytes(b"{}\n")
        self.results = self.workdir / f"complement-results-{VERSION}.json"
        self.write_results(release_evidence=True)
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                        FAKE_OUT=str(self.calls_dir), FAKE_GPG_STATUS=valid_status())

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def write_results(self, release_evidence: bool, log_sha256: str | None = None, version: str = VERSION) -> None:
        self.results.write_text(json.dumps({
            "version": version,
            "release_evidence": release_evidence,
            "not_evidence_because": [] if release_evidence else ["the package was not verified"],
            "log": {"name": self.log.name, "sha256": log_sha256 or sha256(self.log.read_bytes())},
        }), encoding="utf-8")

    def publish(self, tag: str = f"v{VERSION}-alpha.1") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(PUBLISHER), "--results", str(self.results), "--log", str(self.log), "--tag", tag],
            env=self.env, capture_output=True, text=True, timeout=60, check=False,
        )

    def calls(self) -> str:
        path = self.calls_dir / "calls"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_evidence_is_signed_by_the_maintainer_and_attached_to_the_release(self) -> None:
        # GIVEN release evidence for a version, and its tag's release.
        # WHEN it is published.
        result = self.publish()
        # THEN both files are signed with the maintainer key and uploaded, with
        # their signatures, to that release in this project's repository.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertIn(f"--local-user {MAINTAINER_KEY}", calls)
        self.assertTrue((self.workdir / f"{self.results.name}.asc").exists())
        self.assertTrue((self.workdir / f"{self.log.name}.asc").exists())
        upload = [line for line in calls.splitlines() if line.startswith("gh release upload")]
        self.assertEqual(len(upload), 1)
        for name in (self.results.name, f"{self.results.name}.asc", self.log.name, f"{self.log.name}.asc"):
            self.assertIn(name, upload[0])
        self.assertIn(f"--repo {REPOSITORY}", upload[0])
        self.assertNotIn("--clobber", upload[0])

    def test_results_that_are_not_evidence_are_never_published(self) -> None:
        # GIVEN results recorded from an unsigned run.
        self.write_results(release_evidence=False)
        # WHEN publishing is attempted.
        result = self.publish()
        # THEN it is refused before anything is signed or uploaded.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), "")

    def test_a_log_that_is_not_the_recorded_one_is_refused(self) -> None:
        # GIVEN results whose log digest differs from the log given.
        self.write_results(release_evidence=True, log_sha256="0" * 64)
        # WHEN publishing is attempted.
        result = self.publish()
        # THEN it is refused before anything is signed.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), "")

    def test_evidence_goes_only_to_its_own_versions_tag(self) -> None:
        for tag in ("v0.12.56-alpha.1", "v0.12.5", "0.12.55", "latest"):
            with self.subTest(tag=tag):
                # GIVEN evidence for 0.12.55.
                # WHEN it is published to another version's tag.
                result = self.publish(tag)
                # THEN it is refused.
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), "")

    def test_existing_signatures_are_not_overwritten(self) -> None:
        # GIVEN a signature already beside the results.
        (self.workdir / f"{self.results.name}.asc").write_text("earlier", encoding="utf-8")
        # WHEN publishing is attempted.
        result = self.publish()
        # THEN it is refused and the signature is untouched.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.workdir / f"{self.results.name}.asc").read_text(encoding="utf-8"), "earlier")

    def test_a_tag_without_a_release_is_refused_before_signing(self) -> None:
        # GIVEN a tag whose release does not exist yet.
        self.env["FAKE_GH_VIEW_EXIT"] = "1"
        # WHEN publishing is attempted.
        result = self.publish()
        # THEN nothing is signed.
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gpg ", self.calls())

    def test_signatures_by_another_key_are_not_uploaded(self) -> None:
        # GIVEN gpg signs with a key other than the maintainer's.
        self.env["FAKE_GPG_STATUS"] = valid_status("F" * 40)
        # WHEN publishing is attempted.
        result = self.publish()
        # THEN nothing is uploaded.
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("gh release upload", self.calls())


if __name__ == "__main__":
    unittest.main()
