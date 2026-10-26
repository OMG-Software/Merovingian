#!/usr/bin/env python3
"""Behaviour of scripts/run_complement.py against fake docker, go, git and gpg.

The real run needs Docker, Go, the network and the maintainer key, and is made
by the maintainer before a release (tests/complement/AGENTS.md). These tests
put stand-ins for those tools on PATH and check the script's own decisions:
what it refuses before building anything, what it passes to Complement, and
that the verdict is the summariser's, not `go test`'s.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "scripts" / "run_complement.py"
RUN_CONFIG = REPO_ROOT / "tests" / "complement" / "run.toml"
PINNED = tomllib.loads(RUN_CONFIG.read_text(encoding="utf-8"))
COMMIT = PINNED["complement"]["commit"]
MAINTAINER_KEY = PINNED["release"]["maintainer_key"]
PACKAGE_NAME = "merovingian_0.12.55_amd64-debian.deb"
SERVER_SHA = "ab" * 32
TESTS = "github.com/matrix-org/complement/tests"

FAKE_TOOLS = {
    "gpg": """\
        #!/bin/sh
        echo "gpg $*" >> "$FAKE_OUT/calls"
        printf '%b' "$FAKE_GPG_STATUS"
        exit "${FAKE_GPG_EXIT:-0}"
        """,
    "git": """\
        #!/bin/sh
        echo "git $*" >> "$FAKE_OUT/calls"
        case " $* " in
            *" rev-parse HEAD "*) echo "$FAKE_GIT_HEAD" ;;
        esac
        exit 0
        """,
    "go": """\
        #!/bin/sh
        echo "go $*" >> "$FAKE_OUT/calls"
        case "$1 $2" in
            "env GOVERSION") echo "$FAKE_GO_VERSION"; exit 0 ;;
        esac
        case " $* " in
            *" -list "*) cat "$FAKE_LISTING"; exit 0 ;;
        esac
        env | grep -E '^(COMPLEMENT_|MEROVINGIAN_)' | sort > "$FAKE_OUT/go-env"
        cat "$FAKE_RUN_LOG"
        echo "go test noise on stderr" >&2
        exit 1
        """,
    "docker": """\
        #!/bin/sh
        echo "docker $*" >> "$FAKE_OUT/calls"
        case "$1" in
            version) echo "27.1.0" ;;
            build)
                for last; do :; done
                ls -A "$last" > "$FAKE_OUT/build-context"
                sha256sum "$last/artifact/merovingian.deb" | cut -d ' ' -f 1 > "$FAKE_OUT/built-package"
                ;;
            image) echo "sha256:$(printf 'cd%.0s' $(seq 32))" ;;
            run) echo "$FAKE_SERVER_SHA  /usr/bin/merovingian-server" ;;
        esac
        exit 0
        """,
}


def event(action: str, test: str | None = None) -> dict:
    record: dict = {"Action": action, "Package": TESTS}
    if test is not None:
        record["Test"] = test
    return record


def valid_status(fingerprint: str = MAINTAINER_KEY) -> str:
    return (
        f"[GNUPG:] GOODSIG 92A3A264F0A7BE20 Maintainer\\n"
        f"[GNUPG:] VALIDSIG {fingerprint} 2026-10-26 1793000000 0 4 0 22 10 00 {fingerprint}\\n"
    )


@unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "the fake tools are POSIX shell")
class RunComplementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="run-complement-"))
        self.bin = self.workdir / "bin"
        self.out = self.workdir / "out"
        self.bin.mkdir()
        self.out.mkdir()
        for name, body in FAKE_TOOLS.items():
            tool = self.bin / name
            tool.write_text(textwrap.dedent(body), encoding="utf-8")
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        self.package = self.workdir / PACKAGE_NAME
        self.package.write_bytes(b"not really a package")
        self.digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.sums = self.workdir / "SHA256SUMS"
        self.sums.write_text(f"{'0' * 64}  packages/other.rpm\n{self.digest}  packages/{PACKAGE_NAME}\n", encoding="utf-8")
        self.signature = self.workdir / "SHA256SUMS.asc"
        self.signature.write_text("signature", encoding="utf-8")
        self.skip_list = self.workdir / "skip-list.toml"
        self.skip_list.write_text("", encoding="utf-8")
        self.listing = self.workdir / "listing.jsonl"
        self.listing.write_text("", encoding="utf-8")
        self.run_log = self.workdir / "run-input.jsonl"
        self.write_run_log([event("run", "TestA"), event("pass", "TestA"), event("pass")])
        self.results = self.workdir / "results"
        self.env = dict(
            os.environ,
            PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            FAKE_OUT=str(self.out),
            FAKE_GPG_STATUS=valid_status(),
            FAKE_GIT_HEAD=COMMIT,
            FAKE_GO_VERSION="go1.26.2",
            FAKE_LISTING=str(self.listing),
            FAKE_RUN_LOG=str(self.run_log),
            FAKE_SERVER_SHA=SERVER_SHA,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def write_run_log(self, events: list[dict]) -> None:
        self.run_log.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")

    def run_script(self, *extra: str, signed: bool = True) -> subprocess.CompletedProcess[str]:
        args = [sys.executable, "-I", str(RUNNER), "--package", str(self.package), "--work-dir", str(self.results),
                "--skip-list", str(self.skip_list)]
        if signed:
            args += ["--sha256sums", str(self.sums), "--signature", str(self.signature)]
        return subprocess.run(args + list(extra), env=self.env, capture_output=True, text=True, timeout=120, check=False)

    def calls(self) -> str:
        path = self.out / "calls"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def metadata(self) -> dict:
        return json.loads((self.results / "run-metadata.json").read_text(encoding="utf-8"))

    def test_a_green_run_of_a_signed_package_records_what_was_tested(self) -> None:
        # GIVEN a package whose digest is in a SHA256SUMS signed by the maintainer key.
        # WHEN Complement is run against it and every test passes.
        result = self.run_script()
        # THEN the run succeeds and records the tested package, image and Complement.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        metadata = self.metadata()
        self.assertEqual(metadata["verification"], {"method": "gpg", "key": MAINTAINER_KEY})
        self.assertEqual(metadata["package"], {"name": PACKAGE_NAME, "sha256": self.digest})
        self.assertEqual(metadata["complement"]["commit"], COMMIT)
        self.assertEqual(metadata["go_version"], "go1.26.2")
        self.assertEqual(metadata["docker_version"], "27.1.0")
        self.assertTrue(metadata["image_id"].startswith("sha256:"))
        self.assertEqual(metadata["in_image_server_sha256"], SERVER_SHA)
        self.assertFalse(metadata["landlock_waived"])
        self.assertIsNone(metadata["run_filter"])
        self.assertEqual(json.loads((self.results / "summary.json").read_text(encoding="utf-8"))["verdict"], "pass")

    def test_the_image_is_built_from_the_verified_package_outside_the_source_tree(self) -> None:
        # GIVEN a signed package.
        # WHEN the run builds the image.
        result = self.run_script()
        # THEN the build gets exactly that package and its digest, and nothing
        # is written into tests/complement in the source tree.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.out / "built-package").read_text(encoding="utf-8").strip(), self.digest)
        self.assertIn(f"MEROVINGIAN_DEB_SHA256={self.digest}", self.calls())
        self.assertIn("Dockerfile", (self.out / "build-context").read_text(encoding="utf-8").split())
        self.assertFalse((REPO_ROOT / "tests" / "complement" / "artifact").exists())

    def test_complement_runs_the_built_image_at_the_pinned_commit(self) -> None:
        # GIVEN a signed package.
        # WHEN Complement is run.
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        go_env = dict(line.split("=", 1) for line in (self.out / "go-env").read_text(encoding="utf-8").splitlines())
        # THEN it fetches the pinned commit, and runs every test package with
        # JSON output against the image just built.
        self.assertIn(f"fetch --depth 1 origin {COMMIT}", self.calls())
        self.assertTrue(go_env["COMPLEMENT_BASE_IMAGE"].startswith("merovingian-complement:"))
        self.assertEqual(go_env["COMPLEMENT_SPAWN_HS_TIMEOUT_SECS"], "60")
        run_call = [line for line in self.calls().splitlines() if line.startswith("go test") and "-list" not in line]
        self.assertEqual(len(run_call), 1)
        self.assertIn("-json", run_call[0])
        self.assertIn("-count=1", run_call[0])
        self.assertTrue(run_call[0].endswith("./tests/..."))

    def test_the_verdict_is_the_summarisers_not_go_tests(self) -> None:
        # GIVEN go test exits 1, as it does whenever any test fails.
        # WHEN the only failure is listed as expected.
        self.write_run_log([event("run", "TestA"), event("fail", "TestA"), event("fail")])
        self.skip_list.write_text(textwrap.dedent("""\
            [[entry]]
            test = "TestA"
            package = "tests"
            mode = "expect-fail"
            category = "known-gap"
            reason = "Not implemented."
            todo = "docs/todos/capability-gaps.md"
            """), encoding="utf-8")
        listed = self.run_script()
        # THEN the run is green; an unlisted failure makes it red.
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        self.assertEqual(self.metadata()["go_test_exit_code"], 1)
        shutil.rmtree(self.results)
        self.skip_list.write_text("", encoding="utf-8")
        self.assertEqual(self.run_script().returncode, 1)

    def test_skip_entries_reach_go_test(self) -> None:
        # GIVEN a skip entry for a test that exists.
        self.skip_list.write_text(textwrap.dedent("""\
            [[entry]]
            test = "TestB"
            package = "tests"
            mode = "skip"
            category = "known-gap"
            reason = "Not implemented."
            todo = "docs/todos/capability-gaps.md"
            not_run_because = "It wedges the server for the tests after it."
            """), encoding="utf-8")
        self.listing.write_text(
            json.dumps({"Action": "output", "Package": TESTS, "Output": "TestB\n"}) + "\n", encoding="utf-8")
        # WHEN Complement is run.
        result = self.run_script()
        # THEN go test is told to skip it.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("-skip ^(TestB)$", self.calls())

    def test_a_package_not_in_the_signed_sums_is_refused_before_anything_is_built(self) -> None:
        # GIVEN SHA256SUMS that lists the package under a different digest.
        self.sums.write_text(f"{'1' * 64}  packages/{PACKAGE_NAME}\n", encoding="utf-8")
        # WHEN the run starts.
        result = self.run_script()
        # THEN it refuses before building an image or fetching Complement.
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("docker build", self.calls())
        self.assertNotIn("git ", self.calls())

    def test_a_package_missing_from_the_sums_is_refused(self) -> None:
        # GIVEN SHA256SUMS that does not list the package.
        self.sums.write_text(f"{self.digest}  packages/some-other.deb\n", encoding="utf-8")
        # WHEN the run starts.
        result = self.run_script()
        # THEN it refuses.
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("docker build", self.calls())

    def test_a_signature_that_does_not_verify_is_refused(self) -> None:
        cases = {
            "gpg fails": ("", "2"),
            "a bad signature": (f"[GNUPG:] BADSIG 92A3A264F0A7BE20 Maintainer\\n", "1"),
            "another key": (valid_status("F" * 40), "0"),
            "a revoked key": (valid_status() + "[GNUPG:] REVKEYSIG 92A3A264F0A7BE20 Maintainer\\n", "0"),
        }
        for name, (status, exit_code) in cases.items():
            with self.subTest(case=name):
                # GIVEN gpg reports that SHA256SUMS is not validly signed by the maintainer key.
                self.env["FAKE_GPG_STATUS"] = status
                self.env["FAKE_GPG_EXIT"] = exit_code
                shutil.rmtree(self.results, ignore_errors=True)
                (self.out / "calls").unlink(missing_ok=True)
                # WHEN the run starts.
                result = self.run_script()
                # THEN it refuses before building anything.
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("docker build", self.calls())

    def test_an_unsigned_package_runs_but_says_so(self) -> None:
        # GIVEN a locally built package with no signed sums.
        # WHEN Complement is run against it with --unsigned.
        result = self.run_script("--unsigned", signed=False)
        # THEN gpg is not consulted and the run records that the package was unverified.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("gpg ", self.calls())
        self.assertEqual(self.metadata()["verification"], {"method": "unsigned"})

    def test_unsigned_and_signed_inputs_are_not_mixed(self) -> None:
        # GIVEN --unsigned together with sums and a signature, or neither.
        for args, signed in ((("--unsigned",), True), ((), False)):
            with self.subTest(args=args, signed=signed):
                # WHEN the run starts.
                result = self.run_script(*args, signed=signed)
                # THEN it refuses: the caller must say which it means.
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(), "")

    def test_a_work_directory_that_is_not_empty_is_refused(self) -> None:
        # GIVEN a work directory left from an earlier run.
        self.results.mkdir()
        (self.results / "summary.json").write_text("{}", encoding="utf-8")
        # WHEN the run starts.
        result = self.run_script()
        # THEN it refuses rather than mix two runs' files.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), "")

    def test_a_go_older_than_complement_needs_is_refused(self) -> None:
        # GIVEN a Go toolchain older than the pinned commit's go.mod asks for.
        self.env["FAKE_GO_VERSION"] = "go1.25.9"
        # WHEN the run starts.
        result = self.run_script()
        # THEN it refuses before building anything.
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("docker build", self.calls())

    def test_a_checkout_at_another_commit_is_refused(self) -> None:
        # GIVEN a fetch that leaves a different commit checked out.
        self.env["FAKE_GIT_HEAD"] = "0" * 40
        # WHEN the run continues.
        result = self.run_script()
        # THEN it refuses before running any test.
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(line.startswith("go test") for line in self.calls().splitlines()))

    def test_the_landlock_waiver_reaches_the_container_only_when_asked(self) -> None:
        # GIVEN a run with the Landlock waiver.
        # WHEN Complement is run.
        result = self.run_script("--allow-without-landlock")
        # THEN Complement shares exactly the waiver with each container, and the run records it.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        go_env = dict(line.split("=", 1) for line in (self.out / "go-env").read_text(encoding="utf-8").splitlines())
        prefix = go_env["COMPLEMENT_SHARE_ENV_PREFIX"]
        self.assertEqual(go_env[f"{prefix}MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK"], "true")
        self.assertEqual([key for key in go_env if key.startswith(prefix)],
                         [f"{prefix}MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK"])
        self.assertTrue(self.metadata()["landlock_waived"])

    def test_without_the_waiver_nothing_is_shared(self) -> None:
        # GIVEN a run without the waiver.
        # WHEN Complement is run.
        result = self.run_script()
        # THEN no environment is shared with the containers.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("COMPLEMENT_SHARE_ENV_PREFIX", (self.out / "go-env").read_text(encoding="utf-8"))

    def test_a_filtered_run_is_recorded_as_partial(self) -> None:
        # GIVEN a run limited to some tests.
        # WHEN Complement is run with --run.
        result = self.run_script("--run", "TestA")
        # THEN go test gets the filter, and the run records it.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("-run TestA", self.calls())
        self.assertEqual(self.metadata()["run_filter"], "TestA")


if __name__ == "__main__":
    unittest.main()
