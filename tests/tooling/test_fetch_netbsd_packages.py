#!/usr/bin/env python3
"""scripts/fetch-netbsd-packages.py: the pure resolver and verifier. No test touches the network."""
from __future__ import annotations

import bz2
import gzip
import hashlib
import http.client
import importlib.util
import io
import lzma
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "fetch-netbsd-packages.py"

_spec = importlib.util.spec_from_file_location("fetch_netbsd_packages", SCRIPT)
fetch = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = fetch
_spec.loader.exec_module(fetch)

SUMMARY = """PKGNAME=clang-21.1.8nb1
DEPENDS=llvm-21.1.8{,nb*}
DEPENDS=perl>=5.0
DEPENDS=python{313,312}>=3.12
FILE_NAME=clang-21.1.8nb1.tgz
FILE_SIZE=10

PKGNAME=llvm-21.1.8nb1
FILE_NAME=llvm-21.1.8nb1.tgz
FILE_SIZE=20

PKGNAME=llvm-21.1.8
FILE_NAME=llvm-21.1.8.tgz
FILE_SIZE=20

PKGNAME=llvm-20.1.0
FILE_NAME=llvm-20.1.0.tgz
FILE_SIZE=20

PKGNAME=perl-5.40.0
DEPENDS=missing-dep>=1.0
FILE_NAME=perl-5.40.0.tgz
FILE_SIZE=30

PKGNAME=perl-5.8.9nb2
FILE_NAME=perl-5.8.9nb2.tgz
FILE_SIZE=30

PKGNAME=python313-3.13.15
FILE_NAME=python313-3.13.15.tgz
FILE_SIZE=40

PKGNAME=python312-3.12.1
FILE_NAME=python312-3.12.1.tgz
FILE_SIZE=40

PKGNAME=gdb-10.1nb6
FILE_NAME=gdb-10.1nb6.tgz
FILE_SIZE=50
"""


class BraceExpansionTests(unittest.TestCase):
    def test_empty_alternative_and_glob_suffix(self) -> None:
        # GIVEN pkgsrc's DEPENDS form for "this version, with or without a revision".
        # WHEN it is expanded THEN both spellings come back, in order.
        self.assertEqual(fetch.expand_braces("llvm-21.1.8{,nb*}"), ["llvm-21.1.8", "llvm-21.1.8nb*"])

    def test_no_braces_is_unchanged(self) -> None:
        self.assertEqual(fetch.expand_braces("clang"), ["clang"])

    def test_nested_and_multiple_groups(self) -> None:
        self.assertEqual(
            fetch.expand_braces("{a,b{1,2}}-x"),
            ["a-x", "b1-x", "b2-x"],
        )
        self.assertEqual(fetch.expand_braces("{a,b}{1,2}"), ["a1", "a2", "b1", "b2"])

    def test_unbalanced_braces_are_refused(self) -> None:
        with self.assertRaises(fetch.FetchError):
            fetch.expand_braces("a{b,c")


class DeweyTests(unittest.TestCase):
    def test_ordering(self) -> None:
        for lower, higher in (
            ("1.2", "1.10"),
            ("3.13.15", "3.13.15nb1"),
            ("21.1.8nb1", "21.1.8nb2"),
            ("1.0alpha1", "1.0beta1"),
            ("1.0rc1", "1.0"),
            ("1.0", "1.0pl1"),
            ("1.0a", "1.0b"),
            ("5.8.9nb2", "5.40.0"),
        ):
            with self.subTest(lower=lower, higher=higher):
                self.assertEqual(fetch.dewey_compare(lower, higher), -1)
                self.assertEqual(fetch.dewey_compare(higher, lower), 1)

    def test_trailing_zeros_are_equal(self) -> None:
        self.assertEqual(fetch.dewey_compare("1.0", "1"), 0)
        self.assertEqual(fetch.dewey_compare("2.5nb0", "2.5"), 0)


class MatchingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packages = fetch.parse_summary(SUMMARY)

    def names(self, pattern: str) -> str | None:
        found = fetch.best_match(pattern, self.packages)
        return found.pkgname if found else None

    def test_stem_picks_the_highest_version(self) -> None:
        self.assertEqual(self.names("llvm"), "llvm-21.1.8nb1")
        self.assertEqual(self.names("perl"), "perl-5.40.0")

    def test_dewey_bounds(self) -> None:
        self.assertEqual(self.names("llvm>=21.1.0"), "llvm-21.1.8nb1")
        self.assertEqual(self.names("llvm>=20<21"), "llvm-20.1.0")
        self.assertIsNone(self.names("llvm>=22"))
        self.assertEqual(self.names("perl<5.9"), "perl-5.8.9nb2")

    def test_glob_and_brace_patterns(self) -> None:
        self.assertEqual(self.names("llvm-21.1.8{,nb*}"), "llvm-21.1.8")
        self.assertEqual(self.names("llvm-2[0-9]*"), "llvm-21.1.8nb1")
        self.assertEqual(self.names("python{313,312}>=3.12"), "python313-3.13.15")

    def test_exact_pkgname(self) -> None:
        self.assertEqual(self.names("llvm-20.1.0"), "llvm-20.1.0")

    def test_unsafe_pattern_is_refused(self) -> None:
        for pattern in ("../etc", "a/b", "x;rm", "$(id)"):
            with self.subTest(pattern=pattern), self.assertRaises(fetch.FetchError):
                fetch.best_match(pattern, self.packages)


class ClosureTests(unittest.TestCase):
    def test_transitive_closure_and_unresolved(self) -> None:
        # GIVEN a summary where clang needs llvm, perl and python, and perl needs something absent.
        packages = fetch.parse_summary(SUMMARY)

        # WHEN the closure of clang is resolved, with gdb optional and a second absent optional.
        closure, unresolved = fetch.resolve_closure(["clang"], ["gdb", "nothere"], packages)

        # THEN every dependency is picked once at its best version, and what matched nothing is reported.
        self.assertEqual(
            [p.pkgname for p in closure],
            ["clang-21.1.8nb1", "gdb-10.1nb6", "llvm-21.1.8", "perl-5.40.0", "python313-3.13.15"],
        )
        self.assertEqual(unresolved, ["missing-dep>=1.0", "nothere"])

    def test_missing_requested_package_fails(self) -> None:
        with self.assertRaises(fetch.FetchError):
            fetch.resolve_closure(["nothere"], [], fetch.parse_summary(SUMMARY))

    def test_cycles_terminate(self) -> None:
        packages = fetch.parse_summary(
            "PKGNAME=a-1\nDEPENDS=b>=1\nFILE_NAME=a-1.tgz\n\nPKGNAME=b-1\nDEPENDS=a>=1\nFILE_NAME=b-1.tgz\n"
        )
        closure, _ = fetch.resolve_closure(["a"], [], packages)
        self.assertEqual([p.pkgname for p in closure], ["a-1", "b-1"])


class VerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "x-1.tgz"

    def package(self, data: bytes, cksum: str | None = None, size: int | None = -1) -> object:
        return fetch.Package("x-1", "x-1.tgz", len(data) if size == -1 else size, cksum)

    def test_each_compression_passes(self) -> None:
        for compress in (gzip.compress, lzma.compress, bz2.compress):
            data = compress(b"payload" * 100)
            self.path.write_bytes(data)
            self.assertIsNone(fetch.verify_file(self.path, self.package(data)), compress.__module__)

    def test_size_mismatch(self) -> None:
        data = gzip.compress(b"payload")
        self.path.write_bytes(data)
        self.assertIn("size", fetch.verify_file(self.path, self.package(data, size=len(data) + 1)))

    def test_truncated_archive_is_rejected(self) -> None:
        data = lzma.compress(b"payload" * 10000)
        self.path.write_bytes(data[:-20])
        self.assertIsNotNone(fetch.verify_file(self.path, self.package(data[:-20])))

    def test_unknown_format_is_rejected(self) -> None:
        self.path.write_bytes(b"not an archive")
        self.assertIn("unknown compression", fetch.verify_file(self.path, self.package(b"not an archive")))

    def test_checksum_match_and_mismatch(self) -> None:
        data = gzip.compress(b"payload")
        self.path.write_bytes(data)
        good = "SHA512 " + hashlib.sha512(data).hexdigest()
        bad = "SHA256 " + "0" * 64
        self.assertIsNone(fetch.verify_file(self.path, self.package(data, good)))
        self.assertIn("mismatch", fetch.verify_file(self.path, self.package(data, bad)))
        self.assertIn("unsupported", fetch.verify_file(self.path, self.package(data, "MD5 abcd")))


class SyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "pkgs"
        self.data = gzip.compress(b"payload")
        self.package = fetch.Package("x-1", "x-1.tgz", len(self.data), None)

    def fake_download(self, payloads: list[bytes]):
        calls = []

        def download(bases, package, target, attempts, timeout):  # noqa: ANN001
            calls.append(package.file_name)
            target.write_bytes(payloads[min(len(calls), len(payloads)) - 1])

        return calls, download

    def test_cached_good_file_is_reused_and_stale_files_pruned(self) -> None:
        self.output.mkdir()
        (self.output / "x-1.tgz").write_bytes(self.data)
        (self.output / "old-0.tgz").write_bytes(b"old")
        calls, download = self.fake_download([self.data])
        with mock.patch.object(fetch, "download_package", download):
            result = fetch.sync_directory(self.output, [self.package], [], 1, 1)
        self.assertEqual(result, (0, 1, 1))
        self.assertEqual(calls, [])
        self.assertEqual([p.name for p in self.output.iterdir()], ["x-1.tgz"])

    def test_corrupt_cached_file_is_downloaded_again(self) -> None:
        self.output.mkdir()
        (self.output / "x-1.tgz").write_bytes(b"corrupt")
        calls, download = self.fake_download([self.data])
        with mock.patch.object(fetch, "download_package", download):
            result = fetch.sync_directory(self.output, [self.package], [], 1, 1)
        self.assertEqual(result, (1, 0, 0))
        self.assertEqual((self.output / "x-1.tgz").read_bytes(), self.data)

    def test_one_bad_download_is_retried_once(self) -> None:
        calls, download = self.fake_download([b"bad", self.data])
        with mock.patch.object(fetch, "download_package", download):
            result = fetch.sync_directory(self.output, [self.package], [], 1, 1)
        self.assertEqual(result, (1, 0, 0))
        self.assertEqual(len(calls), 2)

    def test_second_bad_download_fails_and_leaves_nothing(self) -> None:
        calls, download = self.fake_download([b"bad", b"worse"])
        with mock.patch.object(fetch, "download_package", download), self.assertRaises(fetch.FetchError):
            fetch.sync_directory(self.output, [self.package], [], 1, 1)
        self.assertFalse((self.output / "x-1.tgz").exists())


class RefusalTests(unittest.TestCase):
    def run_script(self, *arguments: str) -> int:
        with mock.patch.object(fetch, "fetch_summary", side_effect=AssertionError("must refuse before the network")):
            try:
                return fetch.run(list(arguments))
            except fetch.FetchError:
                return 1

    def base(self, *extra: str) -> list[str]:
        return ["--release", "11.0", "--arch", "amd64", "--output-dir", "out", "--lockfile", "lock", *extra]

    def test_names_with_slash_or_dotdot_are_refused(self) -> None:
        for name in ("a/b", "..", "a..b", "a\\b", "a b"):
            with self.subTest(name=name):
                self.assertEqual(self.run_script(*self.base(name)), 1)

    def test_odd_release_arch_mirror_and_output_are_refused(self) -> None:
        self.assertEqual(self.run_script("--release", "11/../x", "--arch", "amd64", "--output-dir", "o", "--lockfile", "l", "a"), 1)
        self.assertEqual(self.run_script(*self.base("--mirror", "evil.example/x", "a")), 1)
        self.assertEqual(self.run_script("--release", "11.0", "--arch", "amd64", "--output-dir", "../o", "--lockfile", "l", "a"), 1)

    def test_non_https_url_is_refused(self) -> None:
        with self.assertRaises(fetch.FetchError):
            fetch.http_get("http://cdn.netbsd.org/x", mock.Mock(), 10, 1)


class _FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, length: str | None) -> None:
        super().__init__(body)
        self.headers = {} if length is None else {"Content-Length": length}


class HttpGetTests(unittest.TestCase):
    def get(self, body: bytes, length: str | None) -> bytes:
        opener = mock.Mock()
        opener.open.return_value = _FakeResponse(body, length)
        destination = io.BytesIO()
        with mock.patch.object(fetch, "_OPENER", opener):
            fetch.http_get("https://cdn.netbsd.org/x", destination, 1024, 1)
        return destination.getvalue()

    def test_a_body_of_the_announced_length_is_kept(self) -> None:
        # GIVEN a response whose body matches its Content-Length.
        # THEN every byte is written.
        self.assertEqual(self.get(b"abcdef", "6"), b"abcdef")

    def test_a_body_without_a_length_is_kept(self) -> None:
        # GIVEN a chunked response, which announces no length.
        # THEN the body is written; verification against pkg_summary still checks it.
        self.assertEqual(self.get(b"abc", None), b"abc")

    def test_a_body_shorter_than_its_content_length_fails(self) -> None:
        # GIVEN a connection that drops after part of a fixed-length body, which http.client
        # reports as a normal end of stream.
        # THEN the download fails, so the caller tries the next mirror.
        with self.assertRaisesRegex(fetch.FetchError, "ended after 3 of 6 bytes"):
            self.get(b"abc", "6")

    def test_an_http_protocol_error_is_retried(self) -> None:
        # GIVEN an action that raises http.client's own exception type, which is not an OSError.
        calls: list[int] = []

        def action() -> str:
            calls.append(1)
            if len(calls) == 1:
                raise http.client.IncompleteRead(b"")
            return "done"

        # THEN with_retries treats it as a failed attempt, not a crash.
        with mock.patch.object(fetch.time, "sleep"):
            self.assertEqual(fetch.with_retries(action, "x", 2, 0), "done")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
