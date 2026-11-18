#!/usr/bin/env python3
"""scripts/fetch-netbsd-packages.py: the pure resolver and verifier. No test touches the network."""
from __future__ import annotations

import bz2
import contextlib
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
            ("1.0a", "1.0.2"),
            ("5.8.9nb2", "5.40.0"),
        ):
            with self.subTest(lower=lower, higher=higher):
                self.assertEqual(fetch.dewey_compare(lower, higher), -1)
                self.assertEqual(fetch.dewey_compare(higher, lower), 1)

    def test_a_letter_after_digits_is_two_components(self) -> None:
        # GIVEN NetBSD's dewey.c, where 1.0a is 1.0.0.1, which is less than 1.0.2.
        packages = fetch.parse_summary("PKGNAME=lib-1.0a\nFILE_NAME=lib-1.0a.tgz\nFILE_SIZE=1\n")
        # WHEN lib>=1.0.2 is matched THEN lib-1.0a is not a candidate.
        self.assertIsNone(fetch.best_match("lib>=1.0.2", packages))
        self.assertEqual(fetch.best_match("lib>=1.0", packages).pkgname, "lib-1.0a")

    def test_patch_is_not_a_modifier(self) -> None:
        # GIVEN NetBSD's dewey.c, which knows alpha, beta, pre, rc and pl, so "patch" is the letters p, a, t, c, h.
        packages = fetch.parse_summary(
            "PKGNAME=x-1.0patch20\nFILE_NAME=x-1.0patch20.tgz\nFILE_SIZE=1\n\n"
            "PKGNAME=x-1.0q1\nFILE_NAME=x-1.0q1.tgz\nFILE_SIZE=1\n"
        )
        # WHEN the versions are compared and matched
        order = fetch.dewey_compare("1.0patch20", "1.0q1")
        best = fetch.best_match("x", packages)
        # THEN 1.0patch20 sorts below 1.0q1 (p < q) and the stem picks x-1.0q1.
        self.assertEqual(order, -1)
        self.assertEqual(best.pkgname, "x-1.0q1")

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

    def test_a_fresh_download_is_not_verified_again(self) -> None:
        # GIVEN a download_package that has already verified what it moved into place.
        calls, download = self.fake_download([self.data])
        # WHEN the directory is synced
        with mock.patch.object(fetch, "download_package", download), mock.patch.object(fetch, "verify_file") as verify:
            result = fetch.sync_directory(self.output, [self.package], [], 1, 1)
        # THEN the file is kept and verify_file was not called again.
        self.assertEqual(result, (1, 0, 0))
        self.assertEqual(calls, ["x-1.tgz"])
        verify.assert_not_called()

    def test_a_download_that_cannot_be_verified_fails_and_leaves_nothing(self) -> None:
        # GIVEN a download_package that gives up.
        def download(bases, package, target, attempts, timeout):  # noqa: ANN001
            raise fetch.FetchError("no mirror served a verified file")

        # WHEN the directory is synced THEN the error propagates and no file is left.
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


DAMAGED_GZIP = bytes([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3]) + b"\xff" * 16  # an invalid deflate block: zlib.error


class ZlibErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_damaged_deflate_data_fails_verification(self) -> None:
        # GIVEN a gzip file whose deflate data is damaged, which gzip reports as zlib.error.
        path = self.root / "x-1.tgz"
        path.write_bytes(DAMAGED_GZIP)
        package = fetch.Package("x-1", "x-1.tgz", len(DAMAGED_GZIP), None)
        # WHEN it is verified THEN that is a rejection, not a crash.
        self.assertIn("not a complete compressed archive", fetch.verify_file(path, package))

    def test_damaged_cached_package_is_downloaded_again(self) -> None:
        # GIVEN a cached package with damaged deflate data and a good download.
        good = gzip.compress(b"payload")
        output = self.root / "pkgs"
        output.mkdir()
        (output / "x-1.tgz").write_bytes(DAMAGED_GZIP)
        package = fetch.Package("x-1", "x-1.tgz", None, None)  # no size, so only the stream check can reject it

        def download(bases, package, target, attempts, timeout):  # noqa: ANN001
            target.write_bytes(good)

        # WHEN the directory is synced THEN the damaged copy is replaced.
        with mock.patch.object(fetch, "download_package", download):
            result = fetch.sync_directory(output, [package], [], 1, 1)
        self.assertEqual(result, (1, 0, 0))
        self.assertEqual((output / "x-1.tgz").read_bytes(), good)

    def test_damaged_summary_makes_the_next_format_be_tried(self) -> None:
        # GIVEN a mirror whose pkg_summary.gz is damaged and whose pkg_summary.bz2 is fine.
        def get(url, destination, limit, timeout, deadline=900.0):  # noqa: ANN001
            if url.endswith("pkg_summary.gz"):
                destination.write(DAMAGED_GZIP)
            elif url.endswith("pkg_summary.bz2"):
                destination.write(bz2.compress(SUMMARY.encode()))
            else:
                raise fetch.FetchError("not found")

        # WHEN the summary is fetched THEN the bz2 one is used.
        with mock.patch.object(fetch, "http_get", get), contextlib.redirect_stderr(io.StringIO()):
            packages = fetch.fetch_summary(["https://a/"], None, 1, 1)
        self.assertIn("clang-21.1.8nb1", [p.pkgname for p in packages])


class SummaryRootsTests(unittest.TestCase):
    WITHOUT = "PKGNAME=perl-5.40.0\nFILE_NAME=perl-5.40.0.tgz\nFILE_SIZE=3\n"
    CLANG_NO_SIZE = "PKGNAME=clang-1\nFILE_NAME=clang-1.tgz\n"
    CLANG = "PKGNAME=clang-1\nFILE_NAME=clang-1.tgz\nFILE_SIZE=5\n"
    CLANG_BAD_SIZE = "PKGNAME=clang-1\nFILE_NAME=clang-1.tgz\nFILE_SIZE=\u00b2\n"

    def serving(self, texts: dict[str, str]):
        def get(url, destination, limit, timeout, deadline=900.0):  # noqa: ANN001
            if url in texts:
                destination.write(gzip.compress(texts[url].encode()))
            else:
                raise fetch.FetchError("not found")

        return get

    def fetch(self, texts: dict[str, str], bases: list[str], summary_file: Path | None, required: list[str]):
        with mock.patch.object(fetch, "http_get", self.serving(texts)), contextlib.redirect_stderr(io.StringIO()):
            return fetch.fetch_summary(bases, summary_file, 1, 1, required)

    def test_a_summary_without_a_required_package_is_not_kept(self) -> None:
        # GIVEN a first mirror whose summary lacks clang and a second that has it.
        texts = {"https://a/pkg_summary.gz": self.WITHOUT, "https://b/pkg_summary.gz": SUMMARY}
        with tempfile.TemporaryDirectory() as directory:
            summary_file = Path(directory) / "summary.txt"
            # WHEN the summary is fetched with clang required.
            packages = self.fetch(texts, ["https://a/", "https://b/"], summary_file, ["clang"])
            # THEN the second mirror's summary is the one used and the one written.
            self.assertIn("clang-21.1.8nb1", [p.pkgname for p in packages])
            self.assertEqual(summary_file.read_text(encoding="utf-8"), SUMMARY)

    def test_no_candidate_with_the_required_package_fails_and_writes_nothing(self) -> None:
        # GIVEN a single mirror whose summary lacks clang.
        texts = {"https://a/pkg_summary.gz": self.WITHOUT}
        with tempfile.TemporaryDirectory() as directory:
            summary_file = Path(directory) / "summary.txt"
            # WHEN the summary is fetched with clang required THEN it fails and writes nothing.
            with self.assertRaisesRegex(fetch.FetchError, "required clang"):
                self.fetch(texts, ["https://a/"], summary_file, ["clang"])
            self.assertFalse(summary_file.exists())

    def test_a_cached_summary_missing_a_required_package_falls_back_to_a_mirror(self) -> None:
        # GIVEN a cached summary file without clang and a mirror that has it.
        texts = {"https://a/pkg_summary.gz": SUMMARY}
        with tempfile.TemporaryDirectory() as directory:
            summary_file = Path(directory) / "summary.txt"
            summary_file.write_text(self.WITHOUT, encoding="utf-8")
            # WHEN the summary is fetched with clang required
            packages = self.fetch(texts, ["https://a/"], summary_file, ["clang"])
            # THEN the mirror is used and its summary overwrites the cached one.
            self.assertIn("clang-21.1.8nb1", [p.pkgname for p in packages])
            self.assertEqual(summary_file.read_text(encoding="utf-8"), SUMMARY)

    def test_a_cached_summary_that_does_not_parse_is_ignored(self) -> None:
        # GIVEN a cached summary file with a FILE_SIZE that is a digit to isdigit but not to int.
        texts = {"https://a/pkg_summary.gz": self.CLANG}
        with tempfile.TemporaryDirectory() as directory:
            summary_file = Path(directory) / "summary.txt"
            summary_file.write_text(self.CLANG_BAD_SIZE, encoding="utf-8")
            # WHEN the summary is fetched THEN the mirror is used instead of crashing.
            packages = self.fetch(texts, ["https://a/"], summary_file, ["clang"])
            self.assertEqual(packages[0].file_size, 5)
            self.assertEqual(summary_file.read_text(encoding="utf-8"), self.CLANG)

    def test_a_required_package_without_file_size_makes_the_next_candidate_be_used(self) -> None:
        # GIVEN a first mirror whose clang has no FILE_SIZE and a second whose clang has one.
        texts = {"https://a/pkg_summary.gz": self.CLANG_NO_SIZE, "https://b/pkg_summary.gz": self.CLANG}
        with tempfile.TemporaryDirectory() as directory:
            summary_file = Path(directory) / "summary.txt"
            # WHEN the summary is fetched with clang required
            packages = self.fetch(texts, ["https://a/", "https://b/"], summary_file, ["clang"])
            # THEN the second mirror's summary is used and written.
            self.assertEqual(packages[0].file_size, 5)
            self.assertEqual(summary_file.read_text(encoding="utf-8"), self.CLANG)

    def test_a_file_size_that_does_not_parse_is_a_failed_candidate(self) -> None:
        # GIVEN a first mirror with FILE_SIZE of a superscript two (isdigit true, int fails) and a second with a good summary.
        texts = {"https://a/pkg_summary.gz": self.CLANG_BAD_SIZE, "https://b/pkg_summary.gz": self.CLANG}
        # WHEN the summary is fetched
        packages = self.fetch(texts, ["https://a/", "https://b/"], None, ["clang"])
        # THEN the second candidate is used, not a crash.
        self.assertEqual(packages[0].file_size, 5)

    def test_every_candidate_failing_the_closure_check_fails(self) -> None:
        # GIVEN one mirror whose required package has no FILE_SIZE.
        texts = {"https://a/pkg_summary.gz": self.CLANG_NO_SIZE}
        # WHEN the summary is fetched THEN it fails and names the missing size.
        with self.assertRaisesRegex(fetch.FetchError, "FILE_SIZE"):
            self.fetch(texts, ["https://a/"], None, ["clang"])


class MirrorFallbackTests(unittest.TestCase):
    def test_a_file_that_fails_verification_moves_on_to_the_next_mirror(self) -> None:
        # GIVEN a first mirror serving a wrong-size file and a second serving the right one.
        good = gzip.compress(b"payload" * 10)
        package = fetch.Package("x-1", "x-1.tgz", len(good), None)

        def get(url, destination, limit, timeout, deadline=900.0):  # noqa: ANN001
            destination.write(good + b"extra" if url.startswith("https://a/") else good)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "x-1.tgz"
            bases = ["https://a/", "https://b/"]
            # WHEN the package is downloaded.
            with mock.patch.object(fetch, "http_get", get), contextlib.redirect_stderr(io.StringIO()):
                fetch.download_package(bases, package, target, 1, 1)
            # THEN the second mirror's file is kept, the partial is gone and the first mirror is rotated last.
            self.assertEqual(target.read_bytes(), good)
            self.assertFalse(target.with_name("x-1.tgz.part").exists())
            self.assertEqual(bases, ["https://b/", "https://a/"])


class RunTests(unittest.TestCase):
    DATA = gzip.compress(b"payload")

    def summary(self, size: str | None = None) -> str:
        size = str(len(self.DATA)) if size is None else size
        size_line = f"FILE_SIZE={size}\n" if size else ""
        return (
            f"PKGNAME=clang-1\nDEPENDS=zlib>=1\nFILE_NAME=clang-1.tgz\n{size_line}\n"
            f"PKGNAME=zlib-1\nFILE_NAME=zlib-1.tgz\nFILE_SIZE={len(self.DATA)}\n\n"
            f"PKGNAME=gdb-1\nDEPENDS=zlib>=1\nDEPENDS=gdbdep>=1\nFILE_NAME=gdb-1.tgz\n{size_line}\n"
            f"PKGNAME=gdbdep-1\nFILE_NAME=gdbdep-1.tgz\nFILE_SIZE={len(self.DATA)}\n"
        )

    def arguments(self, root: Path, *extra: str) -> list[str]:
        return [
            "--release", "11.0", "--arch", "amd64", "--output-dir", str(root / "out"),
            "--lockfile", str(root / "lock"), *extra,
        ]

    def temp_root(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def run_with(self, failing: dict[str, Exception], *extra: str) -> tuple[int, str, Path]:
        root = self.temp_root()

        def download(bases, package, target, attempts, timeout):  # noqa: ANN001
            if package.file_name in failing:
                target.with_name(target.name + ".part").write_bytes(b"partial")
                raise failing[package.file_name]
            target.write_bytes(self.DATA)

        errors = io.StringIO()
        with (
            mock.patch.object(fetch, "fetch_summary", return_value=fetch.parse_summary(self.summary())),
            mock.patch.object(fetch, "download_package", download),
            contextlib.redirect_stderr(errors),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = fetch.run(self.arguments(root, *extra))
        return code, errors.getvalue(), root

    def test_an_optional_only_failure_is_a_warning(self) -> None:
        # GIVEN gdb optional, and a download failure for gdb's own dependency.
        # WHEN the run syncs
        code, errors, root = self.run_with({"gdbdep-1.tgz": fetch.FetchError("down")}, "--optional", "gdb", "clang")
        # THEN the run succeeds, warns, and leaves no optional-only file behind.
        self.assertEqual(code, 0)
        self.assertIn("warning: optional package gdbdep-1.tgz", errors)
        names = sorted(p.name for p in (root / "out").iterdir())
        self.assertEqual(names, ["clang-1.tgz", "gdb-1.tgz", "zlib-1.tgz"])

    def test_an_optional_download_failure_leaves_a_lockfile_without_that_package(self) -> None:
        # GIVEN gdb optional, and a download failure for gdb's own dependency.
        # WHEN the run syncs
        code, _, root = self.run_with({"gdbdep-1.tgz": fetch.FetchError("down")}, "--optional", "gdb", "clang")
        # THEN the lockfile names what the directory holds, so the cache is saved under the right key.
        size = len(self.DATA)
        self.assertEqual(code, 0)
        self.assertEqual(
            (root / "lock").read_text(encoding="utf-8"),
            f"clang-1.tgz {size} -\ngdb-1.tgz {size} -\nzlib-1.tgz {size} -\n",
        )

    def test_success_leaves_the_lockfile_whole(self) -> None:
        # GIVEN gdb optional and every download succeeding.
        # WHEN the run syncs
        code, _, root = self.run_with({}, "--optional", "gdb", "clang")
        # THEN the lockfile lists every package, including the optional ones.
        size = len(self.DATA)
        self.assertEqual(code, 0)
        self.assertEqual(
            (root / "lock").read_text(encoding="utf-8"),
            f"clang-1.tgz {size} -\ngdb-1.tgz {size} -\ngdbdep-1.tgz {size} -\nzlib-1.tgz {size} -\n",
        )

    def test_a_dependency_shared_with_the_required_closure_stays_mandatory(self) -> None:
        # GIVEN zlib needed by both clang and the optional gdb, and zlib failing to download.
        error = fetch.FetchError("zlib down")
        # WHEN the run syncs THEN that same error propagates.
        with self.assertRaises(fetch.FetchError) as caught:
            self.run_with({"zlib-1.tgz": error}, "--optional", "gdb", "clang")
        self.assertIs(caught.exception, error)

    def test_a_required_failure_is_fatal(self) -> None:
        # GIVEN clang itself failing to download.
        error = fetch.FetchError("clang down")
        # WHEN the run syncs THEN that same error propagates.
        with self.assertRaises(fetch.FetchError) as caught:
            self.run_with({"clang-1.tgz": error}, "--optional", "gdb", "clang")
        self.assertIs(caught.exception, error)

    def test_an_optional_only_package_without_file_size_is_dropped_with_a_warning(self) -> None:
        # GIVEN gdb, which only the optional list needs, with no FILE_SIZE, and clang with one.
        root = self.temp_root()
        text = self.summary(size="").replace("PKGNAME=clang-1\n", "PKGNAME=clang-1\nFILE_SIZE=1\n")
        packages = fetch.parse_summary(text)
        errors = io.StringIO()
        # WHEN the run resolves
        with (
            mock.patch.object(fetch, "fetch_summary", return_value=packages),
            contextlib.redirect_stderr(errors),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = fetch.run(self.arguments(root, "--resolve-only", "--optional", "gdb", "clang"))
        # THEN the run succeeds, warns, and the lockfile lacks gdb.
        self.assertEqual(code, 0)
        self.assertIn("warning: optional package gdb-1.tgz dropped", errors.getvalue())
        self.assertNotIn("gdb-1.tgz", (root / "lock").read_text(encoding="utf-8"))

    def test_a_package_without_file_size_fails_before_the_lockfile(self) -> None:
        # GIVEN clang with no FILE_SIZE.
        root = self.temp_root()
        packages = fetch.parse_summary(self.summary(size=""))
        # WHEN the run resolves THEN it fails and writes no lockfile.
        with mock.patch.object(fetch, "fetch_summary", return_value=packages), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(fetch.FetchError, "FILE_SIZE"):
                fetch.run(self.arguments(root, "--resolve-only", "clang"))
        self.assertFalse((root / "lock").exists())

    def test_lockfile_lines_carry_size_and_checksum(self) -> None:
        # GIVEN one package with FILE_CKSUM and one without (NetBSD 11.0 publishes none).
        packages = fetch.parse_summary(
            "PKGNAME=a-1\nFILE_NAME=a-1.tgz\nFILE_SIZE=10\nFILE_CKSUM=SHA512 abcd\n\n"
            "PKGNAME=b-1\nFILE_NAME=b-1.tgz\nFILE_SIZE=20\n"
        )
        # WHEN the lockfile text is built
        text = fetch.lockfile_text(packages)
        # THEN each line is name, size and checksum or a dash.
        self.assertEqual(text, "a-1.tgz 10 SHA512 abcd\nb-1.tgz 20 -\n")

    def test_resolve_only_writes_the_content_lockfile_and_downloads_nothing(self) -> None:
        # GIVEN a summary and a sync_directory that must not run.
        root = self.temp_root()
        packages = fetch.parse_summary(self.summary())
        # WHEN the run resolves only
        with (
            mock.patch.object(fetch, "fetch_summary", return_value=packages),
            mock.patch.object(fetch, "sync_directory") as sync,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = fetch.run(self.arguments(root, "--resolve-only", "clang"))
        # THEN the lockfile has size and no checksum for each package, and nothing was synced.
        size = len(self.DATA)
        self.assertEqual(code, 0)
        self.assertEqual((root / "lock").read_text(encoding="utf-8"), f"clang-1.tgz {size} -\nzlib-1.tgz {size} -\n")
        sync.assert_not_called()


if __name__ == "__main__":
    unittest.main()
