#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""CI only: downloads NetBSD binary packages on the Linux host runner, before the VM starts.

The NetBSD VMs reach the package mirrors through QEMU user-mode NAT, which is slow and drops
connections; pkg_add inside the guest then paid a multi-minute timeout per failure and the
dependency install took about 100 minutes. The host runner has a fast, stable network. This
script resolves the transitive closure of the requested packages from the mirror's
pkg_summary, downloads every .tgz into one directory inside the workspace (which the VM
action syncs into the guest) and verifies it. The guest installs from that directory alone
first, and from the directory plus each mirror only if that fails, so anything the resolver
missed still comes from the network (ADR-0844).

Which pkg_summary: the cached one, else each mirror's gz, bz2 and xz in turn. A candidate must
decode to at most MAX_DECODED_SUMMARY_BYTES, list every required package, and give a FILE_SIZE
for every package in the required closure; one that fails is skipped. The first candidate whose
required closure resolves completely is used. When none does, the first that passed the other
checks is used, with a warning naming the dependencies the guest must take from the mirrors.

Trust: HTTPS only. Requests go to the configured mirrors; a redirect from a mirror to another host
is followed when the target is HTTPS, as pkg_add itself does, and a redirect to anything but HTTPS is
refused. Integrity rests on three checks, made on every run for every file, whether just downloaded
(verified once, inside the download) or restored from the CI cache: FILE_SIZE from pkg_summary
(required for the required closure; an optional-only package without one is dropped), a full read
of the compressed stream (gzip, xz or bzip2), which checks its integrity trailer, and FILE_CKSUM
when the repository publishes one. NetBSD 11.0 publishes no FILE_CKSUM, so nothing authenticates
an archive beyond what pkg_add had before. A file that fails is deleted and downloaded again (from the next mirror when it failed on download); a file no mirror serves verified fails the run.

Optional packages (--optional) are best-effort: the required closure is downloaded first and any
failure there fails the run; a failure in the packages only the optional ones need is a warning.

Package names and file names are never interpolated into a shell. Names containing '/', '..'
or characters outside the package-name alphabet are refused.

Usage:
  fetch-netbsd-packages.py --release 11.0 --arch amd64 --output-dir DIR --lockfile FILE \\
      [--mirror HOST ...] [--summary-file FILE] [--optional NAME ...] [--resolve-only] PACKAGE ...
"""

from __future__ import annotations

import argparse
import http.client
import bz2
import fnmatch
import gzip
import hashlib
import io
import lzma
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MIRRORS = ("cdn.netbsd.org", "ftp.netbsd.org")
# Each format with a factory for a streaming decompressor, so the decoded size can be bounded.
SUMMARY_NAMES = (
    ("pkg_summary.gz", lambda: zlib.decompressobj(wbits=31)),
    ("pkg_summary.bz2", bz2.BZ2Decompressor),
    ("pkg_summary.xz", lzma.LZMADecompressor),
)
# Package names, patterns and file names: pkgsrc's alphabet plus the pattern syntax. No '/'.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+\-]*$")
SAFE_PATTERN = re.compile(r"^[A-Za-z0-9_.+\-\[\]\*\?\{\},<>=!]+$")
SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+\-]*\.tgz$")
SAFE_RELEASE = re.compile(r"^[0-9]+(\.[0-9]+)*$")
SAFE_ARCH = re.compile(r"^[a-z0-9_]+$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")
GZIP_MAGIC = bytes([0x1F, 0x8B])
XZ_MAGIC = bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
MAX_SUMMARY_BYTES = 256 * 1024 * 1024
# The decoded pkg_summary is a few tens of MiB; a compressed file this small must not inflate past this.
MAX_DECODED_SUMMARY_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024


class FetchError(Exception):
    """A condition that fails the step."""


# ---------------------------------------------------------------- pure resolution helpers


def expand_braces(pattern: str) -> list[str]:
    """Expands csh-style braces, as pkgsrc DEPENDS uses: `llvm-21{,nb*}` -> `llvm-21`, `llvm-21nb*`."""
    start = pattern.find("{")
    if start < 0:
        return [pattern]
    depth = 0
    end = -1
    cuts = [start]
    for index in range(start, len(pattern)):
        char = pattern[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
        elif char == "," and depth == 1:
            cuts.append(index)
    if end < 0:
        raise FetchError(f"unbalanced braces in pattern {pattern!r}")
    cuts.append(end)
    prefix, suffix = pattern[:start], pattern[end + 1 :]
    result: list[str] = []
    for left, right in zip(cuts, cuts[1:]):
        for inner in expand_braces(pattern[left + 1 : right]):
            for tail in expand_braces(suffix):
                result.append(prefix + inner + tail)
    return result


# pkg_install's dewey.c (mkcomponent) matches the modifiers, "nb" and single letters with strncasecmp and
# tolower, so every one of them is case-insensitive. It knows exactly these modifiers; "patch" is the
# letters p, a, t, c, h. "nb" takes any number of digits (none is 0) and may appear anywhere.
_MODIFIERS = {"alpha": -3, "beta": -2, "pre": -1, "rc": -1, "pl": 0}
_TOKEN = re.compile(r"[0-9]+|alpha|beta|pre|rc|pl|nb[0-9]*|[a-z]|[._]", re.IGNORECASE | re.ASCII)


def _version_parts(version: str) -> tuple[list[int], int]:
    revision = 0
    parts: list[int] = []
    for token in _TOKEN.findall(version):
        lowered = token.lower()
        if token.isdigit():
            parts.append(int(token))
        elif lowered in _MODIFIERS:
            parts.append(_MODIFIERS[lowered])
        elif lowered.startswith("nb"):
            revision = int(lowered[2:] or "0")
        elif token in "._":
            parts.append(0)
        else:
            # pkg_install's dewey.c: a letter is two components, 0 then its ordinal, so 1.0a is 1.0.0.1.
            parts.append(0)
            parts.append(ord(lowered) - ord("a") + 1)
    return parts, revision


def dewey_compare(left: str, right: str) -> int:
    """pkg_install-style version comparison: -1, 0 or 1."""
    left_parts, left_revision = _version_parts(left)
    right_parts, right_revision = _version_parts(right)
    length = max(len(left_parts), len(right_parts))
    left_parts += [0] * (length - len(left_parts))
    right_parts += [0] * (length - len(right_parts))
    for a, b in zip(left_parts + [left_revision], right_parts + [right_revision]):
        if a != b:
            return -1 if a < b else 1
    return 0


def split_pkgname(pkgname: str) -> tuple[str, str]:
    """`clang-21.1.8nb1` -> (`clang`, `21.1.8nb1`)."""
    base, separator, version = pkgname.rpartition("-")
    if not separator or not base or not version:
        raise FetchError(f"not a package name: {pkgname!r}")
    return base, version


@dataclass(frozen=True)
class Package:
    pkgname: str
    file_name: str
    file_size: int | None
    file_cksum: str | None
    depends: tuple[str, ...] = field(default=())

    @property
    def base(self) -> str:
        return split_pkgname(self.pkgname)[0]

    @property
    def version(self) -> str:
        return split_pkgname(self.pkgname)[1]


def parse_summary(text: str) -> list[Package]:
    """Parses pkg_summary(5): blank-line separated records of KEY=VALUE lines."""
    packages: list[Package] = []
    for record in text.split("\n\n"):
        values: dict[str, list[str]] = {}
        for line in record.split("\n"):
            key, separator, value = line.partition("=")
            if separator:
                values.setdefault(key, []).append(value)
        if "PKGNAME" not in values:
            continue
        pkgname = values["PKGNAME"][0]
        size = values.get("FILE_SIZE", [""])[0]
        file_size: int | None = None
        if size.isdigit():
            try:
                file_size = int(size)
            except ValueError:  # str.isdigit is true for characters int() refuses, such as a superscript two
                file_size = None
        packages.append(
            Package(
                pkgname=pkgname,
                file_name=values.get("FILE_NAME", [pkgname + ".tgz"])[0],
                file_size=file_size,
                file_cksum=values.get("FILE_CKSUM", [None])[0],
                depends=tuple(values.get("DEPENDS", [])),
            )
        )
    return packages


_DEWEY = re.compile(r"(<=|>=|<|>)([^<>=]+)")


def _dewey_matches(version: str, constraints: list[tuple[str, str]]) -> bool:
    for operator, bound in constraints:
        order = dewey_compare(version, bound)
        if not {"<": order < 0, "<=": order <= 0, ">": order > 0, ">=": order >= 0}[operator]:
            return False
    return True


def _alternative_candidates(alternative: str, packages: list[Package]) -> list[Package]:
    operator = re.search(r"[<>]", alternative)
    if operator:
        base = alternative[: operator.start()]
        constraints = _DEWEY.findall(alternative[operator.start() :])
        if not constraints or "".join(o + v for o, v in constraints) != alternative[operator.start() :]:
            raise FetchError(f"cannot parse version constraint in {alternative!r}")
        return [p for p in packages if p.base == base and _dewey_matches(p.version, constraints)]
    if re.search(r"[\[\]*?]", alternative):
        return [p for p in packages if fnmatch.fnmatchcase(p.pkgname, alternative)]
    exact = [p for p in packages if p.pkgname == alternative]
    return exact or [p for p in packages if p.base == alternative]


def best_match(pattern: str, packages: list[Package]) -> Package | None:
    """The highest-version package matching `pattern`, or None. The first brace alternative that
    matches anything wins, so the order a package lists its alternatives in is kept."""
    if not SAFE_PATTERN.match(pattern):
        raise FetchError(f"refusing pattern {pattern!r}")
    for alternative in expand_braces(pattern):
        candidates = _alternative_candidates(alternative, packages)
        if candidates:
            best = candidates[0]
            for candidate in candidates[1:]:
                if candidate.base == best.base and dewey_compare(candidate.version, best.version) > 0:
                    best = candidate
            return best
    return None


def resolve_closure(
    requested: list[str], optional: list[str], packages: list[Package]
) -> tuple[list[Package], list[str]]:
    """The transitive closure of `requested` (and `optional` ones that exist). Returns the packages
    in a stable order and the dependency patterns nothing matched, which pkg_add will try the network for.
    A requested package that is absent fails; an absent optional one does not."""
    by_name = {p.pkgname: p for p in packages}
    chosen: dict[str, Package] = {}
    unresolved: list[str] = []
    queue: list[str] = []
    for name in requested:
        found = best_match(name, packages)
        if found is None:
            raise FetchError(f"no package matches requested {name!r}")
        queue.append(found.pkgname)
    for name in optional:
        found = best_match(name, packages)
        if found is None:
            unresolved.append(name)
        else:
            queue.append(found.pkgname)
    while queue:
        pkgname = queue.pop()
        if pkgname in chosen:
            continue
        package = by_name[pkgname]
        chosen[pkgname] = package
        for dependency in package.depends:
            found = best_match(dependency, packages)
            if found is None:
                unresolved.append(dependency)
            elif found.pkgname not in chosen:
                queue.append(found.pkgname)
    return [chosen[name] for name in sorted(chosen)], sorted(set(unresolved))


# ---------------------------------------------------------------- verification


def checksum_algorithm(cksum: str) -> tuple[str, str] | None:
    """`SHA512 <hex>` (or `sha256 <hex>`) -> (algorithm, hex). Anything else is None."""
    fields = cksum.split()
    if len(fields) >= 2 and fields[0].lower() in ("sha256", "sha512") and re.fullmatch(r"[0-9a-fA-F]+", fields[-1]):
        return fields[0].lower(), fields[-1].lower()
    return None


def verify_file(path: Path, package: Package) -> str | None:
    """None when the file is what pkg_summary says it is, else the reason it is not."""
    try:
        size = path.stat().st_size
    except OSError as error:
        return f"cannot stat: {error}"
    if package.file_size is not None and size != package.file_size:
        return f"size {size} != pkg_summary FILE_SIZE {package.file_size}"
    parsed = checksum_algorithm(package.file_cksum) if package.file_cksum else None
    if package.file_cksum and parsed is None:
        return f"unsupported FILE_CKSUM {package.file_cksum!r}"
    digest = hashlib.new(parsed[0]) if parsed else None
    try:
        with path.open("rb") as handle:
            if digest is not None:
                for chunk in iter(lambda: handle.read(CHUNK), b""):
                    digest.update(chunk)
                handle.seek(0)
            # A full read of the compressed stream checks its own integrity trailer. pkgsrc names
            # every package .tgz whatever its compression; NetBSD 11's are xz.
            magic = handle.read(6)
            handle.seek(0)
            if magic[:2] == GZIP_MAGIC:
                stream = gzip.GzipFile(fileobj=handle)
            elif magic == XZ_MAGIC:
                stream = lzma.LZMAFile(handle)
            elif magic[:3] == b"BZh":
                stream = bz2.BZ2File(handle)
            else:
                return f"unknown compression, magic {magic.hex()}"
            with stream:
                while stream.read(CHUNK):
                    pass
    except (OSError, EOFError, lzma.LZMAError, zlib.error) as error:
        return f"not a complete compressed archive: {error}"
    if digest is not None and digest.hexdigest() != parsed[1]:
        return f"{parsed[0]} mismatch"
    return None


# ---------------------------------------------------------------- network


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"refusing redirect to non-HTTPS URL {newurl!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnly)


def http_get(url: str, destination: io.BufferedIOBase, limit: int, timeout: float, deadline: float = 900.0) -> None:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise FetchError(f"refusing non-HTTPS URL {url!r}")
    request = urllib.request.Request(url, headers={"User-Agent": "merovingian-ci-fetch-netbsd-packages"})
    total = 0
    started = time.monotonic()
    with _OPENER.open(request, timeout=timeout) as response:
        expected = response.headers.get("Content-Length")
        while True:
            chunk = response.read(CHUNK)
            if not chunk:
                # http.client ends a dropped fixed-length body without raising; a short body is a failed
                # download of this mirror, not a file for verification to reject later.
                if expected is not None and expected.isdigit() and total != int(expected):
                    raise FetchError(f"{url} ended after {total} of {expected} bytes")
                return
            total += len(chunk)
            if time.monotonic() - started > deadline:
                raise FetchError(f"{url} took longer than {deadline:.0f}s")
            if total > limit:
                raise FetchError(f"{url} exceeds {limit} bytes")
            destination.write(chunk)


def with_retries(action, description: str, attempts: int, delay: float):  # noqa: ANN001
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except (OSError, http.client.HTTPException, FetchError) as error:
            last = error
            print(f"  {description}: attempt {attempt}/{attempts} failed: {error}", file=sys.stderr)
            if attempt < attempts:
                time.sleep(delay * attempt)
    raise FetchError(f"{description}: giving up: {last}")


def safe_packages(packages: list[Package]) -> list[Package]:
    """Drops the packages whose FILE_NAME is not a plain .tgz name: a hostile or damaged summary line
    must not become a path."""
    return [p for p in packages if SAFE_FILE.match(p.file_name)]


def usable_summary(
    text: str, required: tuple[str, ...] | list[str]
) -> tuple[list[Package], list[str]]:
    """Parses `text` and returns its safe packages with the dependency patterns the required closure
    leaves unresolved, or raises when the summary cannot serve this run: a required package is absent,
    or a package in the required closure has no valid FILE_SIZE."""
    packages = safe_packages(parse_summary(text))
    absent = [r for r in required if best_match(r, packages) is None]
    if absent:
        raise FetchError(f"no package matches required {', '.join(absent)}")
    closure, unresolved = resolve_closure(list(required), [], packages)
    unsized = [p.file_name for p in closure if p.file_size is None]
    if unsized:
        raise FetchError(f"pkg_summary gives no valid FILE_SIZE for required: {' '.join(unsized)}")
    return packages, unresolved


def decompress_bounded(decompressor, data: bytes, limit: int) -> bytes:  # noqa: ANN001
    """Decodes `data` with a streaming `decompressor`, failing once the output exceeds `limit` bytes,
    so a small compressed file cannot inflate without bound. A stream that ends early is an EOFError."""
    pieces: list[bytes] = []
    total = 0
    for offset in range(0, max(len(data), 1), CHUNK):
        piece = data[offset : offset + CHUNK]
        while True:
            produced = decompressor.decompress(piece, limit + 1 - total)
            total += len(produced)
            if total > limit:
                raise FetchError(f"pkg_summary decodes to more than {limit} bytes")
            pieces.append(produced)
            if decompressor.eof:
                return b"".join(pieces)
            piece = getattr(decompressor, "unconsumed_tail", b"")
            if not piece and getattr(decompressor, "needs_input", True):
                break
            # zlib left input unconsumed, or bz2 and lzma hold output back: ask again.
    raise EOFError("pkg_summary ends before its compressed stream does")


def _store_summary(summary_file: Path, text: str) -> None:
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = summary_file.with_name(summary_file.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, summary_file)


def fetch_summary(
    bases: list[str],
    summary_file: Path | None,
    attempts: int,
    timeout: float,
    required: tuple[str, ...] | list[str] = (),
) -> list[Package]:
    """The parsed pkg_summary of the first source that serves the `required` closure completely: an existing
    `summary_file`, else the first mirror and format that downloads, decompresses (within
    MAX_DECODED_SUMMARY_BYTES), parses and resolves it. A candidate that does not is recorded and the next
    is tried. A candidate whose required closure leaves dependencies unresolved is only a fallback: the
    first such one is used, with a warning, when no candidate is complete. Only a used download is written."""
    errors: list[str] = []
    fallback: tuple[list[Package], list[str], str | None] | None = None
    if summary_file is not None and summary_file.is_file():
        # Written by an earlier run of this script in the same job: decompressed pkg_summary text.
        try:
            packages, unresolved = usable_summary(summary_file.read_text(encoding="utf-8", errors="replace"), required)
            if not unresolved:
                return packages
            fallback = (packages, unresolved, None)
        except (FetchError, OSError, ValueError) as error:
            print(f"  {summary_file}: ignored, not usable: {error}", file=sys.stderr)
            errors.append(f"{summary_file}: {error}")
    for base in bases:
        for name, make_decompressor in SUMMARY_NAMES:
            buffer = io.BytesIO()

            def attempt(url: str = base + name, buffer: io.BytesIO = buffer) -> None:
                buffer.seek(0)
                buffer.truncate()
                http_get(url, buffer, MAX_SUMMARY_BYTES, timeout)

            try:
                with_retries(attempt, base + name, attempts, 3)
                decoded = decompress_bounded(make_decompressor(), buffer.getvalue(), MAX_DECODED_SUMMARY_BYTES)
                text = _decode(decoded)
                packages, unresolved = usable_summary(text, required)
            except (FetchError, OSError, EOFError, lzma.LZMAError, zlib.error, ValueError) as error:
                errors.append(f"{base}{name}: {error}")
                continue
            if unresolved:
                if fallback is None:
                    fallback = (packages, unresolved, text)
                continue
            if summary_file is not None:
                _store_summary(summary_file, text)
            return packages
    if fallback is not None:
        packages, unresolved, text = fallback
        print(
            "warning: no pkg_summary resolves every required dependency; using the first usable one, "
            f"and the guest takes these from the mirrors: {' '.join(unresolved)}",
            file=sys.stderr,
        )
        if summary_file is not None and text is not None:
            _store_summary(summary_file, text)
        return packages
    raise FetchError("cannot fetch pkg_summary: " + "; ".join(errors))


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def download_package(bases: list[str], package: Package, target: Path, attempts: int, timeout: float) -> None:
    """Tries each mirror in turn, `attempts` rounds. A mirror that fails is moved to the end of `bases`
    (in place), so one stalled CDN edge costs one timeout, not one per package."""
    partial = target.with_name(target.name + ".part")
    errors: list[str] = []
    for round_number in range(1, attempts + 1):
        for base in list(bases):
            url = base + urllib.parse.quote(package.file_name)
            try:
                with partial.open("wb") as handle:
                    http_get(url, handle, MAX_PACKAGE_BYTES, timeout)
            except (OSError, http.client.HTTPException, FetchError) as error:
                print(f"  {url}: round {round_number}/{attempts} failed: {error}", file=sys.stderr)
                errors.append(f"{url}: {error}")
                bases.remove(base)
                bases.append(base)
                continue
            reason = verify_file(partial, package)
            if reason is not None:
                print(f"  {url}: round {round_number}/{attempts} rejected: {reason}", file=sys.stderr)
                errors.append(f"{url}: {reason}")
                partial.unlink(missing_ok=True)
                bases.remove(base)
                bases.append(base)
                continue
            os.replace(partial, target)
            return
        time.sleep(2 * round_number)
    partial.unlink(missing_ok=True)
    raise FetchError(f"{package.file_name}: " + "; ".join(errors[-len(bases) :]))


# ---------------------------------------------------------------- driver


def check_names(values: list[str], what: str) -> None:
    for value in values:
        if "/" in value or ".." in value or "\\" in value or not SAFE_PATTERN.match(value):
            raise FetchError(f"refusing {what} {value!r}")


def human(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MiB"


def _ensure_package(output: Path, package: Package, bases: list[str], attempts: int, timeout: float) -> bool:
    """Leaves a verified copy of `package` in `output`. True when it was downloaded, False when reused."""
    target = output / package.file_name
    if target.is_symlink():
        target.unlink()
    if target.exists():
        reason = verify_file(target, package)
        if reason is None:
            return False
        print(f"  {package.file_name}: cached copy rejected ({reason}); downloading again", file=sys.stderr)
        target.unlink()
    # download_package verifies the file before it moves it into place, so a fresh download is not read again.
    download_package(bases, package, target, attempts, timeout)
    return True


def sync_directory(
    output: Path,
    closure: list[Package],
    bases: list[str],
    attempts: int,
    timeout: float,
    optional_only: frozenset[str] = frozenset(),
) -> tuple[int, int, int]:
    """Makes `output` hold the closure's files, each verified. Returns (downloaded, reused, pruned).
    The packages named in `optional_only` (file names) are fetched after the rest and are best-effort:
    a failure is a warning, the partial file is removed and the run carries on."""
    output.mkdir(parents=True, exist_ok=True)
    wanted = {p.file_name for p in closure}
    pruned = 0
    for entry in output.iterdir():
        if entry.name not in wanted:
            if entry.is_file() or entry.is_symlink():
                entry.unlink()
                pruned += 1
    downloaded = reused = 0
    ordered = [p for p in closure if p.file_name not in optional_only] + [
        p for p in closure if p.file_name in optional_only
    ]
    for package in ordered:
        try:
            if _ensure_package(output, package, bases, attempts, timeout):
                downloaded += 1
            else:
                reused += 1
        except FetchError as error:
            if package.file_name not in optional_only:
                raise
            print(f"warning: optional package {package.file_name} not downloaded: {error}", file=sys.stderr)
            (output / package.file_name).unlink(missing_ok=True)
            (output / (package.file_name + ".part")).unlink(missing_ok=True)
    return downloaded, reused, pruned


def lockfile_text(closure: list[Package]) -> str:
    """One `FILE_NAME FILE_SIZE FILE_CKSUM|-` line per package, in the closure's sorted order, so the
    CI cache key changes when a package's size or checksum does, not only its name."""
    lines = []
    for package in closure:
        cksum = " ".join(package.file_cksum.split()) if package.file_cksum else "-"
        lines.append(f"{package.file_name} {package.file_size} {cksum or '-'}\n")
    return "".join(lines)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch NetBSD binary packages and their dependencies on the host.")
    parser.add_argument("--release", required=True, help="NetBSD release directory, e.g. 11.0")
    parser.add_argument("--arch", required=True, help="repository architecture directory, e.g. amd64")
    parser.add_argument("--mirror", action="append", default=[], help="mirror host (HTTPS), in order of preference")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--lockfile",
        required=True,
        type=Path,
        help="receives one `FILE_NAME FILE_SIZE FILE_CKSUM|-` line per resolved package, for the cache key",
    )
    parser.add_argument("--summary-file", type=Path, help="keeps pkg_summary between runs of this script in one job")
    parser.add_argument("--optional", action="append", default=[], help="a package to include when the repository has it")
    parser.add_argument("--resolve-only", action="store_true", help="write the lockfile; download nothing")
    parser.add_argument("--dry-run", action="store_true", help="resolve and print sizes; write and download nothing")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0, help="seconds per network read")
    parser.add_argument("packages", nargs="+", help="package names, as given to pkg_add")
    return parser.parse_args(argv)


def run(argv: list[str]) -> int:
    args = parse_arguments(argv)
    if not SAFE_RELEASE.match(args.release) or not SAFE_ARCH.match(args.arch):
        raise FetchError("release or arch has an unexpected form")
    mirrors = args.mirror or list(DEFAULT_MIRRORS)
    for mirror in mirrors:
        if not SAFE_HOST.match(mirror):
            raise FetchError(f"refusing mirror host {mirror!r}")
    check_names(args.packages, "package name")
    check_names(args.optional, "optional package name")
    if args.output_dir.name in ("", ".", "..") or ".." in args.output_dir.parts:
        raise FetchError(f"refusing output directory {str(args.output_dir)!r}")
    bases = [f"https://{m}/pub/pkgsrc/packages/NetBSD/{args.arch}/{args.release}/All/" for m in mirrors]

    packages = fetch_summary(bases, args.summary_file, args.attempts, args.timeout, args.packages)
    packages = safe_packages(packages)
    required_closure, _ = resolve_closure(args.packages, [], packages)
    closure, unresolved = resolve_closure(args.packages, args.optional, packages)
    required_names = {p.pkgname for p in required_closure}
    optional_only = frozenset(p.file_name for p in closure if p.pkgname not in required_names)
    dropped = [p for p in closure if p.file_size is None and p.file_name in optional_only]
    for package in dropped:
        print(
            f"warning: optional package {package.file_name} dropped: pkg_summary gives no valid FILE_SIZE",
            file=sys.stderr,
        )
    closure = [p for p in closure if p not in dropped]
    optional_only = frozenset(p.file_name for p in closure if p.file_name in optional_only)
    known_size = sum(p.file_size or 0 for p in closure)
    print(f"summary: {len(packages)} packages in {args.arch}/{args.release}")
    print(f"resolved: {len(closure)} packages, {human(known_size)} to download when nothing is cached")
    if unresolved:
        print(f"unresolved dependency patterns (pkg_add will try the network): {' '.join(unresolved)}")
    if args.dry_run:
        for package in closure:
            print(f"  {package.file_name} {package.file_size}")
        return 0

    unsized = [p.file_name for p in closure if p.file_size is None]
    if unsized:
        raise FetchError(f"pkg_summary gives no valid FILE_SIZE for: {' '.join(unsized)}")
    args.lockfile.parent.mkdir(parents=True, exist_ok=True)
    args.lockfile.write_text(lockfile_text(closure), encoding="utf-8", newline="\n")
    if args.resolve_only:
        return 0
    downloaded, reused, pruned = sync_directory(
        args.output_dir, closure, bases, args.attempts, args.timeout, optional_only
    )
    failed = [p for p in closure if p.file_name in optional_only and not (args.output_dir / p.file_name).exists()]
    if failed:
        # The CI cache save step keys on the lockfile's hash at save time: save what the directory holds.
        closure = [p for p in closure if p not in failed]
        args.lockfile.write_text(lockfile_text(closure), encoding="utf-8", newline="\n")
        missing = " ".join(p.file_name for p in failed)
        print(f"lockfile rewritten without the optional packages that did not download: {missing}")
    print(f"done: {len(closure)} resolved, {downloaded} downloaded, {reused} reused from cache, {pruned} stale files removed")
    return 0


def main() -> int:
    try:
        return run(sys.argv[1:])
    except FetchError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
