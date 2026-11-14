#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Unified build script for Merovingian.
# Delegates to the shell scripts in scripts/ for each build target.

import argparse
import configparser
import hashlib
import io
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

PROFILES = ("debug", "release", "sanitizer", "coverage", "fuzz", "hardened")

# build.py vm (ADR-0752): the VM holds one checkout per local checkout under
# ~/merovingian-vm/<name>, each with a manifest of what was last sent to it.
VM_REMOTE_ROOT = "merovingian-vm"
VM_MANIFEST = ".vm-sync/manifest"
VM_MANIFEST_NEXT = ".vm-sync/manifest.next"
VM_DEFAULT_BUILDDIR = "build-vm"
# One compile job per 1.5 GiB of VM memory unless --jobs says otherwise: a
# C++26 translation unit here can take more than 1 GiB to compile.
VM_MEMORY_PER_JOB_KIB = 1_572_864
VM_TESTLOGS = ("testlog.txt", "testlog.json")
# The remote script exits with this status, and leaves VM_BASELINE_MARKER in its
# run directory, when the VM's manifest changed between build.py reading it and
# the script taking the lock; build.py then reads it again and resends.
VM_BASELINE_CHANGED = 75
VM_BASELINE_MARKER = "baseline-changed"
VM_SYNC_ATTEMPTS = 3
_VM_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{16}$")
VM_SETTING_NAMES = ("host", "user", "port", "identity", "jobs")
_VM_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]*$")
_VM_USER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_VM_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_VM_BUILDDIR_PATTERN = re.compile(r"^build[A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*$")
_TESTLOG_SUMMARY_PATTERN = re.compile(
    r"^(Ok|Expected Fail|Fail|Unexpected Pass|Skipped|Timeout):\s+\d+\s*$")


def quote_bash(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def run_script(script_path: Path, args: list[str]) -> int:
    cmd = ["sh", str(script_path)] + args
    return subprocess.call(cmd)


def run_wsl(args: argparse.Namespace, extra: list[str]) -> int:
    repo_root = str(REPO_ROOT)

    # Convert Windows path to WSL path
    match = re.match(r"^([A-Za-z]):\\(.*)$", repo_root)
    if match:
        drive = match.group(1).lower()
        tail = match.group(2).replace("\\", "/")
        wsl_path = f"/mnt/{drive}/{tail}"
    else:
        result = subprocess.run(
            ["wsl.exe", "--", "wslpath", "-a", "--", repo_root],
            capture_output=True, text=True,
        )
        if result.returncode != 0 or not result.stdout.strip():
            print(f"error: unable to resolve WSL path for {repo_root}", file=sys.stderr)
            return 1
        wsl_path = result.stdout.strip()

    # Build argument list for build-wsl.sh (space-separated, not --key=value)
    wsl_args = ["--builddir", args.builddir]
    wsl_args += ["--cc", args.cc]
    wsl_args += ["--cxx", args.cxx]
    wsl_args += ["--wrap-mode", args.wrap_mode]
    if args.profile:
        wsl_args += ["--profile", args.profile]
    if args.buildtype:
        wsl_args += ["--buildtype", args.buildtype]
    if args.sanitize:
        wsl_args += ["--sanitize", args.sanitize]
    if args.coverage:
        wsl_args.append("--coverage")
    if args.build_fuzz:
        wsl_args.append("--build-fuzz")
    if args.hardening:
        wsl_args.append("--hardening")
    if args.no_tests:
        wsl_args.append("--no-tests")
    if args.setup_only:
        wsl_args.append("--setup-only")
    if args.compile_only:
        wsl_args.append("--compile-only")
    if args.dry_run:
        wsl_args.append("--dry-run")
    if args.clean:
        wsl_args.append("--clean")

    # Quote each argument for the bash -lc string
    quoted_wsl_args = " ".join(quote_bash(a) for a in wsl_args)
    command = f"cd {quote_bash(wsl_path)} && sh ./scripts/build-wsl.sh {quoted_wsl_args}"

    wsl_cmd = ["wsl.exe"]
    if args.distro:
        wsl_cmd += ["-d", args.distro]
    wsl_cmd += ["--", "bash", "-lc", command]

    return subprocess.call(wsl_cmd)


def add_common_dev_args(parser: argparse.ArgumentParser, builddir_default: str | None = "build",
                        builddir_help: str = ""):
    parser.add_argument("--builddir", default=builddir_default,
                        help=f"Meson build directory (default: {builddir_help or builddir_default})")
    parser.add_argument("--cc", default="clang", help="C compiler (default: clang)")
    parser.add_argument("--cxx", default="clang++", help="C++ compiler (default: clang++)")
    parser.add_argument("--wrap-mode", default="forcefallback",
                        help="Meson wrap mode (default: forcefallback)")
    parser.add_argument("--no-tests", action="store_true", help="Skip running tests")
    parser.add_argument("--setup-only", action="store_true",
                        help="Configure Meson and stop")
    parser.add_argument("--compile-only", action="store_true",
                        help="Configure and compile, but do not test")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without running them")


def add_profile_args(parser: argparse.ArgumentParser):
    parser.add_argument("--profile", choices=PROFILES,
                        help="Named build profile")
    parser.add_argument("--buildtype", help="Meson buildtype (e.g. debug, release)")
    parser.add_argument("--sanitize", help="Meson b_sanitize value (e.g. address,undefined)")
    parser.add_argument("--coverage", action="store_true",
                        help="Enable Meson coverage instrumentation")
    parser.add_argument("--build-fuzz", action="store_true",
                        help="Enable fuzz harness targets")
    parser.add_argument("--hardening", action="store_true",
                        help="Enable hardening flags")


def build_linux(args: argparse.Namespace) -> int:
    script = SCRIPTS_DIR / "build-linux.sh"
    cmd_args = ["--builddir", args.builddir]
    cmd_args += ["--cc", args.cc]
    cmd_args += ["--cxx", args.cxx]
    cmd_args += ["--wrap-mode", args.wrap_mode]
    if args.profile:
        cmd_args += ["--profile", args.profile]
    if args.buildtype:
        cmd_args += ["--buildtype", args.buildtype]
    if args.sanitize:
        cmd_args += ["--sanitize", args.sanitize]
    if args.coverage:
        cmd_args.append("--coverage")
    if args.build_fuzz:
        cmd_args.append("--build-fuzz")
    if args.hardening:
        cmd_args.append("--hardening")
    if args.no_tests:
        cmd_args.append("--no-tests")
    if args.setup_only:
        cmd_args.append("--setup-only")
    if args.compile_only:
        cmd_args.append("--compile-only")
    if args.dry_run:
        cmd_args.append("--dry-run")
    if args.jobs is not None:
        cmd_args += ["--jobs", str(args.jobs)]
    return run_script(script, cmd_args)


def build_bsd(args: argparse.Namespace) -> int:
    script = SCRIPTS_DIR / "build-bsd.sh"
    cmd_args = ["--builddir", args.builddir]
    cmd_args += ["--cc", args.cc]
    cmd_args += ["--cxx", args.cxx]
    pkg_config = getattr(args, "pkg_config", "")
    if pkg_config:
        cmd_args += ["--pkg-config", pkg_config]
    cmd_args += ["--wrap-mode", args.wrap_mode]
    if args.profile:
        cmd_args += ["--profile", args.profile]
    if args.buildtype:
        cmd_args += ["--buildtype", args.buildtype]
    if args.sanitize:
        cmd_args += ["--sanitize", args.sanitize]
    if args.coverage:
        cmd_args.append("--coverage")
    if args.build_fuzz:
        cmd_args.append("--build-fuzz")
    if args.hardening:
        cmd_args.append("--hardening")
    if args.no_tests:
        cmd_args.append("--no-tests")
    if args.setup_only:
        cmd_args.append("--setup-only")
    if args.compile_only:
        cmd_args.append("--compile-only")
    if args.dry_run:
        cmd_args.append("--dry-run")
    if args.jobs is not None:
        cmd_args += ["--jobs", str(args.jobs)]
    return run_script(script, cmd_args)


def build_wsl(args: argparse.Namespace) -> int:
    return run_wsl(args, [])


class VmError(Exception):
    """A vm setting, path or checkout that build.py refuses to work with."""


@dataclass(frozen=True)
class VmSettings:
    """Where and how build.py vm reaches the VM. jobs None means size by memory;
    name is the --vm name ("" for the default [vm] section)."""
    host: str
    user: str
    port: int
    identity: str
    jobs: int | None
    name: str = ""


def positive_int(value: str) -> int:
    """argparse type for --jobs: a whole number of at least 1."""
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"expected a positive whole number, not {value!r}")
    return int(value)


def vm_config_path(env: Mapping[str, str]) -> Path:
    """The per-user settings file: $MEROVINGIAN_VM_CONFIG, else ~/.config/merovingian/vm.ini.

    It lives outside the repository so every worktree reads the same file and a
    host address is never committed."""
    override = env.get("MEROVINGIAN_VM_CONFIG", "")
    if override:
        return Path(override)
    return Path.home() / ".config" / "merovingian" / "vm.ini"


def load_vm_settings(args: argparse.Namespace, env: Mapping[str, str],
                     config_path: Path) -> VmSettings:
    """Resolve each vm setting from the command line, then MEROVINGIAN_VM_<NAME>,
    then config_path: its [vm] section, or [vm.<name>] for the VM that --vm or
    MEROVINGIAN_VM_NAME names. Raises VmError on a missing host or VM section,
    or a value ssh could read as an option."""
    vm_name = (getattr(args, "vm", None) or env.get("MEROVINGIAN_VM_NAME", "")).strip()
    if vm_name and not _VM_NAME_PATTERN.match(vm_name):
        raise VmError(f"VM name {vm_name!r} must be lower-case letters, digits, '-' or '_'")
    section = f"vm.{vm_name}" if vm_name else "vm"
    file_values: dict[str, str] = {}
    if config_path.is_file():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(config_path, encoding="utf-8")
        except configparser.Error as error:
            raise VmError(f"cannot read {config_path}: {error}") from error
        if parser.has_section(section):
            for name, value in parser.items(section):
                if name not in VM_SETTING_NAMES:
                    raise VmError(f"{config_path}: unknown [{section}] setting {name!r}")
                file_values[name] = value.strip()
        elif vm_name:
            known = ", ".join(s[3:] for s in parser.sections() if s.startswith("vm.")) or "none"
            raise VmError(f"{config_path} has no [{section}] section (named VMs: {known})")
    elif vm_name:
        raise VmError(f"--vm {vm_name} needs a [{section}] section in {config_path}")

    def pick(name: str) -> str:
        from_cli = getattr(args, name, None)
        if from_cli not in (None, ""):
            return str(from_cli)
        from_env = env.get(f"MEROVINGIAN_VM_{name.upper()}", "").strip()
        if from_env:
            return from_env
        return file_values.get(name, "")

    host = pick("host")
    if not host:
        raise VmError("no VM host: pass --host, set MEROVINGIAN_VM_HOST, "
                      f"or set host in the [{section}] section of {config_path}")
    if not _VM_HOST_PATTERN.match(host):
        raise VmError(f"VM host {host!r} is not a host name or IP address")

    user = pick("user")
    if user and not _VM_USER_PATTERN.match(user):
        raise VmError(f"VM user {user!r} is not a user name")

    port_text = pick("port") or "22"
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise VmError(f"VM port {port_text!r} is not a port number")

    identity = pick("identity")
    if identity:
        identity = str(Path(identity).expanduser())
        if not Path(identity).is_file():
            raise VmError(f"VM identity file {identity} does not exist")

    jobs_text = pick("jobs")
    jobs = None
    if jobs_text:
        if not jobs_text.isdigit() or int(jobs_text) < 1:
            raise VmError(f"VM jobs {jobs_text!r} is not a positive whole number")
        jobs = int(jobs_text)

    return VmSettings(host=host, user=user, port=int(port_text), identity=identity, jobs=jobs,
                      name=vm_name)


def vm_default_builddir(settings: VmSettings) -> str:
    """build-vm for the default VM, build-vm-<name> for a named one, so two VMs'
    logs never overwrite each other locally."""
    return f"{VM_DEFAULT_BUILDDIR}-{settings.name}" if settings.name else VM_DEFAULT_BUILDDIR


def validate_vm_builddir(builddir: str) -> str:
    """Return builddir if it is a relative path whose first part starts with
    "build", the prefix the sync never sends; raise VmError otherwise."""
    parts = builddir.split("/")
    if not _VM_BUILDDIR_PATTERN.match(builddir) or any(part in (".", "..") for part in parts):
        raise VmError(f"--builddir {builddir!r} must be a relative path whose first "
                      "part starts with 'build', with no '.' or '..' parts")
    return builddir


def vm_checkout_name(repo_root: Path) -> str:
    """Name the VM-side checkout after the local one: its directory name plus a
    hash of its full path, so two worktrees never share a remote checkout."""
    resolved = str(repo_root.resolve())
    key = resolved.lower() if os.name == "nt" else resolved
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    stem = re.sub(r"[^A-Za-z0-9._-]", "-", repo_root.name).strip(".-") or "checkout"
    return f"{stem[:40]}-{digest}"


def vm_ssh_command(settings: VmSettings) -> list[str]:
    """The ssh invocation for every call to the VM. It never asks for a
    password and refuses a host key that is unknown or has changed."""
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4",
               "-p", str(settings.port)]
    if settings.identity:
        command += ["-i", settings.identity, "-o", "IdentitiesOnly=yes"]
    destination = f"{settings.user}@{settings.host}" if settings.user else settings.host
    return command + ["--", destination]


def _check_vm_path(path: str) -> None:
    """Refuse a path the manifest format or the VM checkout cannot hold safely."""
    if any(character in path for character in "\t\n\r"):
        raise VmError(f"cannot sync {path!r}: tab or newline in the path")
    if path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
        raise VmError(f"cannot sync {path!r}: not a plain relative path")


def _git_paths(repo_root: Path, *git_args: str) -> list[str]:
    """Run git ls-files with -z in repo_root and split its output."""
    result = subprocess.run(["git", "-C", str(repo_root), "ls-files", "-z", *git_args],
                            capture_output=True, check=True)
    return [entry for entry in result.stdout.decode("utf-8").split("\0") if entry]


def vm_local_files(repo_root: Path) -> dict[str, tuple[int, int, int]]:
    """Map each file to send to the VM to (mode, size, mtime).

    Sends every tracked file as it is on disk, with git's executable bit, and
    every untracked file git does not ignore, except under a top-level name
    starting with "build" or "." (build output, worktrees, tool caches). A
    tracked file deleted on disk is left out. Raises VmError on a symbolic link
    or submodule, which the sync does not carry."""
    files: dict[str, tuple[int, int, int]] = {}
    for entry in _git_paths(repo_root, "--stage"):
        meta, path = entry.split("\t", 1)
        git_mode = meta.split(" ", 1)[0]
        if git_mode not in ("100644", "100755"):
            raise VmError(f"cannot sync {path!r}: git mode {git_mode} is not a regular file")
        _check_vm_path(path)
        try:
            # lstat, not stat: a tracked file replaced on disk by a symbolic link
            # must be refused, not followed to a target outside the checkout.
            status = (repo_root / path).lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(status.st_mode):
            raise VmError(f"cannot sync {path!r}: not a regular file on disk")
        mode = 0o755 if git_mode == "100755" else 0o644
        files[path] = (mode, status.st_size, int(status.st_mtime))
    for path in _git_paths(repo_root, "--others", "--exclude-standard"):
        top = path.split("/", 1)[0]
        if path in files or top.startswith("build") or top.startswith("."):
            continue
        _check_vm_path(path)
        status = (repo_root / path).lstat()
        if not stat.S_ISREG(status.st_mode):
            raise VmError(f"cannot sync {path!r}: not a regular file on disk")
        executable = os.name != "nt" and bool(status.st_mode & stat.S_IXUSR)
        files[path] = (0o755 if executable else 0o644, status.st_size, int(status.st_mtime))
    return files


def format_vm_manifest(files: Mapping[str, tuple[int, int, int]]) -> str:
    """One "mode<TAB>size<TAB>mtime<TAB>path" line per file, sorted by path."""
    return "".join(f"{mode:o}\t{size}\t{mtime}\t{path}\n"
                   for path, (mode, size, mtime) in sorted(files.items()))


def parse_vm_manifest(text: str) -> dict[str, tuple[int, int, int]]:
    """Read a manifest written by format_vm_manifest. A line that does not parse
    is dropped, so its file counts as missing and is sent again."""
    files: dict[str, tuple[int, int, int]] = {}
    for line in text.splitlines():
        fields = line.split("\t", 3)
        if len(fields) != 4:
            continue
        mode, size, mtime, path = fields
        try:
            files[path] = (int(mode, 8), int(size), int(mtime))
        except ValueError:
            continue
    return files


def plan_vm_sync(local: Mapping[str, tuple[int, int, int]],
                 remote: Mapping[str, tuple[int, int, int]]) -> list[str]:
    """The paths whose mode, size or mtime differ from what the VM last received."""
    return [path for path in sorted(local) if remote.get(path) != local[path]]


def plan_vm_stale(local: Mapping[str, tuple[int, int, int]],
                  remote: Mapping[str, tuple[int, int, int]]) -> list[str]:
    """The paths the VM last received that this checkout no longer has."""
    return sorted(path for path in remote if path not in local)


def vm_manifest_digest(manifest: bytes) -> str:
    """The SHA-256 the remote script compares the VM's manifest against, under its lock."""
    return hashlib.sha256(manifest).hexdigest()


def write_vm_sync_archive(stream: BinaryIO, repo_root: Path,
                          local: Mapping[str, tuple[int, int, int]],
                          send: list[str]) -> None:
    """Stream a tar of the files in send, then the full manifest as
    VM_MANIFEST_NEXT, which the VM installs only after every file arrived."""
    with tarfile.open(fileobj=stream, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for path in send:
            mode, size, mtime = local[path]
            info = tarfile.TarInfo(path)
            info.size = size
            info.mtime = mtime
            info.mode = mode
            with open(repo_root / path, "rb") as source:
                archive.addfile(info, source)
        manifest = format_vm_manifest(local).encode("utf-8")
        info = tarfile.TarInfo(VM_MANIFEST_NEXT)
        info.size = len(manifest)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(manifest))


def vm_incoming_list(send: Sequence[str]) -> bytes:
    """The list of the paths the archive will bring, as the VM reads it before the archive:
    its length in bytes and a newline, then one path per line."""
    listing = "".join(f"{path}\n" for path in send).encode("utf-8")
    return f"{len(listing)}\n".encode("ascii") + listing


def write_vm_sync_stream(stream: BinaryIO, repo_root: Path,
                         local: Mapping[str, tuple[int, int, int]],
                         send: list[str]) -> None:
    """What build.py vm sends on the remote script's stdin: vm_incoming_list(send), then the archive."""
    stream.write(vm_incoming_list(send))
    write_vm_sync_archive(stream, repo_root, local, send)


# Run on the VM with python3 -c: copies the incoming list (vm_incoming_list) from stdin to stdout. os.read never
# returns more than it is asked for, so the archive that follows stays on stdin for tar.
_VM_READ_INCOMING = """import os, sys
def take(count):
    data = b""
    while len(data) < count:
        chunk = os.read(0, count - len(data))
        if not chunk:
            sys.exit("build.py vm: the stream ended inside the list of incoming files")
        data += chunk
    return data
header = b""
while not header.endswith(b"\\n"):
    if len(header) > 20:
        sys.exit("build.py vm: the stream does not start with a list of incoming files")
    header += take(1)
try:
    size = int(header)
except ValueError:
    sys.exit("build.py vm: the stream does not start with a list of incoming files")
sys.stdout.buffer.write(take(size))
"""


def vm_run_dir(token: str) -> str:
    """The directory, relative to the VM checkout, that holds one run's own files:
    its log snapshot and, when its baseline was stale, VM_BASELINE_MARKER."""
    if not _VM_TOKEN_PATTERN.match(token):
        raise VmError(f"bad run token {token!r}")
    return f".vm-sync/run-{token}"


def vm_remote_script(checkout: str, run_line: str, *, token: str, baseline_sha256: str,
                     stale: Sequence[str] = (), builddir: str = "", clean: bool = False,
                     size_jobs: bool = False) -> str:
    """The POSIX sh script the remote host runs for one build.py vm call.

    It sets $os from uname and $build_script to build-linux.sh on Linux or
    build-bsd.sh on FreeBSD, OpenBSD, NetBSD or DragonFly, refusing any other
    system. It takes the ssh user's lock, so a second run as that user (from any
    checkout) waits; everything after that happens under the lock:

    1. The VM's manifest must still hash to baseline_sha256, the manifest
       build.py planned the sync against. If another run changed it meanwhile,
       the script leaves VM_BASELINE_MARKER in the run directory and exits
       VM_BASELINE_CHANGED without touching the checkout, and build.py retries.
    2. With builddir it removes that build's old test logs (and the whole
       directory with clean), before anything can fail.
    3. It deletes the stale paths, files this checkout no longer has, and any
       directory that leaves empty, before unpacking, so a file that became a
       directory (or the reverse) never blocks the archive.
    4. It reads the list of incoming paths that precedes the archive on stdin
       (vm_incoming_list) and adds them, zeroed, to the manifest, so an unpack
       cut off part-way leaves nothing the next run does not know to delete.
       Then it unpacks the archive into ~/merovingian-vm/<checkout> and installs
       the new manifest, which arrives last, only after that succeeds.
    5. With size_jobs it sets $jobs from the host's memory, runs run_line, and
       with builddir copies the test logs into the run directory, so build.py
       fetches this run's logs even after a later run has replaced the build's.

    The lock is flock(2) on fd 9, taken through Python's fcntl because FreeBSD,
    OpenBSD and NetBSD ship no flock(1). A flock lock belongs to the open file,
    so this shell's fd 9 keeps holding it after Python exits."""
    run_dir = vm_run_dir(token)
    if not re.fullmatch(r"[0-9a-f]{64}", baseline_sha256):
        raise VmError(f"bad manifest digest {baseline_sha256!r}")
    stale_end = f"VM_STALE_{token}"
    if stale_end in stale:
        raise VmError(f"cannot sync a path named {stale_end!r}")
    lines = [
        "set -eu",
        "os=$(uname -s)",
        'case "$os" in',
        "    Linux) build_script=build-linux.sh ;;",
        "    FreeBSD|OpenBSD|NetBSD|DragonFly) build_script=build-bsd.sh ;;",
        '    *) echo "build.py vm: unsupported remote system $os" >&2; exit 2 ;;',
        "esac",
        "py=",
        "for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do",
        '    if command -v "$candidate" >/dev/null 2>&1; then py=$candidate; break; fi',
        "done",
        'if [ -z "$py" ]; then',
        "    echo 'build.py vm: no python3 on the remote host; run scripts/remote-host-setup.sh' >&2",
        "    exit 2",
        "fi",
        f'root="$HOME"/{quote_bash(VM_REMOTE_ROOT)}',
        f'checkout="$root"/{quote_bash(checkout)}',
        'mkdir -p "$checkout/.vm-sync"',
        'exec 9>>"$root/.lock"',
        """if ! "$py" -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)' 2>/dev/null; then""",
        "    echo 'build.py vm: another run holds the VM lock; waiting for it' >&2",
        """    "$py" -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX)'""",
        "fi",
        'cd "$checkout"',
        f"run_dir={run_dir}",
        'mkdir -p "$run_dir"',
        f"baseline=$(cat {VM_MANIFEST} 2>/dev/null | "
        """"$py" -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')""",
        f'if [ "$baseline" != {baseline_sha256} ]; then',
        "    echo 'build.py vm: another run changed the VM checkout since this one read it' >&2",
        f'    : > "$run_dir/{VM_BASELINE_MARKER}"',
        f"    exit {VM_BASELINE_CHANGED}",
        "fi",
        # Before the checkout changes, zero the metadata of every entry in the
        # manifest. If the sync then fails part-way, the next run plans against
        # this, so it resends every file (a file deleted here and later restored
        # with its old metadata included), yet still knows which paths are stale.
        f"if [ -f {VM_MANIFEST} ]; then",
        """    awk 'BEGIN { FS = "\\t"; OFS = "\\t" } NF >= 4 { print 0, 0, 0, $4 }' """
        f"{VM_MANIFEST} > .vm-sync/manifest.dirty",
        f"    mv -f .vm-sync/manifest.dirty {VM_MANIFEST}",
        "fi",
    ]
    if builddir:
        quoted = quote_bash(builddir)
        if clean:
            lines.append(f"rm -rf -- {quoted}")
        lines += [f"rm -f -- {quoted}/meson-logs/{name}" for name in VM_TESTLOGS]
    if stale:
        lines += [
            "while IFS= read -r stale; do",
            '    case "$stale" in',
            "        ''|/*|..|../*|*/..|*/../*) continue ;;",
            "    esac",
            # A stale file that is now a directory was made by an earlier unpack,
            # interrupted after it had begun filling the file's replacement:
            # the archive refills it, so leave it.
            '    if [ -d "$stale" ] && [ ! -L "$stale" ]; then continue; fi',
            '    rm -f -- "$stale"',
            '    parent=$(dirname -- "$stale")',
            '    if [ "$parent" != . ]; then rmdir -p -- "$parent" 2>/dev/null || true; fi',
            f"done <<'{stale_end}'",
            *stale,
            stale_end,
        ]
    lines += [
        # Before unpacking, add every path the archive will bring to the zeroed
        # manifest. An unpack cut off part-way then leaves no file the manifest
        # does not name, so the next run deletes those the checkout no longer has,
        # whatever changed locally in between.
        f"[ -f {VM_MANIFEST} ] || : > {VM_MANIFEST}",
        f""""$py" -c '{_VM_READ_INCOMING}' > .vm-sync/incoming""",
        """awk 'BEGIN { FS = "\\t"; OFS = "\\t" } """
        """FILENAME == ARGV[1] { if (NF >= 4) { seen[$4] = 1; print } next } """
        """!($0 in seen) { seen[$0] = 1; print 0, 0, 0, $0 }' """
        f"{VM_MANIFEST} .vm-sync/incoming > .vm-sync/manifest.dirty",
        f"mv -f .vm-sync/manifest.dirty {VM_MANIFEST}",
        "rm -f .vm-sync/incoming",
        f"rm -f {VM_MANIFEST_NEXT}",
        "tar -xf -",
        f"if [ ! -f {VM_MANIFEST_NEXT} ]; then",
        "    echo 'build.py vm: the archive carried no manifest' >&2",
        "    exit 2",
        "fi",
        f"mv -f {VM_MANIFEST_NEXT} {VM_MANIFEST}",
    ]
    if size_jobs:
        lines += [
            'if [ "$os" = Linux ]; then',
            "    mem_kib=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)",
            "    cpus=$(nproc)",
            "else",
            "    mem_kib=$(( $(sysctl -n hw.physmem) / 1024 ))",
            "    cpus=$(sysctl -n hw.ncpu)",
            "fi",
            f"jobs=$((mem_kib / {VM_MEMORY_PER_JOB_KIB}))",
            '[ "$jobs" -ge 1 ] || jobs=1',
            '[ "$jobs" -le "$cpus" ] || jobs=$cpus',
            'echo "build.py vm: $jobs parallel jobs ($cpus CPUs, $((mem_kib / 1024)) MiB memory)" >&2',
        ]
    lines += ["set +e", f"( {run_line} )", "status=$?", "set -e"]
    if builddir:
        lines += [f'if [ -f {quoted}/meson-logs/{name} ]; then '
                  f'cp -- {quoted}/meson-logs/{name} "$run_dir/{name}"; fi'
                  for name in VM_TESTLOGS]
    lines.append('exit "$status"')
    return "\n".join(lines) + "\n"


def _vm_build_line(args: argparse.Namespace, builddir: str, jobs: int | None) -> str:
    """The call of the remote host's build script ($build_script, set by
    vm_remote_script); uses $jobs from that script when jobs is None."""
    build_args = ["--builddir", builddir, "--cc", args.cc, "--cxx", args.cxx,
                  "--wrap-mode", args.wrap_mode]
    if args.profile:
        build_args += ["--profile", args.profile]
    if args.buildtype:
        build_args += ["--buildtype", args.buildtype]
    if args.sanitize:
        build_args += ["--sanitize", args.sanitize]
    for flag, enabled in (("--coverage", args.coverage), ("--build-fuzz", args.build_fuzz),
                          ("--hardening", args.hardening), ("--no-tests", args.no_tests),
                          ("--setup-only", args.setup_only),
                          ("--compile-only", args.compile_only)):
        if enabled:
            build_args.append(flag)
    quoted = " ".join(quote_bash(arg) for arg in build_args)
    jobs_arg = quote_bash(str(jobs)) if jobs is not None else '"$jobs"'
    return (f'exec env PATH="$HOME/.local/bin:$PATH" sh "./scripts/$build_script" '
            f"{quoted} --jobs {jobs_arg}")


_VM_FETCH_MISSING = 3


def vm_fetch(ssh: list[str], remote_path: str) -> bytes | None:
    """Read a file on the VM, relative to the ssh user's home.

    Returns None only when the file does not exist there. Raises VmError when
    the file could not be read for any other reason, such as ssh refusing the
    key, so a log that was written is never reported as missing."""
    quoted = quote_bash(remote_path)
    script = f"cd && if [ -f {quoted} ]; then exec cat -- {quoted}; fi; exit {_VM_FETCH_MISSING}"
    result = subprocess.run(ssh + ["sh -c " + quote_bash(script)], capture_output=True)
    if result.returncode == _VM_FETCH_MISSING:
        return None
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise VmError(f"cannot copy {remote_path} back from the VM "
                      f"(exit {result.returncode}): {detail}")
    return result.stdout


def build_vm(args: argparse.Namespace) -> int:
    """Sync this checkout to a Linux or BSD VM over ssh and build, test or run a
    command there; see "Building on a VM" in docs/dev-environment.md."""
    try:
        settings = load_vm_settings(args, os.environ, vm_config_path(os.environ))
        builddir = validate_vm_builddir(args.builddir or vm_default_builddir(settings))
        if args.exec_command is not None and not args.exec_command:
            raise VmError("--exec needs a command to run")
        local = vm_local_files(REPO_ROOT)
    except (VmError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    ssh = vm_ssh_command(settings)
    checkout = vm_checkout_name(REPO_ROOT)
    remote_dir = f"{VM_REMOTE_ROOT}/{checkout}"
    runs_tests = args.exec_command is None and not (args.no_tests or args.setup_only
                                                    or args.compile_only)
    if args.exec_command is not None:
        run_line = ("exec env MEROVINGIAN_TEST_DISABLE_HARDENING=1 "
                    + " ".join(quote_bash(arg) for arg in args.exec_command))
        script_options = {}
    else:
        run_line = _vm_build_line(args, builddir, settings.jobs)
        script_options = {"builddir": builddir, "clean": args.clean,
                          "size_jobs": settings.jobs is None}

    local_logs = REPO_ROOT / builddir / "meson-logs"
    if runs_tests and not args.dry_run:
        for name in VM_TESTLOGS:
            (local_logs / name).unlink(missing_ok=True)

    for _attempt in range(VM_SYNC_ATTEMPTS):
        probe = subprocess.run(
            ssh + [f"cat -- {quote_bash(remote_dir + '/' + VM_MANIFEST)} 2>/dev/null || true"],
            capture_output=True)
        if probe.returncode != 0:
            sys.stderr.write(probe.stderr.decode("utf-8", "replace"))
            print(f"error: cannot reach the VM at {ssh[-1]} (ssh exit {probe.returncode})",
                  file=sys.stderr)
            return 2
        remote = parse_vm_manifest(probe.stdout.decode("utf-8", "replace"))
        send = plan_vm_sync(local, remote)
        token = secrets.token_hex(8)
        run_dir = f"{remote_dir}/{vm_run_dir(token)}"
        try:
            script = vm_remote_script(checkout, run_line, token=token,
                                      baseline_sha256=vm_manifest_digest(probe.stdout),
                                      stale=plan_vm_stale(local, remote), **script_options)
        except VmError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2

        print(f"build.py vm: sending {len(send)} of {len(local)} files to "
              f"{ssh[-1]}:~/{remote_dir}", file=sys.stderr)
        if args.dry_run:
            print(script)
            return 0

        process = subprocess.Popen(ssh + ["sh -c " + quote_bash(script)], stdin=subprocess.PIPE)
        try:
            write_vm_sync_stream(process.stdin, REPO_ROOT, local, send)
        except BrokenPipeError:
            pass
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
        status = process.wait()
        try:
            retry = (status == VM_BASELINE_CHANGED
                     and vm_fetch(ssh, f"{run_dir}/{VM_BASELINE_MARKER}") is not None)
            logs = {}
            if not retry and runs_tests:
                logs = {name: vm_fetch(ssh, f"{run_dir}/{name}") for name in VM_TESTLOGS}
        except VmError as error:
            # The run may well have written its log; say so rather than "no testlog",
            # and never exit 0 without a log the result can be read from.
            print(f"error: {error}", file=sys.stderr)
            print(f"build.py vm: the build exited {status}; its logs are still on the VM "
                  f"under ~/{run_dir}/", file=sys.stderr)
            return status or 2
        subprocess.run(ssh + [f"rm -rf -- {quote_bash(run_dir)}"], capture_output=True)
        if not retry:
            break
        print("build.py vm: reading the VM's manifest again and resending", file=sys.stderr)
    else:
        print(f"error: the VM checkout kept changing under {VM_SYNC_ATTEMPTS} attempts",
              file=sys.stderr)
        return 2

    if runs_tests:
        local_logs.mkdir(parents=True, exist_ok=True)
        ignore_file = REPO_ROOT / builddir / ".gitignore"
        if not ignore_file.exists():
            ignore_file.write_text("*\n", encoding="utf-8")
        for name, data in logs.items():
            if data is not None:
                (local_logs / name).write_bytes(data)
        if logs.get("testlog.txt") is not None:
            summary = [line for line in (local_logs / "testlog.txt").read_text(
                encoding="utf-8", errors="replace").splitlines()
                if _TESTLOG_SUMMARY_PATTERN.match(line)]
            print(f"build.py vm: {local_logs / 'testlog.txt'}", file=sys.stderr)
            for line in summary:
                print(f"build.py vm:   {line}", file=sys.stderr)
        else:
            print("build.py vm: the run wrote no testlog.txt", file=sys.stderr)
    return status


def build_deb(args: argparse.Namespace) -> int:
    return run_script(SCRIPTS_DIR / "build-deb.sh", [])


def build_rpm(args: argparse.Namespace) -> int:
    return run_script(SCRIPTS_DIR / "build-rpm.sh", [])


def build_pkg(args: argparse.Namespace) -> int:
    return run_script(SCRIPTS_DIR / "build-freebsd-pkg.sh", [])


def build_static(args: argparse.Namespace) -> int:
    env = os.environ.copy()
    if args.version:
        env["MEROVINGIAN_VERSION"] = args.version
    cmd = ["sh", str(SCRIPTS_DIR / "build-static-linux.sh")]
    return subprocess.call(cmd, env=env)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified build script for Merovingian",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python build.py linux
  python build.py linux --profile hardened --builddir build-hardened
  python build.py bsd
  python build.py wsl --distro Ubuntu
  python build.py vm
  python build.py vm --vm freebsd
  python build.py vm --exec ./build-vm/tests/merovingian-unit-tests "[push]"
  python build.py deb
  python build.py rpm
  python build.py pkg
  python build.py static --version 0.4.40
""",
    )
    subparsers = parser.add_subparsers(dest="target", required=True,
                                        help="Build target")

    # linux
    linux_parser = subparsers.add_parser("linux", help="Linux development build")
    add_common_dev_args(linux_parser, "build")
    add_profile_args(linux_parser)
    linux_parser.add_argument("--jobs", type=positive_int,
                              help="Most compile jobs and tests at once (default: Meson's)")

    # bsd
    bsd_parser = subparsers.add_parser("bsd", help="BSD development build")
    add_common_dev_args(bsd_parser, "build")
    add_profile_args(bsd_parser)
    bsd_parser.add_argument("--pkg-config", default="",
                             help="pkg-config command (default: pkgconf, then pkg-config)")
    bsd_parser.add_argument("--jobs", type=positive_int,
                            help="Most compile jobs and tests at once (default: Meson's)")

    # wsl
    wsl_parser = subparsers.add_parser("wsl",
                                        help="WSL (Windows Subsystem for Linux) build")
    add_common_dev_args(wsl_parser, "build-wsl")
    add_profile_args(wsl_parser)
    wsl_parser.add_argument("--distro", default="",
                             help="WSL distro name (default: system default)")
    wsl_parser.add_argument("--clean", action="store_true",
                             help="Wipe the build directory before configuring")

    # vm
    vm_parser = subparsers.add_parser(
        "vm", help="Build and test on a Linux or BSD VM over ssh (docs/dev-environment.md)")
    add_common_dev_args(vm_parser, None,
                        f"{VM_DEFAULT_BUILDDIR}, or {VM_DEFAULT_BUILDDIR}-<name> with --vm")
    vm_parser.add_argument("--vm", help="Named VM: the [vm.<name>] section of the settings file "
                                        "(default: MEROVINGIAN_VM_NAME, then [vm])")
    add_profile_args(vm_parser)
    vm_parser.add_argument("--host", help="VM host name or address "
                           "(default: MEROVINGIAN_VM_HOST, then the settings file)")
    vm_parser.add_argument("--user", help="ssh user on the VM")
    vm_parser.add_argument("--port", help="ssh port on the VM (default: 22)")
    vm_parser.add_argument("--identity", help="ssh private key file")
    vm_parser.add_argument("--jobs", type=positive_int,
                           help="Most compile jobs and tests at once "
                                "(default: one per 1.5 GiB of VM memory)")
    vm_parser.add_argument("--clean", action="store_true",
                           help="Wipe the VM's build directory before configuring")
    vm_parser.add_argument("--exec", dest="exec_command", nargs=argparse.REMAINDER,
                           help="Sync, then run this command in the VM checkout instead "
                                "of building; must come last")

    # deb
    subparsers.add_parser("deb", help="Build Debian .deb package")

    # rpm
    subparsers.add_parser("rpm", help="Build RPM package")

    # pkg
    subparsers.add_parser("pkg", help="Build FreeBSD .pkg package")

    # static
    static_parser = subparsers.add_parser("static",
                                           help="Build portable static Linux tarball")
    static_parser.add_argument("--version", default="",
                               help="Package version (default: from script)")

    args = parser.parse_args()

    handlers = {
        "linux": build_linux,
        "bsd": build_bsd,
        "wsl": build_wsl,
        "vm": build_vm,
        "deb": build_deb,
        "rpm": build_rpm,
        "pkg": build_pkg,
        "static": build_static,
    }

    handler = handlers[args.target]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
