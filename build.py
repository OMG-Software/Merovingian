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
import shutil
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping

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
VM_SETTING_NAMES = ("host", "user", "port", "identity", "jobs")
_VM_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]*$")
_VM_USER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
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


def add_common_dev_args(parser: argparse.ArgumentParser, builddir_default: str = "build"):
    parser.add_argument("--builddir", default=builddir_default,
                        help=f"Meson build directory (default: {builddir_default})")
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
    return run_script(script, cmd_args)


def build_wsl(args: argparse.Namespace) -> int:
    return run_wsl(args, [])


class VmError(Exception):
    """A vm setting, path or checkout that build.py refuses to work with."""


@dataclass(frozen=True)
class VmSettings:
    """Where and how build.py vm reaches the VM. jobs None means size by memory."""
    host: str
    user: str
    port: int
    identity: str
    jobs: int | None


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
    then the [vm] section of config_path. Raises VmError on a missing host or a
    value ssh could read as an option."""
    file_values: dict[str, str] = {}
    if config_path.is_file():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(config_path, encoding="utf-8")
        except configparser.Error as error:
            raise VmError(f"cannot read {config_path}: {error}") from error
        if parser.has_section("vm"):
            for name, value in parser.items("vm"):
                if name not in VM_SETTING_NAMES:
                    raise VmError(f"{config_path}: unknown [vm] setting {name!r}")
                file_values[name] = value.strip()

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
                      f"or set host in the [vm] section of {config_path}")
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

    return VmSettings(host=host, user=user, port=int(port_text), identity=identity, jobs=jobs)


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
            status = (repo_root / path).stat()
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


def vm_remote_script(checkout: str, run_line: str, *, builddir: str = "",
                     clean: bool = False, size_jobs: bool = False) -> str:
    """The POSIX sh script the VM runs for one build.py vm call.

    It takes the ssh user's lock, so a second run as that user (from any checkout) waits, then
    unpacks the archive on stdin into ~/merovingian-vm/<checkout>, deletes the
    files the previous manifest listed and the new one does not, and installs
    the new manifest. With builddir it removes that build's old test logs (and
    the whole directory with clean) so a failed build cannot leave a stale
    testlog behind. With size_jobs it sets $jobs from the VM's memory. Then it
    runs run_line, still holding the lock."""
    lines = [
        "set -eu",
        f'root="$HOME"/{quote_bash(VM_REMOTE_ROOT)}',
        f'checkout="$root"/{quote_bash(checkout)}',
        'mkdir -p "$checkout/.vm-sync"',
        'exec 9>"$root/.lock"',
        "if ! flock -n 9; then",
        "    echo 'build.py vm: another run holds the VM lock; waiting for it' >&2",
        "    flock 9",
        "fi",
        'cd "$checkout"',
        f"rm -f {VM_MANIFEST_NEXT}",
        "tar -xf -",
        f"if [ ! -f {VM_MANIFEST_NEXT} ]; then",
        "    echo 'build.py vm: the archive carried no manifest' >&2",
        "    exit 2",
        "fi",
        f"touch {VM_MANIFEST}",
        f"LC_ALL=C cut -f4- {VM_MANIFEST} | LC_ALL=C sort > .vm-sync/old.list",
        f"LC_ALL=C cut -f4- {VM_MANIFEST_NEXT} | LC_ALL=C sort > .vm-sync/new.list",
        "LC_ALL=C comm -23 .vm-sync/old.list .vm-sync/new.list | while IFS= read -r stale; do",
        "    case \"$stale\" in",
        "        ''|/*|..|../*|*/..|*/../*) continue ;;",
        "    esac",
        "    rm -f -- \"$stale\"",
        "done",
        f"mv -f {VM_MANIFEST_NEXT} {VM_MANIFEST}",
    ]
    if builddir:
        quoted = quote_bash(builddir)
        if clean:
            lines.append(f"rm -rf -- {quoted}")
        lines += [f"rm -f -- {quoted}/meson-logs/{name}" for name in VM_TESTLOGS]
    if size_jobs:
        lines += [
            "mem_kib=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)",
            "cpus=$(nproc)",
            f"jobs=$((mem_kib / {VM_MEMORY_PER_JOB_KIB}))",
            '[ "$jobs" -ge 1 ] || jobs=1',
            '[ "$jobs" -le "$cpus" ] || jobs=$cpus',
            'echo "build.py vm: $jobs parallel jobs ($cpus CPUs, $((mem_kib / 1024)) MiB memory)" >&2',
        ]
    lines.append(run_line)
    return "\n".join(lines) + "\n"


def _vm_build_line(args: argparse.Namespace, jobs: int | None) -> str:
    """The build-linux.sh call for a build run; uses $jobs from the script when jobs is None."""
    build_args = ["--builddir", args.builddir, "--cc", args.cc, "--cxx", args.cxx,
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
    return (f'exec env PATH="$HOME/.local/bin:$PATH" sh ./scripts/build-linux.sh '
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
    """Sync this checkout to the Linux VM over ssh and build, test or run a
    command there; see "Building on a Linux VM" in docs/dev-environment.md."""
    try:
        settings = load_vm_settings(args, os.environ, vm_config_path(os.environ))
        builddir = validate_vm_builddir(args.builddir)
        if args.exec_command is not None and not args.exec_command:
            raise VmError("--exec needs a command to run")
        local = vm_local_files(REPO_ROOT)
    except (VmError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    ssh = vm_ssh_command(settings)
    checkout = vm_checkout_name(REPO_ROOT)
    remote_dir = f"{VM_REMOTE_ROOT}/{checkout}"
    probe = subprocess.run(ssh + [f"cat -- {quote_bash(remote_dir + '/' + VM_MANIFEST)} 2>/dev/null || true"],
                           capture_output=True)
    if probe.returncode != 0:
        sys.stderr.write(probe.stderr.decode("utf-8", "replace"))
        print(f"error: cannot reach the VM at {ssh[-1]} (ssh exit {probe.returncode})",
              file=sys.stderr)
        return 2
    send = plan_vm_sync(local, parse_vm_manifest(probe.stdout.decode("utf-8", "replace")))

    runs_tests = args.exec_command is None and not (args.no_tests or args.setup_only
                                                    or args.compile_only)
    if args.exec_command is not None:
        run_line = ("exec env MEROVINGIAN_TEST_DISABLE_HARDENING=1 "
                    + " ".join(quote_bash(arg) for arg in args.exec_command))
        script = vm_remote_script(checkout, run_line)
    else:
        script = vm_remote_script(checkout, _vm_build_line(args, settings.jobs),
                                  builddir=builddir, clean=args.clean,
                                  size_jobs=settings.jobs is None)

    print(f"build.py vm: sending {len(send)} of {len(local)} files to "
          f"{ssh[-1]}:~/{remote_dir}", file=sys.stderr)
    if args.dry_run:
        print(script)
        return 0

    local_logs = REPO_ROOT / builddir / "meson-logs"
    if runs_tests:
        for name in VM_TESTLOGS:
            (local_logs / name).unlink(missing_ok=True)

    process = subprocess.Popen(ssh + ["sh -c " + quote_bash(script)], stdin=subprocess.PIPE)
    try:
        write_vm_sync_archive(process.stdin, REPO_ROOT, local, send)
    except BrokenPipeError:
        pass
    finally:
        try:
            process.stdin.close()
        except BrokenPipeError:
            pass
    status = process.wait()

    if runs_tests:
        local_logs.mkdir(parents=True, exist_ok=True)
        ignore_file = REPO_ROOT / builddir / ".gitignore"
        if not ignore_file.exists():
            ignore_file.write_text("*\n", encoding="utf-8")
        fetched = False
        try:
            for name in VM_TESTLOGS:
                data = vm_fetch(ssh, f"{remote_dir}/{builddir}/meson-logs/{name}")
                if data is not None:
                    (local_logs / name).write_bytes(data)
                    fetched = fetched or name == "testlog.txt"
        except VmError as error:
            # The run may well have written its log; say so rather than "no testlog",
            # and never exit 0 without a log the result can be read from.
            print(f"error: {error}", file=sys.stderr)
            print(f"build.py vm: the build exited {status}; its logs are still on the VM "
                  f"under ~/{remote_dir}/{builddir}/meson-logs/", file=sys.stderr)
            return status or 2
        if fetched:
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
        "vm", help="Build and test on a Linux VM over ssh (docs/dev-environment.md)")
    add_common_dev_args(vm_parser, VM_DEFAULT_BUILDDIR)
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
