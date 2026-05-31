#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Unified build script for Merovingian.
# Delegates to the shell scripts in scripts/ for each build target.

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

PROFILES = ("debug", "release", "sanitizer", "coverage", "fuzz", "hardened")


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
        "deb": build_deb,
        "rpm": build_rpm,
        "pkg": build_pkg,
        "static": build_static,
    }

    handler = handlers[args.target]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
