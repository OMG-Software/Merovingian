#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for `build.py vm` (ADR-0752): settings, paths, the sync plan and archive,
the script the VM runs, and `build-linux.sh --jobs`."""
from __future__ import annotations

import argparse
import importlib.util
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LINUX_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-linux.sh"
REMOTE_HOST_SETUP = REPO_ROOT / "scripts" / "remote-host-setup.sh"

_spec = importlib.util.spec_from_file_location("merovingian_build", REPO_ROOT / "build.py")
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


def vm_args(**overrides) -> argparse.Namespace:
    values = {"host": None, "user": None, "port": None, "identity": None, "jobs": None}
    values.update(overrides)
    return argparse.Namespace(**values)


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class VmSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.config = self.dir / "vm.ini"
        self.key = self.dir / "key"
        self.key.write_text("not a real key\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_command_line_beats_environment_which_beats_the_settings_file(self) -> None:
        # GIVEN a settings file, environment variables and command-line values for the host.
        self.config.write_text(f"[vm]\nhost = file-host\nuser = fileuser\nport = 2222\n"
                               f"identity = {self.key}\njobs = 3\n", encoding="utf-8")
        env = {"MEROVINGIAN_VM_HOST": "env-host", "MEROVINGIAN_VM_USER": "envuser"}

        # WHEN the settings are resolved with and without a command-line host.
        from_cli = build.load_vm_settings(vm_args(host="cli-host"), env, self.config)
        from_env = build.load_vm_settings(vm_args(), env, self.config)
        from_file = build.load_vm_settings(vm_args(), {}, self.config)

        # THEN each source wins only where the ones before it say nothing.
        self.assertEqual(("cli-host", "envuser"), (from_cli.host, from_cli.user))
        self.assertEqual(("env-host", "envuser"), (from_env.host, from_env.user))
        self.assertEqual(build.VmSettings("file-host", "fileuser", 2222, str(self.key), 3),
                         from_file)

    def test_missing_host_and_option_like_values_are_refused(self) -> None:
        # GIVEN no host anywhere, and values ssh would read as options or that are malformed.
        cases = [
            vm_args(),
            vm_args(host="-oProxyCommand=touch /tmp/x"),
            vm_args(host="host name"),
            vm_args(host="vm", user="-luser"),
            vm_args(host="vm", port="0"),
            vm_args(host="vm", port="65536"),
            vm_args(host="vm", port="22x"),
            vm_args(host="vm", identity=str(self.dir / "absent")),
        ]
        for args in cases:
            # WHEN each is resolved.
            # THEN it is refused before ssh ever runs.
            with self.subTest(args=args), self.assertRaises(build.VmError):
                build.load_vm_settings(args, {}, self.config)

    def test_unknown_setting_and_bad_jobs_in_the_file_are_refused(self) -> None:
        for body in ("[vm]\nhost = vm\nhots = typo\n", "[vm]\nhost = vm\njobs = 0\n",
                     "[vm]\nhost = vm\njobs = two\n"):
            # GIVEN a settings file with a misspelt key or an unusable jobs value.
            self.config.write_text(body, encoding="utf-8")
            # WHEN it is read.
            # THEN build.py refuses it rather than guessing.
            with self.subTest(body=body), self.assertRaises(build.VmError):
                build.load_vm_settings(vm_args(), {}, self.config)

    def test_ssh_never_prompts_and_refuses_unknown_host_keys(self) -> None:
        # GIVEN settings with a key file.
        settings = build.VmSettings("vm.example", "builder", 2200, str(self.key), None)

        # WHEN the ssh command is built.
        command = build.vm_ssh_command(settings)

        # THEN it is batch-only, pins host keys, uses only that key, and ends options before the host.
        self.assertIn("BatchMode=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertEqual(["-p", "2200"], command[command.index("-p"):command.index("-p") + 2])
        self.assertEqual(["--", "builder@vm.example"], command[-2:])


class VmPathTests(unittest.TestCase):
    def test_builddir_must_stay_under_a_build_prefixed_relative_path(self) -> None:
        # GIVEN accepted and refused build directories.
        for good in ("build-vm", "build", "build-vm/asan", "build_tsan"):
            # WHEN validated THEN accepted unchanged.
            self.assertEqual(good, build.validate_vm_builddir(good))
        for bad in ("out", "/build-vm", "../build-vm", "build-vm/../src", "build-vm/.",
                    "build vm", "build-vm/", ""):
            with self.subTest(bad=bad), self.assertRaises(build.VmError):
                build.validate_vm_builddir(bad)

    def test_checkout_name_is_stable_per_path_and_distinct_between_paths(self) -> None:
        # GIVEN two checkouts with the same directory name in different places.
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = Path(first) / "Merovingian"
            two = Path(second) / "Merovingian"
            one.mkdir()
            two.mkdir()

            # WHEN each is named twice.
            # THEN the name repeats for one path, differs between paths, and is shell-safe.
            self.assertEqual(build.vm_checkout_name(one), build.vm_checkout_name(one))
            self.assertNotEqual(build.vm_checkout_name(one), build.vm_checkout_name(two))
            self.assertRegex(build.vm_checkout_name(one), r"^Merovingian-[0-9a-f]{12}$")


@unittest.skipUnless(shutil.which("git"), "needs git")
class VmLocalFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-q")
        (self.repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "a.cpp").write_bytes(b"int a;\n")
        (self.repo / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.repo / "gone.txt").write_text("x\n", encoding="utf-8")
        git(self.repo, "add", ".gitignore", "src/a.cpp", "run.sh", "gone.txt")
        git(self.repo, "update-index", "--chmod=+x", "run.sh")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_tracked_and_new_files_are_sent_but_build_and_dot_directories_are_not(self) -> None:
        # GIVEN a new source file, build output, a dot directory, an ignored file and a deleted file.
        (self.repo / "src" / "new.cpp").write_text("int b;\n", encoding="utf-8")
        for path in ("build-vm/meson-logs/testlog.txt", "build-wsl/x.o", ".cache/c", "ignored.txt"):
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_text("skip\n", encoding="utf-8")
        (self.repo / "gone.txt").unlink()

        # WHEN the files to sync are listed.
        files = build.vm_local_files(self.repo)

        # THEN only the tracked files on disk and the new source file are sent, with git's modes.
        self.assertEqual({".gitignore", "run.sh", "src/a.cpp", "src/new.cpp"}, set(files))
        self.assertEqual(0o755, files["run.sh"][0])
        self.assertEqual(0o644, files["src/a.cpp"][0])
        self.assertEqual(len(b"int a;\n"), files["src/a.cpp"][1])

    def test_a_tracked_symbolic_link_is_refused(self) -> None:
        # GIVEN a symbolic link recorded in the index.
        blob = subprocess.run(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                              input=b"src/a.cpp", capture_output=True, check=True).stdout.decode().strip()
        git(self.repo, "update-index", "--add", "--cacheinfo", f"120000,{blob},link")

        # WHEN the files to sync are listed.
        # THEN build.py refuses rather than sending a link the VM would follow.
        with self.assertRaises(build.VmError):
            build.vm_local_files(self.repo)


class VmManifestAndArchiveTests(unittest.TestCase):
    def test_only_changed_files_are_planned_and_bad_manifest_lines_are_resent(self) -> None:
        # GIVEN local files and what the VM's manifest says it last received.
        local = {"a": (0o644, 1, 10), "b": (0o644, 2, 20), "c": (0o755, 3, 30), "d": (0o644, 4, 40)}
        remote_text = build.format_vm_manifest({"a": (0o644, 1, 10), "b": (0o644, 2, 99),
                                                "c": (0o644, 3, 30)}) + "garbage line\n644\tx\t1\td\n"

        # WHEN the sync is planned.
        send = build.plan_vm_sync(local, build.parse_vm_manifest(remote_text))

        # THEN unchanged files are skipped; a changed mtime or mode, or an unreadable entry, is resent.
        self.assertEqual(["b", "c", "d"], send)

    def test_archive_carries_the_sent_files_then_the_full_manifest(self) -> None:
        # GIVEN two files on disk, of which one is to be sent.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dir").mkdir()
            (root / "dir" / "x.sh").write_bytes(b"echo x\n")
            (root / "y.txt").write_bytes(b"y\n")
            local = {"dir/x.sh": (0o755, 7, 1_700_000_000), "y.txt": (0o644, 2, 1_700_000_001)}
            stream = io.BytesIO()

            # WHEN the archive is written.
            build.write_vm_sync_archive(stream, root, local, ["dir/x.sh"])

        # THEN it holds that file with its mode and mtime, and the manifest of both files last.
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r") as archive:
            members = archive.getmembers()
            self.assertEqual(["dir/x.sh", build.VM_MANIFEST_NEXT], [m.name for m in members])
            self.assertEqual((0o755, 1_700_000_000), (members[0].mode, members[0].mtime))
            self.assertEqual(b"echo x\n", archive.extractfile(members[0]).read())
            manifest = archive.extractfile(members[1]).read().decode("utf-8")
        self.assertEqual(local, build.parse_vm_manifest(manifest))


@unittest.skipUnless(os.name == "posix" and all(shutil.which(tool) for tool in
                                                ("sh", "tar", "flock", "comm", "cut", "sort")),
                     "needs a POSIX host with tar and flock")
class VmRemoteScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.source = Path(self.temp.name) / "source"
        self.home.mkdir()
        self.source.mkdir()
        self.checkout = self.home / build.VM_REMOTE_ROOT / "co"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def sync(self, files: dict[str, bytes], run_line: str, **options) -> subprocess.CompletedProcess:
        local = {}
        for path, data in files.items():
            (self.source / path).parent.mkdir(parents=True, exist_ok=True)
            (self.source / path).write_bytes(data)
            local[path] = (0o644, len(data), 1_700_000_000 + len(data))
        remote = build.parse_vm_manifest(
            (self.checkout / build.VM_MANIFEST).read_text(encoding="utf-8")
            if (self.checkout / build.VM_MANIFEST).exists() else "")
        archive = io.BytesIO()
        build.write_vm_sync_archive(archive, self.source, local, build.plan_vm_sync(local, remote))
        script = build.vm_remote_script("co", run_line, **options)
        return subprocess.run(["sh", "-c", script], input=archive.getvalue(), capture_output=True,
                              env={**os.environ, "HOME": str(self.home)})

    def test_files_dropped_locally_are_deleted_and_nothing_outside_is_touched(self) -> None:
        # GIVEN a first sync of two files, a build output file, and a file beside the checkout.
        first = self.sync({"src/a.cpp": b"a1", "src/b.cpp": b"b"}, "true")
        self.assertEqual(0, first.returncode, first.stderr)
        (self.checkout / "build-vm").mkdir()
        (self.checkout / "build-vm" / "obj.o").write_bytes(b"o")
        outside = self.home / build.VM_REMOTE_ROOT / "outside.txt"
        outside.write_bytes(b"keep")
        manifest = self.checkout / build.VM_MANIFEST
        manifest.write_text(manifest.read_text(encoding="utf-8") + "644\t1\t1\t../outside.txt\n",
                            encoding="utf-8")

        # WHEN the second sync drops b.cpp and changes a.cpp, and runs a command.
        second = self.sync({"src/a.cpp": b"a2-changed"}, "echo ran > ran.txt")

        # THEN b.cpp is gone, a.cpp is current, build output and the path outside survive,
        # and the command ran in the checkout.
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertFalse((self.checkout / "src" / "b.cpp").exists())
        self.assertEqual(b"a2-changed", (self.checkout / "src" / "a.cpp").read_bytes())
        self.assertTrue((self.checkout / "build-vm" / "obj.o").exists())
        self.assertEqual(b"keep", outside.read_bytes())
        self.assertEqual(b"ran\n", (self.checkout / "ran.txt").read_bytes())
        self.assertEqual({"src/a.cpp"}, set(build.parse_vm_manifest(manifest.read_text(encoding="utf-8"))))

    def test_a_build_run_removes_stale_test_logs_and_clean_removes_the_build(self) -> None:
        # GIVEN a checkout with a previous build's test log and object file.
        self.assertEqual(0, self.sync({"a": b"a"}, "true").returncode)
        logs = self.checkout / "build-vm" / "meson-logs"
        logs.mkdir(parents=True)
        (logs / "testlog.txt").write_text("Ok: 99\n", encoding="utf-8")
        (self.checkout / "build-vm" / "obj.o").write_bytes(b"o")

        # WHEN a build run fails before writing a log.
        failed = self.sync({"a": b"a"}, "exit 3", builddir="build-vm")

        # THEN its exit status comes back and the old log cannot be mistaken for its result.
        self.assertEqual(3, failed.returncode)
        self.assertFalse((logs / "testlog.txt").exists())
        self.assertTrue((self.checkout / "build-vm" / "obj.o").exists())

        # WHEN a clean run follows THEN the build directory is gone before the command runs.
        cleaned = self.sync({"a": b"a"}, "test ! -e build-vm", builddir="build-vm", clean=True)
        self.assertEqual(0, cleaned.returncode, cleaned.stderr)

    def test_jobs_are_sized_from_memory_and_capped_at_the_cpu_count(self) -> None:
        # GIVEN a build run that sizes its jobs.
        # WHEN it prints the value it chose.
        result = self.sync({"a": b"a"}, 'echo "jobs=$jobs"', builddir="build-vm", size_jobs=True)

        # THEN it is at least one and no more than the CPUs.
        self.assertEqual(0, result.returncode, result.stderr)
        jobs = int(result.stdout.decode().strip().split("=")[1])
        self.assertGreaterEqual(jobs, 1)
        self.assertLessEqual(jobs, os.cpu_count())


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
class VmFetchTests(unittest.TestCase):
    """vm_fetch appends one shell command line to the ssh command, so ["sh", "-c"]
    stands in for ssh here and runs that line locally."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.environ = os.environ.copy()
        os.environ["HOME"] = str(self.home)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.environ)
        self.temp.cleanup()

    def test_a_present_file_is_read_and_a_missing_one_is_none(self) -> None:
        # GIVEN a log under the remote user's home and a path with no file.
        (self.home / "co" / "meson-logs").mkdir(parents=True)
        (self.home / "co" / "meson-logs" / "testlog.txt").write_bytes(b"Ok: 84\n")

        # WHEN both are fetched.
        # THEN the log's bytes come back, and the missing file is None.
        self.assertEqual(b"Ok: 84\n", build.vm_fetch(["sh", "-c"], "co/meson-logs/testlog.txt"))
        self.assertIsNone(build.vm_fetch(["sh", "-c"], "co/meson-logs/testlog.json"))

    def test_an_ssh_failure_is_an_error_not_a_missing_file(self) -> None:
        # GIVEN an ssh that fails as it does when the VM refuses the key (exit 255).
        refused = ["sh", "-c", "echo 'Permission denied (publickey)' >&2; exit 255", "ssh"]

        # WHEN a log is fetched through it.
        # THEN the failure is raised with its exit status, never reported as "no log".
        with self.assertRaisesRegex(build.VmError, r"exit 255.*Permission denied"):
            build.vm_fetch(refused, "co/meson-logs/testlog.txt")


@unittest.skipUnless(shutil.which("sh"), "needs sh")
class BuildLinuxJobsTests(unittest.TestCase):
    def run_wrapper(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(LINUX_BUILD_WRAPPER), *args], capture_output=True, text=True)

    def test_jobs_takes_a_positive_whole_number(self) -> None:
        # GIVEN unusable --jobs values.
        for bad in ("0", "-1", "two", "", "07"):
            # WHEN build-linux.sh parses them THEN it fails before configuring anything.
            result = self.run_wrapper("--jobs", bad)
            with self.subTest(bad=bad):
                self.assertNotEqual(0, result.returncode)
                self.assertIn("--jobs", result.stderr)
        # GIVEN a valid value WHEN followed by --help THEN parsing accepts it and documents it.
        accepted = self.run_wrapper("--jobs", "3", "--help")
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn("--jobs <n>", accepted.stdout)


@unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
class RemoteHostSetupTests(unittest.TestCase):
    def dry_run(self, os_release: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp) / "os-release"
            release.write_text(os_release, encoding="utf-8")
            return subprocess.run(
                ["sh", str(REMOTE_HOST_SETUP), "--dry-run", "--os-release", str(release),
                 "--tools-venv", "/opt/venv", "--bin-dir", "/opt/bin"],
                capture_output=True, text=True)

    def test_a_debian_family_host_gets_every_library_build_linux_checks_and_a_current_meson(self) -> None:
        for os_release in ('ID=ubuntu\n', 'ID=debian\n', 'ID=linuxmint\nID_LIKE="ubuntu debian"\n'):
            # GIVEN Ubuntu, Debian, or a derivative that names them in ID_LIKE.
            # WHEN the setup is previewed.
            result = self.dry_run(os_release)

            # THEN it installs the libraries build-linux.sh requires, and Meson 1.11+ linked into the bin dir.
            with self.subTest(os_release=os_release):
                self.assertEqual(0, result.returncode, result.stderr)
                for package in ("libsodium-dev", "libssl-dev", "libpq-dev", "libcurl4-openssl-dev",
                                "libpng-dev", "libturbojpeg0-dev", "python3-venv", "clang"):
                    self.assertIn(f" {package}", result.stdout)
                self.assertIn("'meson>=1.11' ninja", result.stdout)
                self.assertIn("ln -sf /opt/venv/bin/meson /opt/bin/meson", result.stdout)

    def test_another_distribution_is_refused_before_anything_runs(self) -> None:
        # GIVEN a distribution outside the Debian family.
        # WHEN the setup is previewed.
        result = self.dry_run('ID=fedora\nID_LIKE="rhel centos"\n')

        # THEN it fails naming the distribution and prints no command.
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ID=fedora", result.stderr)
        self.assertNotIn("+ ", result.stdout)

    def test_it_is_not_the_wsl_setup_script(self) -> None:
        # GIVEN the remote-host setup script.
        # WHEN its text is read.
        script = REMOTE_HOST_SETUP.read_text(encoding="utf-8")

        # THEN it neither runs nor tells the user to run the WSL wrapper.
        self.assertNotIn("build-wsl.sh", script)


if __name__ == "__main__":
    unittest.main()
