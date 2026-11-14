#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for `build.py vm` (ADR-0752): settings, named VMs, paths, the sync plan
and archive, the script the remote host runs on Linux and the BSDs, the
`--jobs` and `--hardening` options of `build-linux.sh` and `build-bsd.sh`, and
`remote-host-setup.sh`."""
from __future__ import annotations

import argparse
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LINUX_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-linux.sh"
BSD_BUILD_WRAPPER = REPO_ROOT / "scripts" / "build-bsd.sh"
REMOTE_HOST_SETUP = REPO_ROOT / "scripts" / "remote-host-setup.sh"

_spec = importlib.util.spec_from_file_location("merovingian_build", REPO_ROOT / "build.py")
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)


def vm_args(**overrides) -> argparse.Namespace:
    values = {"host": None, "user": None, "port": None, "identity": None, "jobs": None,
              "vm": None}
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

    def test_a_named_vm_reads_its_own_section_and_builds_into_its_own_directory(self) -> None:
        # GIVEN a default VM and a named one in the settings file.
        self.config.write_text("[vm]\nhost = linux-vm\nuser = claude\n\n"
                               "[vm.freebsd]\nhost = bsd-vm\nuser = builder\njobs = 4\n",
                               encoding="utf-8")

        # WHEN each is chosen, by --vm and by MEROVINGIAN_VM_NAME, and without a name.
        named = build.load_vm_settings(vm_args(vm="freebsd"), {}, self.config)
        from_env = build.load_vm_settings(vm_args(), {"MEROVINGIAN_VM_NAME": "freebsd"}, self.config)
        default = build.load_vm_settings(vm_args(), {}, self.config)

        # THEN a named VM takes only its own section, and its logs land in build-vm-<name>.
        self.assertEqual(("bsd-vm", "builder", 4, "freebsd"),
                         (named.host, named.user, named.jobs, named.name))
        self.assertEqual(named, from_env)
        self.assertEqual(("linux-vm", "claude", None, ""),
                         (default.host, default.user, default.jobs, default.name))
        self.assertEqual("build-vm-freebsd", build.vm_default_builddir(named))
        self.assertEqual("build-vm", build.vm_default_builddir(default))

    def test_an_unknown_or_malformed_vm_name_is_refused(self) -> None:
        # GIVEN a settings file with one named VM.
        self.config.write_text("[vm.freebsd]\nhost = bsd-vm\n", encoding="utf-8")
        for name in ("openbsd", "../x", "Free BSD", "-x"):
            # WHEN another name, or one that is not a plain lower-case name, is chosen.
            # THEN it is refused rather than falling back to another VM.
            with self.subTest(name=name), self.assertRaises(build.VmError):
                build.load_vm_settings(vm_args(vm=name), {}, self.config)
        # WHEN the file is absent THEN a named VM is refused too.
        with self.assertRaises(build.VmError):
            build.load_vm_settings(vm_args(vm="freebsd"), {}, self.dir / "absent.ini")

    def test_build_options_reach_the_remote_build_script(self) -> None:
        # GIVEN build.py vm options, including --hardening, which both build scripts accept.
        args = argparse.Namespace(cc="clang", cxx="clang++", wrap_mode="forcefallback", profile="",
                                  buildtype="", sanitize="", coverage=False, build_fuzz=False,
                                  hardening=True, no_tests=False, setup_only=False,
                                  compile_only=False)

        # WHEN the remote build command is formed, with and without a fixed job count.
        sized = build._vm_build_line(args, "build-vm-freebsd", None)
        fixed = build._vm_build_line(args, "build-vm", 3)

        # THEN it runs the host's own build script with the options and the right job count.
        self.assertIn('sh "./scripts/$build_script"', sized)
        self.assertIn("'--hardening'", sized)
        self.assertIn("'build-vm-freebsd'", sized)
        self.assertTrue(sized.endswith('--jobs "$jobs"'))
        self.assertTrue(fixed.endswith("--jobs '3'") or fixed.endswith("--jobs 3"))

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

    def test_a_tracked_file_replaced_on_disk_by_a_symbolic_link_is_refused(self) -> None:
        # GIVEN a tracked regular file replaced, uncommitted, by a link to a file outside the checkout.
        outside_dir = tempfile.TemporaryDirectory()
        self.addCleanup(outside_dir.cleanup)
        outside = Path(outside_dir.name) / "secret.txt"
        outside.write_text("secret\n", encoding="utf-8")
        (self.repo / "src" / "a.cpp").unlink()
        try:
            os.symlink(outside, self.repo / "src" / "a.cpp")
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"cannot create a symbolic link here: {error}")

        # WHEN the files to send are listed.
        # THEN the link is refused rather than followed to its target.
        with self.assertRaisesRegex(build.VmError, "src/a.cpp"):
            build.vm_local_files(self.repo)

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
                                                ("sh", "tar", "python3", "comm", "cut", "sort")),
                     "needs a POSIX host with tar and python3")
class VmRemoteScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.source = Path(self.temp.name) / "source"
        self.stubs = Path(self.temp.name) / "stubs"
        self.home.mkdir()
        self.source.mkdir()
        self.stubs.mkdir()
        self.checkout = self.home / build.VM_REMOTE_ROOT / "co"
        self.path = os.environ.get("PATH", "")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def stub(self, name: str, body: str) -> None:
        """Put a command on PATH ahead of the real one, as another system would have it."""
        script = self.stubs / name
        script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        script.chmod(0o755)
        self.path = f"{self.stubs}{os.pathsep}{os.environ.get('PATH', '')}"

    TOKEN = "0123456789abcdef"

    def prepare(self, files: dict[str, bytes], run_line: str, **options) -> tuple[str, bytes]:
        """The script and archive build_vm would send, planned against the VM's manifest now."""
        local = {}
        for path, data in files.items():
            (self.source / path).parent.mkdir(parents=True, exist_ok=True)
            (self.source / path).write_bytes(data)
            local[path] = (0o644, len(data), 1_700_000_000 + len(data))
        manifest = self.checkout / build.VM_MANIFEST
        baseline = manifest.read_bytes() if manifest.exists() else b""
        remote = build.parse_vm_manifest(baseline.decode("utf-8"))
        archive = io.BytesIO()
        build.write_vm_sync_archive(archive, self.source, local, build.plan_vm_sync(local, remote))
        script = build.vm_remote_script("co", run_line, token=self.TOKEN,
                                        baseline_sha256=build.vm_manifest_digest(baseline),
                                        stale=build.plan_vm_stale(local, remote), **options)
        return script, archive.getvalue()

    @property
    def run_dir(self) -> Path:
        return self.checkout / build.vm_run_dir(self.TOKEN)

    def environment(self) -> dict[str, str]:
        return {**os.environ, "HOME": str(self.home), "PATH": self.path}

    def sync(self, files: dict[str, bytes], run_line: str, **options) -> subprocess.CompletedProcess:
        script, archive = self.prepare(files, run_line, **options)
        return subprocess.run(["sh", "-c", script], input=archive, capture_output=True,
                              env=self.environment())

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

    def test_old_logs_are_gone_even_when_unpacking_fails(self) -> None:
        # GIVEN a checkout with a previous build's test log.
        self.assertEqual(0, self.sync({"a": b"a"}, "true").returncode)
        logs = self.checkout / "build-vm" / "meson-logs"
        logs.mkdir(parents=True)
        (logs / "testlog.txt").write_text("Ok: 99\n", encoding="utf-8")
        script, _ = self.prepare({"a": b"a"}, "true", builddir="build-vm")

        # WHEN the archive that arrives is not a tar archive, as when the stream breaks.
        result = subprocess.run(["sh", "-c", script], input=b"not a tar archive" * 64,
                                capture_output=True, env=self.environment())

        # THEN the run fails, and neither the build's log nor a snapshot of it is left to fetch.
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((logs / "testlog.txt").exists())
        self.assertFalse((self.run_dir / "testlog.txt").exists())

    def test_a_file_that_becomes_a_directory_and_back_syncs(self) -> None:
        # GIVEN a synced file x.
        self.assertEqual(0, self.sync({"x": b"file"}, "true").returncode)
        shutil.rmtree(self.source)
        self.source.mkdir()

        # WHEN x becomes a directory holding x/y, and then a file again.
        to_directory = self.sync({"x/y": b"nested"}, "true")
        self.assertEqual(0, to_directory.returncode, to_directory.stderr)
        self.assertEqual(b"nested", (self.checkout / "x" / "y").read_bytes())
        shutil.rmtree(self.source)
        self.source.mkdir()
        to_file = self.sync({"x": b"file again"}, "true")

        # THEN each sync unpacks, because the stale path is removed before unpacking.
        self.assertEqual(0, to_file.returncode, to_file.stderr)
        self.assertEqual(b"file again", (self.checkout / "x").read_bytes())

    def test_a_manifest_changed_since_planning_stops_the_run_untouched(self) -> None:
        # GIVEN a run planned against the VM's manifest.
        self.assertEqual(0, self.sync({"a": b"a"}, "true").returncode)
        script, archive = self.prepare({"a": b"a-changed", "b": b"b"}, "touch ran")

        # WHEN another run replaces that manifest before this one takes the lock.
        manifest = self.checkout / build.VM_MANIFEST
        manifest.write_text(manifest.read_text(encoding="utf-8") + "644\t1\t1\tother\n",
                            encoding="utf-8")
        result = subprocess.run(["sh", "-c", script], input=archive, capture_output=True,
                                env=self.environment())

        # THEN it exits for build.py to retry, marks why, and neither unpacks nor runs anything.
        self.assertEqual(build.VM_BASELINE_CHANGED, result.returncode, result.stderr)
        self.assertTrue((self.run_dir / build.VM_BASELINE_MARKER).exists())
        self.assertEqual(b"a", (self.checkout / "a").read_bytes())
        self.assertFalse((self.checkout / "b").exists())
        self.assertFalse((self.checkout / "ran").exists())

    def test_a_run_keeps_its_own_log_snapshot_and_exit_status(self) -> None:
        # GIVEN a build run whose command writes a test log and fails.
        run_line = "mkdir -p build-vm/meson-logs && echo 'Ok: 7' > build-vm/meson-logs/testlog.txt && exit 4"

        # WHEN it runs.
        result = self.sync({"a": b"a"}, run_line, builddir="build-vm")

        # THEN its status comes back and its log is copied where only this run's token reaches it.
        self.assertEqual(4, result.returncode, result.stderr)
        self.assertEqual(b"Ok: 7\n", (self.run_dir / "testlog.txt").read_bytes())
        self.assertFalse((self.run_dir / "testlog.json").exists())

    def test_jobs_are_sized_from_memory_and_capped_at_the_cpu_count(self) -> None:
        # GIVEN a build run that sizes its jobs.
        # WHEN it prints the value it chose.
        result = self.sync({"a": b"a"}, 'echo "jobs=$jobs"', builddir="build-vm", size_jobs=True)

        # THEN it is at least one and no more than the CPUs.
        self.assertEqual(0, result.returncode, result.stderr)
        jobs = int(result.stdout.decode().strip().split("=")[1])
        self.assertGreaterEqual(jobs, 1)
        self.assertLessEqual(jobs, os.cpu_count())

    def test_a_bsd_host_runs_build_bsd_sh_and_sizes_jobs_from_sysctl(self) -> None:
        # GIVEN a host whose uname says FreeBSD, with 8 GiB of memory and 8 CPUs by sysctl.
        self.stub("uname", "echo FreeBSD")
        self.stub("sysctl", 'case "$2" in hw.physmem) echo 8589934592 ;; hw.ncpu) echo 8 ;;'
                            ' *) exit 1 ;; esac')

        # WHEN a build run reports what it chose.
        result = self.sync({"a": b"a"}, 'echo "$build_script jobs=$jobs"', builddir="build-vm",
                           size_jobs=True)

        # THEN it picks the BSD build script and one job per 1.5 GiB: five, under the eight CPUs.
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("build-bsd.sh jobs=5", result.stdout.decode().strip())

    def test_a_linux_host_runs_build_linux_sh(self) -> None:
        # GIVEN a host whose uname says Linux.
        self.stub("uname", "echo Linux")
        # WHEN a run reports its build script.
        result = self.sync({"a": b"a"}, 'echo "$build_script"')
        # THEN it is the Linux one.
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("build-linux.sh", result.stdout.decode().strip())

    def test_an_unsupported_system_is_refused_before_anything_is_unpacked(self) -> None:
        # GIVEN a host whose uname names a system build.py vm has no build script for.
        self.stub("uname", "echo Darwin")

        # WHEN a run is sent to it.
        result = self.sync({"a": b"a"}, "touch ran")

        # THEN it fails with exit 2, naming the system, and neither unpacks nor runs anything.
        self.assertEqual(2, result.returncode)
        self.assertIn(b"unsupported remote system Darwin", result.stderr)
        self.assertFalse(self.checkout.exists())

    def test_a_second_run_waits_for_the_lock_and_then_runs(self) -> None:
        # GIVEN another process holding the ssh user's lock, as a running suite does.
        root = self.home / build.VM_REMOTE_ROOT
        root.mkdir(parents=True)
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import fcntl, sys\n"
             f"lock = open({str(root / '.lock')!r}, 'a')\n"
             "fcntl.flock(lock, fcntl.LOCK_EX)\n"
             "print('held', flush=True)\n"
             "sys.stdin.read()\n"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual("held", holder.stdout.readline().strip())
            script, archive = self.prepare({"a": b"a"}, "echo ran")
            # The run reads its archive only once it holds the lock, so the archive
            # comes from a file: written into a pipe, it can exceed the pipe's buffer
            # (16 KiB on FreeBSD) and block this test before the holder lets go.
            archive_file = Path(self.temp.name) / "archive.tar"
            archive_file.write_bytes(archive)

            # WHEN a run starts while it is held.
            with archive_file.open("rb") as stdin:
                waiting = subprocess.Popen(["sh", "-c", script], stdin=stdin,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=self.environment())
            time.sleep(1)

            # THEN it has not run yet.
            self.assertIsNone(waiting.poll())
        finally:
            holder.communicate(timeout=30)

        # WHEN the holder exits THEN the waiting run takes the lock, says it waited, and runs.
        stdout, stderr = waiting.communicate(timeout=30)
        self.assertEqual(0, waiting.returncode, stderr)
        self.assertIn(b"another run holds the VM lock; waiting for it", stderr)
        self.assertEqual(b"ran\n", stdout)


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
class BuildScriptJobsAndHardeningTests(unittest.TestCase):
    """build.py vm runs build-linux.sh or build-bsd.sh with --jobs, and build.py
    linux and bsd pass --hardening to them, so both scripts take both options."""

    def run_wrapper(self, wrapper: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(wrapper), *args], capture_output=True, text=True)

    def test_jobs_takes_a_positive_whole_number(self) -> None:
        for wrapper in (LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER):
            # GIVEN unusable --jobs values.
            for bad in ("0", "-1", "two", "", "07"):
                # WHEN the script parses them THEN it fails before configuring anything.
                result = self.run_wrapper(wrapper, "--jobs", bad)
                with self.subTest(wrapper=wrapper.name, bad=bad):
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("--jobs", result.stderr)
            # GIVEN a valid value WHEN followed by --help THEN parsing accepts it and documents it.
            accepted = self.run_wrapper(wrapper, "--jobs", "3", "--help")
            with self.subTest(wrapper=wrapper.name):
                self.assertEqual(0, accepted.returncode, accepted.stderr)
                self.assertIn("--jobs <n>", accepted.stdout)

    def test_jobs_and_hardening_reach_meson(self) -> None:
        for wrapper in (LINUX_BUILD_WRAPPER, BSD_BUILD_WRAPPER):
            # GIVEN --jobs 3 and --hardening.
            # WHEN the script previews its commands.
            result = self.run_wrapper(wrapper, "--dry-run", "--jobs", "3", "--hardening",
                                      "--builddir", "build-x")

            # THEN Meson configures hardening, compiles with three jobs and tests three at once.
            with self.subTest(wrapper=wrapper.name):
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("-Dhardening=true", result.stdout)
                self.assertIn("meson compile -C build-x -j 3", result.stdout)
                self.assertIn("--num-processes 3", result.stdout)


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

    def test_a_freebsd_host_gets_the_ci_packages_from_pkg_and_no_virtual_environment(self) -> None:
        # GIVEN FreeBSD.
        # WHEN the setup is previewed.
        result = self.dry_run('NAME=FreeBSD\nVERSION_ID="15.1"\nID=freebsd\n')

        # THEN pkg installs Meson, the libraries build-bsd.sh needs and python3 for build.py vm's lock,
        # and no apt-get or virtual environment is involved.
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("pkg install -y meson ninja llvm", result.stdout)
        for package in ("libsodium", "openssl", "postgresql17-client", "curl", "python3", "gmake",
                        "catch2", "png", "libjpeg-turbo"):
            self.assertIn(f" {package}", result.stdout)
        self.assertNotIn("apt-get", result.stdout)
        self.assertNotIn("venv", result.stdout)

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
