#!/usr/bin/env python3
"""The LiveKit SFU the packages set up beside Merovingian (ADR-0859).

The service unit, the OpenRC script, the sample livekit.yaml, the key setup
helper and the package scripts name the same account, paths and port, so a
change to one that misses another fails here rather than on an operator's host.
The setup helper runs for real: it must write two owner-only files holding one
secret, never print that secret, and never replace either file.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT = REPO_ROOT / "packaging" / "systemd" / "merovingian-livekit.service"
OPENRC = REPO_ROOT / "packaging" / "openrc" / "merovingian-livekit"
EXAMPLE = REPO_ROOT / "config" / "livekit.yaml.example"
SETUP = REPO_ROOT / "packaging" / "livekit" / "merovingian-livekit-setup"
BUILD_DEB = REPO_ROOT / "scripts" / "build-deb.sh"
POSTINST = REPO_ROOT / "packaging" / "deb" / "postinst"
SPECS = tuple(REPO_ROOT / "packaging" / name / "merovingian.spec" for name in ("rpm", "rhel", "opensuse"))

ACCOUNT = "merovingian-livekit"
CONFIG_PATH = "/etc/merovingian/livekit.yaml"
KEYS_PATH = "/etc/merovingian/livekit-keys.yaml"

SH = shutil.which("sh")


def unit_directives() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in UNIT.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result.setdefault(key, []).append(value)
    return result


def example_value(pattern: str) -> str:
    """The first uncommented line of the sample matching PATTERN, its group 1."""
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(pattern, line)
        if match:
            return match.group(1)
    raise AssertionError(f"{EXAMPLE.name} has no line matching {pattern}")


class ServiceDefinitionTest(unittest.TestCase):
    def test_the_unit_runs_livekit_as_its_own_account_with_the_sample_config(self) -> None:
        directives = unit_directives()
        self.assertEqual(directives["User"], [ACCOUNT])
        self.assertEqual(directives["Group"], [ACCOUNT])
        (exec_start,) = directives["ExecStart"]
        self.assertEqual(exec_start.split()[1:], ["--config", CONFIG_PATH])

    def test_the_unit_keeps_the_packaging_hardening_floor_and_no_capabilities(self) -> None:
        directives = unit_directives()
        for key, value in (("NoNewPrivileges", "true"), ("PrivateTmp", "true"), ("ProtectSystem", "strict"),
                           ("ProtectHome", "true"), ("PrivateDevices", "true"), ("UMask", "0077"),
                           ("CapabilityBoundingSet", ""), ("AmbientCapabilities", ""),
                           ("SystemCallFilter", "@system-service")):
            with self.subTest(key=key):
                self.assertEqual(directives[key], [value])
        (families,) = directives["RestrictAddressFamilies"]
        self.assertEqual(set(families.split()), {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"})

    def test_the_unit_is_never_started_by_the_package_on_its_own(self) -> None:
        # Installed disabled: nothing pulls it in but the operator's `systemctl enable`.
        directives = unit_directives()
        self.assertEqual(directives["WantedBy"], ["multi-user.target"])
        self.assertNotIn("RequiredBy", directives)
        self.assertNotIn("merovingian-livekit", (REPO_ROOT / "packaging" / "systemd" /
                                                 "merovingian.service").read_text(encoding="utf-8"))

    def test_the_openrc_script_matches_the_unit(self) -> None:
        text = OPENRC.read_text(encoding="utf-8")
        self.assertIn(f'command_user="{ACCOUNT}:{ACCOUNT}"', text)
        self.assertIn(f'command_args="--config {CONFIG_PATH}"', text)
        self.assertIn("umask=0077", text)


class SampleConfigTest(unittest.TestCase):
    def test_the_key_file_is_where_the_setup_helper_writes_it(self) -> None:
        self.assertEqual(example_value(r"key_file: (\S+)"), KEYS_PATH)
        self.assertIn("config_dir=/etc/merovingian\n", SETUP.read_text(encoding="utf-8"))
        self.assertIn("keys_file=$config_dir/livekit-keys.yaml\n", SETUP.read_text(encoding="utf-8"))

    def test_rooms_are_never_created_by_joining(self) -> None:
        # Merovingian creates every call's room before issuing its token (ADR-0830).
        self.assertEqual(example_value(r"  auto_create: (\S+)"), "false")

    def test_the_signalling_listener_is_loopback_on_the_port_merovingian_calls(self) -> None:
        # Every entry of bind_addresses, not just the first: a second 0.0.0.0 would expose the room service.
        lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
        start = lines.index("bind_addresses:") + 1
        addresses = []
        for line in lines[start:]:
            if line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r"  - (\S+)", line)
            if not match:
                break
            addresses.append(match.group(1))
        self.assertEqual(addresses, ["127.0.0.1"])
        port = example_value(r"port: (\d+)")
        self.assertIn(f"server.rtc.livekit.api_url=http://127.0.0.1:{port}\n", SETUP.read_text(encoding="utf-8"))


class PackagingTest(unittest.TestCase):
    INSTALLED = ("packaging/systemd/merovingian-livekit.service", "packaging/livekit/merovingian-livekit-setup",
                 "config/livekit.yaml.example")

    def test_every_linux_package_installs_the_three_files(self) -> None:
        for package in (BUILD_DEB, *SPECS):
            text = package.read_text(encoding="utf-8")
            for source in self.INSTALLED:
                with self.subTest(package=str(package.relative_to(REPO_ROOT)), source=source):
                    self.assertIn(source, text)
            with self.subTest(package=str(package.relative_to(REPO_ROOT)), mode="helper"):
                self.assertIn("install -D -m 0755 packaging/livekit/merovingian-livekit-setup", text)

    def test_every_linux_package_creates_the_account(self) -> None:
        self.assertIn(f"getent passwd {ACCOUNT}", POSTINST.read_text(encoding="utf-8"))
        for spec in SPECS:
            text = spec.read_text(encoding="utf-8")
            with self.subTest(spec=str(spec.relative_to(REPO_ROOT))):
                self.assertIn(f"groupadd -r {ACCOUNT}", text)
                self.assertRegex(text, rf"useradd -r -g {ACCOUNT} [^\n]*\\\n(?:[^\n]*\\\n)*\s+{ACCOUNT}\n")
                self.assertIn(f"%{{_unitdir}}/{ACCOUNT}.service\n", text)
                self.assertIn("%{_sbindir}/merovingian-livekit-setup\n", text)

    def test_no_package_enables_the_unit_on_install(self) -> None:
        # %systemd_post applies the host's preset policy, which may say "enable *": the unit
        # must not be handed to it. Stopping it on removal and restarting it on upgrade is fine.
        for spec in SPECS:
            text = spec.read_text(encoding="utf-8")
            with self.subTest(spec=str(spec.relative_to(REPO_ROOT))):
                post = re.findall(r"^%systemd_post .*$", text, re.MULTILINE)
                self.assertEqual(post, ["%systemd_post merovingian.service"])
                self.assertRegex(text, rf"(?m)^%systemd_preun .*\b{ACCOUNT}\.service$")
                self.assertNotRegex(text, r"(?m)^#[^\n]*(?<!%)%systemd_", "an unescaped macro in a comment expands")
        postinst = POSTINST.read_text(encoding="utf-8")
        self.assertNotRegex(postinst, rf"enable[^\n]*{ACCOUNT}")
        self.assertNotIn("deb-systemd-helper", postinst)


@unittest.skipUnless(os.name == "posix" and SH and os.path.exists("/dev/urandom"), "needs a POSIX sh and /dev/urandom")
class SetupHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config_dir = Path(tmp.name)
        self.user = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()
        self.secret_file = self.config_dir / "livekit-secret"
        self.keys_file = self.config_dir / "livekit-keys.yaml"

    def run_setup(self, *extra: str) -> subprocess.CompletedProcess[str]:
        args = [SH, str(SETUP), "--config-dir", str(self.config_dir),
                "--merovingian-user", self.user, "--livekit-user", self.user, *extra]
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def written_secret(self) -> str:
        return self.secret_file.read_text(encoding="utf-8").rstrip("\n")

    def test_it_writes_one_secret_to_two_owner_only_files_and_never_prints_it(self) -> None:
        # GIVEN an empty configuration directory.
        # WHEN the helper runs.
        result = self.run_setup()

        # THEN both files exist, owner-read-only, holding the same 256-bit secret,
        # and the output names the key and both paths but never the secret.
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.secret_file, self.keys_file):
            with self.subTest(path=path.name):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertEqual(path.stat().st_uid, os.getuid())
        secret = self.written_secret()
        self.assertRegex(secret, r"^[0-9a-f]{64}$")
        keys = self.keys_file.read_text(encoding="utf-8")
        match = re.fullmatch(r'(API[0-9a-f]{16}): "([0-9a-f]{64})"\n', keys)
        self.assertIsNotNone(match, keys)
        assert match is not None
        key, keys_secret = match.groups()
        self.assertEqual(keys_secret, secret)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertIn(f"server.rtc.livekit.api_key={key}\n", result.stdout)
        self.assertIn(f"server.rtc.livekit.api_secret_file={self.secret_file}\n", result.stdout)
        self.assertIn(f"api_key: {key}\n", result.stdout)
        self.assertEqual([p.name for p in self.config_dir.iterdir() if p.name.startswith(".")], [])

    def test_a_second_run_changes_nothing_and_prints_the_same_key(self) -> None:
        # GIVEN files from a first run.
        first = self.run_setup()
        self.assertEqual(first.returncode, 0, first.stderr)
        secret, keys = self.written_secret(), self.keys_file.read_text(encoding="utf-8")

        # WHEN the helper runs again.
        second = self.run_setup()

        # THEN it succeeds, both files are unchanged, and it prints the same settings.
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("nothing was changed", second.stdout)
        self.assertEqual(self.written_secret(), secret)
        self.assertEqual(self.keys_file.read_text(encoding="utf-8"), keys)
        self.assertIn(first.stdout.split("Add to", 1)[1], second.stdout)
        self.assertNotIn(secret, second.stdout + second.stderr)

    def test_files_holding_different_secrets_are_refused(self) -> None:
        # GIVEN a secret file, still owner-only, that no longer matches the keys file.
        self.assertEqual(self.run_setup().returncode, 0)
        self.secret_file.chmod(0o600)
        self.secret_file.write_text("f" * 64 + "\n", encoding="utf-8")
        self.secret_file.chmod(0o400)

        # WHEN the helper runs again.
        result = self.run_setup()

        # THEN it fails, says so, and prints no secret.
        self.assertEqual(result.returncode, 1)
        self.assertIn("hold different secrets", result.stderr)
        self.assertNotIn("f" * 64, result.stdout + result.stderr)

    def test_an_existing_pair_with_the_wrong_mode_or_type_is_refused_and_left_as_it_is(self) -> None:
        # Each side's reader refuses a secret file that is not owner-read-only, so a rerun must not report
        # such a pair as ready.
        self.assertEqual(self.run_setup().returncode, 0)
        secret = self.written_secret()
        for path in (self.secret_file, self.keys_file):
            with self.subTest(path=path.name, problem="mode 0600"):
                # GIVEN one file of a matching pair made writable by its owner.
                path.chmod(0o600)

                # WHEN the helper runs again.
                result = self.run_setup()

                # THEN it fails naming that file, changes nothing and prints no secret.
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"{path} must be a regular file", result.stderr)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(secret, result.stdout + result.stderr)
                path.chmod(0o400)
        with self.subTest(problem="symbolic link"):
            # GIVEN the secret file replaced by a link to an owner-only copy of itself.
            target = self.config_dir / "elsewhere"
            self.secret_file.rename(target)
            self.secret_file.symlink_to(target)

            # WHEN the helper runs again, THEN it refuses the link.
            result = self.run_setup()
            self.assertEqual(result.returncode, 1)
            self.assertIn(f"{self.secret_file} must be a regular file", result.stderr)

    def test_one_file_alone_is_refused_and_left_as_it_is(self) -> None:
        for present in ("livekit-secret", "livekit-keys.yaml"):
            with self.subTest(present=present):
                # GIVEN only one of the two files.
                for path in (self.secret_file, self.keys_file):
                    path.unlink(missing_ok=True)
                (self.config_dir / present).write_text("operator's own\n", encoding="utf-8")

                # WHEN the helper runs.
                result = self.run_setup()

                # THEN it fails without writing the other or touching this one.
                self.assertEqual(result.returncode, 1)
                self.assertIn("only one of", result.stderr)
                self.assertEqual((self.config_dir / present).read_text(encoding="utf-8"), "operator's own\n")
                self.assertEqual(sorted(p.name for p in self.config_dir.iterdir()), [present])

    def test_an_unknown_account_or_directory_is_refused_before_anything_is_written(self) -> None:
        for args, message in ((("--livekit-user", "no-such-user-merovingian-test"), "no such user"),
                              (("--config-dir", str(self.config_dir / "missing")), "no such directory")):
            with self.subTest(message=message):
                result = self.run_setup(*args)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)
                self.assertEqual(list(self.config_dir.iterdir()), [])

    def test_an_unknown_option_is_a_usage_error(self) -> None:
        result = self.run_setup("--secret", "x")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
