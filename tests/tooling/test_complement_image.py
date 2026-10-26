#!/usr/bin/env python3
"""Behaviour of the Complement image's scripts (tests/complement/).

The image itself needs Docker and is booted by the `complement-image` job in
.github/workflows/packages.yml. These tests run the scripts it is assembled
from directly: the server-name gate, the config renderer, the state and TLS
preparation, and the hand-over in the entrypoint. When the build passes the
server binary as the first argument, the rendered config must also pass the
real server's `--check-config`.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
COMPLEMENT_DIR = REPO_ROOT / "tests" / "complement"
DOCKERFILE = COMPLEMENT_DIR / "Dockerfile"
ENTRYPOINT = COMPLEMENT_DIR / "entrypoint.sh"
RENDER_CONFIG = COMPLEMENT_DIR / "render-config.sh"
PREPARE_STATE = COMPLEMENT_DIR / "prepare-state.sh"
MINT_TLS = COMPLEMENT_DIR / "mint-tls.sh"
TEMPLATE = COMPLEMENT_DIR / "merovingian.conf.template"
NGINX_CONF = COMPLEMENT_DIR / "nginx.conf"
ROOT_DOCKERFILE = REPO_ROOT / "Dockerfile"
EXAMPLE_CONFIG = REPO_ROOT / "config" / "merovingian.conf.example"
RATE_LIMIT_SOURCE = REPO_ROOT / "src" / "http" / "rate_limit.cpp"
PACKAGES_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "packages.yml"

# Meson passes the built merovingian-server as argv[1]. Read it here, before
# the skip decorators below are evaluated, and hide it from unittest.
SERVER_BINARY = os.environ.get("MEROVINGIAN_SERVER_BINARY", "")
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    SERVER_BINARY = sys.argv.pop(1)

POSIX_ONLY = unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "the image scripts are POSIX shell")
NEEDS_OPENSSL = unittest.skipIf(shutil.which("openssl") is None, "openssl is not installed")

# A rate limit is "cap/window"; Complement must never meet one.
RATE_VALUE = re.compile(r"^(\d+)/(\d+)([smh]?)$")
WINDOW_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600}
MIN_RATE_PER_SECOND = 1_000_000


def config_entries(text: str) -> dict[str, str]:
    """Return the key=value lines of a config, ignoring comments and blanks."""
    entries: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        entries[key.strip()] = value.strip()
    return entries


def current_owner() -> str:
    import grp
    import pwd

    return f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"


def run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        env=dict(os.environ, **(env or {})),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def render(server_name: str, allow_without_landlock: str = "false", root: str = "") -> subprocess.CompletedProcess[str]:
    env = {"MEROVINGIAN_COMPLEMENT_ROOT": root} if root else None
    return run("sh", str(RENDER_CONFIG), str(TEMPLATE), server_name, allow_without_landlock, env=env)


def make_ca(directory: Path) -> None:
    """Write a throwaway CA as Complement mounts it: ca.crt and ca.key."""
    directory.mkdir(parents=True)
    result = run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt"),
        "-days", "2", "-subj", "/CN=Complement test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)


@POSIX_ONLY
class ServerNameGateTests(unittest.TestCase):
    """SERVER_NAME is interpolated into the config and the certificate, so it is checked first."""

    def test_accepts_every_form_of_matrix_server_name(self) -> None:
        # GIVEN server names in each form of the spec's server-name grammar
        # (appendices.md, "Server Name"): a dot-less DNS name as Complement
        # uses, a DNS name, either with a port, and IP literals.
        for name in ("hs1", "hs2:8448", "matrix.example.org", "127.0.0.1:8448", "[::1]", "[2001:db8::1]:8448"):
            with self.subTest(name=name):
                # WHEN the config is rendered for it.
                result = render(name)
                # THEN it renders, naming that server.
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(config_entries(result.stdout)["server.name"], name)

    def test_refuses_anything_else_without_writing_a_config(self) -> None:
        # GIVEN values that are not server names, including ones that would
        # inject a second config line or break out of a certificate subject.
        refused = (
            "",
            "hs1\nsecurity.registration.enabled=false",
            "hs1\rx",
            "hs1 ",
            "hs/1",
            "hs1=x",
            "hs1:",
            "hs1:0",
            "hs1:65536",
            "hs1:123456",
            "[::1",
            "[xyz]",
            "a" * 256,
        )
        for name in refused:
            with self.subTest(name=name):
                # WHEN the config is rendered for it.
                result = render(name)
                # THEN rendering fails and prints no config at all.
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("server name", result.stderr)


@POSIX_ONLY
class RenderedConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        result = render("hs1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.text = result.stdout
        self.config = config_entries(result.stdout)

    def test_every_placeholder_is_filled(self) -> None:
        # GIVEN the rendered config.
        # WHEN it is searched for template placeholders.
        leftovers = re.findall(r"@[A-Z_]+@", self.text)
        # THEN none remain.
        self.assertEqual(leftovers, [])

    def test_open_registration_is_acknowledged(self) -> None:
        # GIVEN the rendered config.
        # WHEN its registration settings are read.
        registration = {key: self.config.get(f"security.registration.{key}") for key in
                        ("enabled", "require_token", "allow_open_registration")}
        # THEN anyone may register, and the acknowledgement ADR-0232 requires is given.
        self.assertEqual(registration, {"enabled": "true", "require_token": "false",
                                        "allow_open_registration": "true"})

    def test_federation_listens_with_tls_on_8448_and_the_client_api_only_on_loopback(self) -> None:
        # GIVEN the rendered config.
        # WHEN its listeners are read.
        # THEN federation is served with TLS on every interface at 8448, and
        # the client API only on loopback, for nginx to put on 8008.
        self.assertEqual(self.config["listeners.federation.bind"], "0.0.0.0:8448")
        self.assertEqual(self.config["listeners.federation.tls"], "true")
        self.assertTrue(self.config["listeners.client.bind"].startswith("127.0.0.1:"))
        self.assertEqual(self.config["listeners.client.tls"], "false")
        self.assertEqual(self.config["listeners.client.reverse_proxy"], "true")
        self.assertIn("127.0.0.1", self.config["server.trusted_proxies"].split(","))

    def test_nginx_forwards_to_the_client_listener(self) -> None:
        # GIVEN the rendered config and the image's nginx config.
        nginx = NGINX_CONF.read_text(encoding="utf-8")
        # WHEN nginx's upstream is compared with the client listener.
        upstreams = re.findall(r"proxy_pass\s+http://([0-9.:]+)\s*;", nginx)
        # THEN nginx sends every request to that listener.
        self.assertEqual(upstreams, [self.config["listeners.client.bind"]])

    def test_only_rfc1918_networks_are_opened_to_federation(self) -> None:
        # GIVEN the rendered config.
        # WHEN the private-network allowance is read.
        ranges = self.config["security.federation.allow_private_ip_ranges"].split(",")
        # THEN it names the three RFC 1918 networks Docker allocates from, and
        # nothing else: loopback and link-local stay blocked.
        self.assertEqual(sorted(ranges), ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

    def test_landlock_stays_required_unless_explicitly_waived(self) -> None:
        # GIVEN the default rendering, and one that waives Landlock.
        waived = render("hs1", "true")
        # WHEN the federation worker's Landlock setting is read from each.
        # THEN only the explicit waiver changes it.
        self.assertEqual(self.config["federation.worker.allow_without_landlock"], "false")
        self.assertEqual(waived.returncode, 0, waived.stderr)
        self.assertEqual(config_entries(waived.stdout)["federation.worker.allow_without_landlock"], "true")

    def test_a_waiver_that_is_not_a_boolean_is_refused(self) -> None:
        for value in ("", "yes", "TRUE", "true\nx=y"):
            with self.subTest(value=value):
                # GIVEN a Landlock waiver that is not exactly true or false.
                # WHEN the config is rendered with it.
                result = render("hs1", value)
                # THEN rendering fails.
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def assert_out_of_reach(self, key: str) -> None:
        match = RATE_VALUE.match(self.config.get(key, ""))
        self.assertIsNotNone(match, f"{key} is not overridden")
        cap, window, unit = int(match.group(1)), int(match.group(2)), match.group(3)
        self.assertGreaterEqual(cap / (window * WINDOW_SECONDS[unit]), MIN_RATE_PER_SECOND, key)

    def test_no_rate_limit_the_server_applies_can_be_reached(self) -> None:
        # GIVEN the rate limits the server applies without per-route config:
        # the per-IP default and tiers and the federation limits, which the
        # example config sets, and the built-in per-user limits. The example's
        # per-route entries are not listed: the rendered config does not carry
        # them, and a tier override outranks a built-in per-IP refinement.
        example = config_entries(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
        configured = [key for key, value in example.items() if RATE_VALUE.match(value)
                      and not key.startswith(("client_rate_limits.per_ip.", "client_rate_limits.per_user."))]
        engine = RATE_LIMIT_SOURCE.read_text(encoding="utf-8")
        per_user_block = re.search(r"\.builtin_per_user\s*=\s*\{(.*?)\n\s*\},", engine, re.S)
        self.assertIsNotNone(per_user_block)
        builtin_per_user = [f"client_rate_limits.per_user.{path}"
                            for path in re.findall(r'\{"(/[^"]+)",', per_user_block.group(1))]
        self.assertIn("client_rate_limits.tier.auth_sensitive", configured)
        self.assertIn("client_rate_limits.per_user./_matrix/client/v3/login", builtin_per_user)
        for key in sorted(configured + builtin_per_user):
            with self.subTest(key=key):
                # WHEN the rendered config's value for it is read.
                # THEN it allows at least a million requests a second.
                self.assert_out_of_reach(key)

    def test_every_rate_limit_the_config_sets_is_out_of_reach(self) -> None:
        # GIVEN the rendered config.
        rate_keys = [key for key, value in self.config.items() if RATE_VALUE.match(value)]
        self.assertTrue(rate_keys)
        for key in rate_keys:
            with self.subTest(key=key):
                # WHEN each rate limit it sets is read.
                # THEN none is low enough for a Complement run to meet.
                self.assert_out_of_reach(key)

    def test_failed_logins_cannot_lock_a_client_out(self) -> None:
        # GIVEN the rendered config.
        # WHEN the login throttle is read.
        throttle = {key: self.config.get(f"security.login_throttle.{key}")
                    for key in ("max_failures_per_source", "max_failures_per_account", "window")}
        # THEN it allows the most failures the server accepts, per second.
        self.assertEqual(throttle, {"max_failures_per_source": "1000", "max_failures_per_account": "100000",
                                    "window": "1s"})

    def test_a_config_root_that_is_not_a_plain_absolute_path_is_refused(self) -> None:
        for root in ("relative/dir", "/tmp/a b", "/tmp/a|b", "/tmp/a\nb"):
            with self.subTest(root=root):
                # GIVEN a test-only config root that could corrupt the paths.
                # WHEN the config is rendered under it.
                result = render("hs1", root=root)
                # THEN rendering fails.
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


@POSIX_ONLY
class PrepareStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="complement-state-"))
        self.state = self.workdir / "state"
        self.key = self.state / "secrets" / "master.key"

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def prepare(self, server_name: str) -> subprocess.CompletedProcess[str]:
        return run("sh", str(PREPARE_STATE), str(self.state), server_name, current_owner())

    def test_first_start_creates_an_owner_only_master_key(self) -> None:
        # GIVEN an empty state directory.
        # WHEN the state is prepared for hs1.
        result = self.prepare("hs1")
        # THEN a 256-bit master key exists that only its owner can read, in a
        # secrets directory apart from the database directory.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.key.stat().st_size, 32)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((self.state / "data").stat().st_mode), 0o700)

    def test_the_server_cannot_plant_entries_where_root_writes(self) -> None:
        # GIVEN state prepared by the entrypoint, which runs as root.
        # WHEN the directories root writes into on the next start are examined.
        result = self.prepare("hs1")
        self.assertEqual(result.returncode, 0, result.stderr)
        # THEN they belong to whoever ran the script, not to OWNER, and only
        # their owner can create entries: a link planted there would be followed
        # by root. The secrets directory can be passed through but not listed.
        for directory, mode in ((self.state, 0o755), (self.state / "secrets", 0o711)):
            self.assertEqual(directory.stat().st_uid, os.getuid())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), mode)

    def test_a_linked_state_directory_is_refused(self) -> None:
        # GIVEN a secrets directory replaced by a symbolic link.
        elsewhere = self.workdir / "elsewhere"
        elsewhere.mkdir()
        self.state.mkdir()
        (self.state / "secrets").symlink_to(elsewhere)
        # WHEN the state is prepared.
        result = self.prepare("hs1")
        # THEN it refuses and writes nothing through the link.
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_stale_temporary_link_is_not_followed(self) -> None:
        # GIVEN a link left where the master key is written before it is renamed.
        target = self.workdir / "target"
        target.write_bytes(b"untouched")
        (self.state / "secrets").mkdir(parents=True)
        (self.state / "secrets" / "master.key.tmp").symlink_to(target)
        # WHEN the state is prepared.
        result = self.prepare("hs1")
        # THEN the key is written in place of the link, and its target is untouched.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), b"untouched")
        self.assertEqual(self.key.stat().st_size, 32)

    def test_a_restart_keeps_the_master_key(self) -> None:
        # GIVEN state prepared once for hs1.
        self.assertEqual(self.prepare("hs1").returncode, 0)
        first = self.key.read_bytes()
        # WHEN the container starts again as hs1, as a Complement snapshot does.
        result = self.prepare("hs1")
        # THEN the same key is kept, so the signing key it protects survives.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.key.read_bytes(), first)

    def test_state_is_never_served_under_another_server_name(self) -> None:
        # GIVEN state prepared for hs1.
        self.assertEqual(self.prepare("hs1").returncode, 0)
        first = self.key.read_bytes()
        # WHEN the container starts as hs2.
        result = self.prepare("hs2")
        # THEN it refuses, naming both, and leaves the key alone.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hs1", result.stderr)
        self.assertEqual(self.key.read_bytes(), first)

    def test_a_master_key_with_no_recorded_server_name_is_refused(self) -> None:
        # GIVEN a master key that this script did not record a server for.
        self.key.parent.mkdir(parents=True)
        self.key.write_bytes(os.urandom(32))
        # WHEN the state is prepared.
        result = self.prepare("hs1")
        # THEN it refuses rather than adopt it.
        self.assertNotEqual(result.returncode, 0)

    def test_a_truncated_master_key_is_refused(self) -> None:
        # GIVEN prepared state whose master key has been cut short.
        self.assertEqual(self.prepare("hs1").returncode, 0)
        self.key.chmod(0o600)
        self.key.write_bytes(b"short")
        self.key.chmod(0o400)
        # WHEN the state is prepared again.
        result = self.prepare("hs1")
        # THEN it refuses rather than start on it.
        self.assertNotEqual(result.returncode, 0)

    def test_an_invalid_server_name_writes_nothing(self) -> None:
        # GIVEN an empty state directory.
        # WHEN the state is prepared for a value that is not a server name.
        result = self.prepare("hs1\nx")
        # THEN it fails before creating anything.
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.state.exists())


@POSIX_ONLY
@NEEDS_OPENSSL
class MintTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="complement-tls-"))
        self.ca = self.workdir / "ca"
        make_ca(self.ca)
        self.ca.chmod(0o555)
        self.cert = self.workdir / "etc" / "server.crt"
        self.key = self.workdir / "secrets" / "tls.key"
        self.cert.parent.mkdir()
        self.key.parent.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.ca.chmod(0o755)
        shutil.rmtree(self.workdir, ignore_errors=True)

    def mint(self, server_name: str) -> subprocess.CompletedProcess[str]:
        return run("sh", str(MINT_TLS), str(self.ca), server_name, str(self.cert), str(self.key), current_owner())

    def openssl_x509(self, *args: str) -> subprocess.CompletedProcess[str]:
        return run("openssl", "x509", "-in", str(self.cert), "-noout", *args)

    def test_issues_a_short_lived_certificate_for_the_server_from_complements_ca(self) -> None:
        # GIVEN Complement's CA.
        # WHEN a certificate is minted for hs1.
        result = self.mint("hs1")
        self.assertEqual(result.returncode, 0, result.stderr)
        # THEN it chains to that CA, names hs1, and lasts about a day.
        verify = run("openssl", "verify", "-CAfile", str(self.ca / "ca.crt"), "-purpose", "sslserver", str(self.cert))
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("DNS:hs1", self.openssl_x509("-ext", "subjectAltName").stdout)
        self.assertEqual(self.openssl_x509("-checkend", "3600").returncode, 0)
        self.assertNotEqual(self.openssl_x509("-checkend", str(26 * 3600)).returncode, 0)

    def test_the_private_key_is_owner_read_only_and_matches_the_certificate(self) -> None:
        # GIVEN a minted certificate.
        self.assertEqual(self.mint("hs1").returncode, 0)
        # WHEN the key and certificate files are examined.
        cert_pub = self.openssl_x509("-pubkey").stdout
        key_pub = run("openssl", "pkey", "-in", str(self.key), "-pubout").stdout
        # THEN the key passes the server's secret-file check (0400), the
        # certificate its config-file check (no group/other write), and they pair.
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.cert.stat().st_mode) & 0o033, 0)
        self.assertTrue(cert_pub)
        self.assertEqual(cert_pub, key_pub)

    def test_a_restart_mints_a_replacement(self) -> None:
        # GIVEN a minted certificate.
        self.assertEqual(self.mint("hs1").returncode, 0)
        first = self.openssl_x509("-serial").stdout
        # WHEN the container starts again.
        result = self.mint("hs1")
        # THEN a fresh certificate replaces it.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.openssl_x509("-serial").stdout, first)

    def test_an_ip_literal_server_name_gets_an_ip_subject_alternative_name(self) -> None:
        # GIVEN Complement's CA.
        # WHEN certificates are minted for IPv4 and IPv6 literal server names.
        self.assertEqual(self.mint("10.1.2.3:8448").returncode, 0)
        ipv4 = self.openssl_x509("-ext", "subjectAltName").stdout
        self.assertEqual(self.mint("[2001:db8::1]").returncode, 0)
        ipv6 = self.openssl_x509("-ext", "subjectAltName").stdout
        # THEN each names its address as an IP, without the port.
        self.assertIn("IP Address:10.1.2.3", ipv4)
        self.assertIn("IP ADDRESS:2001:DB8:0:0:0:0:0:1", ipv6.upper())

    def test_an_invalid_server_name_writes_no_certificate(self) -> None:
        # GIVEN Complement's CA.
        # WHEN minting for a value that is not a server name.
        result = self.mint("hs1/CN=evil")
        # THEN it fails and writes nothing.
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.cert.exists())
        self.assertFalse(self.key.exists())

    def test_a_stale_temporary_link_is_not_followed(self) -> None:
        # GIVEN a link left where the key is written before it is renamed.
        target = self.workdir / "target"
        target.write_bytes(b"untouched")
        Path(f"{self.key}.tmp").symlink_to(target)
        # WHEN a certificate is minted.
        result = self.mint("hs1")
        # THEN the key replaces the link, and the link's target is untouched.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), b"untouched")
        self.assertFalse(self.key.is_symlink())

    def test_the_ca_directory_is_only_read(self) -> None:
        # GIVEN Complement's CA, mounted read-only.
        before = sorted(path.name for path in self.ca.iterdir())
        # WHEN a certificate is minted.
        result = self.mint("hs1")
        # THEN minting succeeds without writing a serial file beside the CA.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(path.name for path in self.ca.iterdir()), before)


@POSIX_ONLY
@NEEDS_OPENSSL
@unittest.skipUnless(SERVER_BINARY, "no merovingian-server binary given")
class ServerAcceptsTheRenderedConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="complement-root-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_the_server_accepts_the_config_the_entrypoint_writes(self) -> None:
        # GIVEN state, a certificate and a config prepared as the entrypoint
        # does, under a scratch root instead of /.
        owner = current_owner()
        state = self.root / "var" / "lib" / "merovingian"
        (self.root / "etc" / "merovingian" / "tls").mkdir(parents=True)
        make_ca(self.root / "ca")
        prepared = run("sh", str(PREPARE_STATE), str(state), "hs1", owner)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        minted = run("sh", str(MINT_TLS), str(self.root / "ca"), "hs1",
                     str(self.root / "etc" / "merovingian" / "tls" / "server.crt"),
                     str(state / "secrets" / "tls.key"), owner)
        self.assertEqual(minted.returncode, 0, minted.stderr)
        rendered = render("hs1", root=str(self.root))
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        config = self.root / "etc" / "merovingian" / "merovingian.conf"
        config.write_text(rendered.stdout, encoding="utf-8")
        config.chmod(0o644)
        # WHEN the real server checks it.
        result = run(SERVER_BINARY, "--check-config", str(config))
        # THEN it has no findings.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class DockerfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOCKERFILE.read_text(encoding="utf-8")
        self.instructions = re.sub(r"\\\r?\n", " ", self.text)

    def test_builds_on_the_same_pinned_base_as_the_shipped_image(self) -> None:
        # GIVEN the shipped image's runtime base and the Complement image's base.
        shipped = re.findall(r"(?m)^FROM\s+(\S+)", ROOT_DOCKERFILE.read_text(encoding="utf-8"))[-1]
        bases = re.findall(r"(?m)^FROM\s+(\S+)", self.text)
        # WHEN they are compared.
        # THEN the Complement image runs on exactly the shipped base.
        self.assertEqual(bases, [shipped])
        self.assertIn("@sha256:", shipped)

    def test_installs_the_package_only_after_checking_its_digest(self) -> None:
        # GIVEN the Dockerfile's instructions.
        # WHEN the step that installs the package is found.
        install = [line for line in self.instructions.splitlines() if "merovingian.deb" in line and "apt-get install" in line]
        # THEN that same step first requires a SHA-256 and checks the package against it.
        self.assertEqual(len(install), 1)
        step = install[0]
        self.assertIn("ARG MEROVINGIAN_DEB_SHA256", self.text)
        self.assertIn("sha256sum", step)
        self.assertLess(step.index("sha256sum"), step.index("apt-get install"))

    def test_starts_as_root_so_the_entrypoint_can_drop_the_bounding_set(self) -> None:
        # GIVEN the Dockerfile.
        # WHEN its user and volume instructions are listed.
        # THEN there are none: Complement does not pass --cap-drop, so the
        # entrypoint must start as root to drop capabilities itself, and state
        # must live in the container layer Complement snapshots, not a volume.
        self.assertEqual(re.findall(r"(?m)^USER\s", self.text), [])
        self.assertEqual(re.findall(r"(?m)^VOLUME\s", self.text), [])

    def test_exposes_complements_ports_and_reports_health_through_the_client_api(self) -> None:
        # GIVEN the Dockerfile.
        exposed = set(re.findall(r"\d+", " ".join(re.findall(r"(?m)^EXPOSE\s+(.*)$", self.text))))
        healthcheck = re.findall(r"(?m)^HEALTHCHECK\s+(.*)$", self.instructions)
        # WHEN its ports and health check are read.
        # THEN it exposes 8008 and 8448, and is healthy only once the client API answers on 8008.
        self.assertEqual(exposed, {"8008", "8448"})
        self.assertEqual(len(healthcheck), 1)
        self.assertIn("http://127.0.0.1:8008/_matrix/client/versions", healthcheck[0])

    def test_copies_every_script_the_entrypoint_runs(self) -> None:
        # GIVEN the scripts and template the entrypoint names.
        entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        named = set(re.findall(r'"\$lib/([A-Za-z0-9._-]+)"', entrypoint))
        self.assertTrue(named)
        copied = set()
        for line in re.findall(r"(?m)^COPY\s+(.*)$", self.instructions):
            copied.update(Path(part).name for part in line.split()[:-1])
        # WHEN they are compared with what the Dockerfile copies.
        # THEN every one is in the image.
        self.assertEqual(named - copied, set())


class EntrypointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = ENTRYPOINT.read_text(encoding="utf-8")
        commands = re.sub(r"\\\r?\n", " ", self.text)
        self.commands = [line.strip() for line in commands.splitlines() if line.strip() and not line.strip().startswith("#")]

    def test_hands_over_to_the_server_without_capabilities_or_privileges(self) -> None:
        # GIVEN the entrypoint.
        # WHEN its last command is read.
        handover = self.commands[-1]
        # THEN it replaces itself with the server as the merovingian user, with
        # an empty bounding set and no_new_privs, as the self-check requires.
        self.assertTrue(handover.startswith("exec setpriv "), handover)
        for flag in ("--reuid=merovingian", "--regid=merovingian", "--init-groups", "--bounding-set=-all",
                     "--inh-caps=-all", "--no-new-privs", "/usr/bin/merovingian-server"):
            self.assertIn(flag, handover)

    def test_checks_its_input_before_it_writes_or_starts_anything(self) -> None:
        # GIVEN the entrypoint.
        def first(marker: str) -> int:
            return next(index for index, line in enumerate(self.commands) if marker in line)

        # WHEN the order of its steps is read.
        # THEN the config is rendered (which checks SERVER_NAME) before state
        # or certificates are touched, and the CA is trusted before the server starts.
        order = [first(marker) for marker in ("render-config.sh", "prepare-state.sh", "mint-tls.sh",
                                              "update-ca-certificates", "nginx", "exec setpriv")]
        self.assertEqual(order, sorted(order))
        self.assertIn("set -eu", self.text)


class NginxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = NGINX_CONF.read_text(encoding="utf-8")

    def test_listens_on_8008(self) -> None:
        # GIVEN the nginx config.
        # WHEN its listen directives are read.
        # THEN it serves Complement's client port.
        self.assertEqual(re.findall(r"(?m)^\s*listen\s+([^;]+);", self.text), ["8008"])

    def test_passes_the_request_target_unchanged(self) -> None:
        # GIVEN the nginx config.
        # WHEN its proxy_pass is read.
        # THEN it names no URI part, so nginx forwards the request target as
        # received; with one, nginx would decode %-escapes such as %21 in room IDs.
        self.assertRegex(self.text, r"proxy_pass\s+http://127\.0\.0\.1:\d+;")

    def test_replaces_rather_than_extends_x_forwarded_for(self) -> None:
        # GIVEN the nginx config.
        # WHEN the forwarded-for header is read.
        # THEN it is set to the peer nginx saw, so a client cannot supply its own address.
        self.assertRegex(self.text, r"proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;")
        self.assertNotIn("$proxy_add_x_forwarded_for", self.text)

    def test_streams_long_polls(self) -> None:
        # GIVEN the nginx config.
        # WHEN its buffering and timeouts are read.
        # THEN responses are not buffered and a long /sync is not cut off.
        self.assertRegex(self.text, r"proxy_buffering\s+off;")
        timeout = re.search(r"proxy_read_timeout\s+(\d+)s;", self.text)
        self.assertIsNotNone(timeout)
        self.assertGreaterEqual(int(timeout.group(1)), 300)


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        workflow = PACKAGES_WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"(?ms)^  complement-image:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
        self.assertIsNotNone(match, "packages.yml has no complement-image job")
        self.job = re.sub(r"\\\n\s*", " ", match.group(1))

    def test_boots_the_image_built_from_the_trixie_package(self) -> None:
        # GIVEN the complement-image job.
        # WHEN its inputs and build are read.
        # THEN it builds tests/complement from the Debian trixie package, pinned by digest.
        self.assertRegex(self.job, r"needs:\s*\[?\s*debian-pkg")
        self.assertIn("name: debian-package", self.job)
        self.assertIn("MEROVINGIAN_DEB_SHA256", self.job)
        self.assertRegex(self.job, r"docker build[^\n]*tests/complement")

    def test_runs_the_container_as_complement_does(self) -> None:
        # GIVEN the complement-image job.
        # WHEN its docker run is read.
        # THEN it passes SERVER_NAME and mounts a CA at /complement/ca, and
        # drops no capabilities itself: the entrypoint must do that.
        self.assertIn("SERVER_NAME=", self.job)
        self.assertIn(":/complement/ca", self.job)
        self.assertNotIn("--cap-drop", self.job)
        self.assertNotIn("no-new-privileges", self.job)

    def test_checks_health_registration_federation_and_a_restart(self) -> None:
        # GIVEN the complement-image job.
        # WHEN its checks are read.
        # THEN it waits for health, asks /register for its flows, reads the
        # federation key over TLS trusting only the test CA, and restarts.
        self.assertIn(".State.Health.Status", self.job)
        self.assertIn("/_matrix/client/v3/register", self.job)
        self.assertIn("m.login.dummy", self.job)
        self.assertIn("/_matrix/key/v2/server", self.job)
        self.assertIn("--cacert", self.job)
        self.assertIn("docker restart", self.job)


if __name__ == "__main__":
    unittest.main()
