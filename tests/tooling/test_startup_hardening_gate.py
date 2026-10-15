#!/usr/bin/env python3
"""Behaviour of scripts/check-startup-hardening-gate.sh against a fake server.

The real server is exercised by the packages workflow. These tests pin the
gate's own decisions: what it accepts as "every hardening check enabled", and
that it fails, rather than hangs or passes, on every other outcome.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_SCRIPT = REPO_ROOT / "scripts" / "check-startup-hardening-gate.sh"

# A stand-in for merovingian-server. It records the config it was given, then
# prints the log lines the real server prints in the scenario FAKE_MODE names.
FAKE_SERVER = textwrap.dedent(
    """\
    #!/bin/sh
    config=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --config) shift; config=$1 ;;
        esac
        shift
    done
    cp "$config" "$FAKE_OUT/config"
    key=$(sed -n 's/^security\\.secrets\\.master_key_file=//p' "$config")
    wc -c < "$key" | tr -d ' ' > "$FAKE_OUT/key_bytes"
    ls -l "$key" | cut -c1-10 > "$FAKE_OUT/key_mode"

    log() { printf '{"level":"info","message":"%s"}\\n' "$1"; }
    case "$FAKE_MODE" in
        ready)
            log "Startup hardening checks: 2"
            log "Hardening self-check: PIE=enabled"
            log "Hardening self-check: FORTIFY_SOURCE=enabled"
            log "Hardening readiness: ready=true blockers=0"
            log "Listeners active; awaiting traffic"
            ;;
        refused)
            log "Startup hardening checks: 2"
            log "Hardening self-check: PIE=enabled"
            log "Hardening self-check: FORTIFY_SOURCE=unknown note=Compile did not advertise _FORTIFY_SOURCE > 0."
            log "Hardening readiness: ready=false blockers=1"
            log "Startup refused: hardening self-check reports a non-enabled control"
            exit 70
            ;;
        unknown_but_ready)
            log "Startup hardening checks: 2"
            log "Hardening self-check: PIE=enabled"
            log "Hardening self-check: FORTIFY_SOURCE=unknown"
            log "Hardening readiness: ready=true blockers=0"
            log "Listeners active; awaiting traffic"
            ;;
        missing_check)
            log "Startup hardening checks: 3"
            log "Hardening self-check: PIE=enabled"
            log "Hardening self-check: FORTIFY_SOURCE=enabled"
            log "Hardening readiness: ready=true blockers=0"
            log "Listeners active; awaiting traffic"
            ;;
        hang)
            log "Startup hardening checks: 2"
            ;;
    esac
    trap 'exit 0' TERM
    while :; do sleep 1; done
    """
)


@unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "the gate is a POSIX shell script")
class StartupHardeningGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="gate-test-"))
        self.out = self.workdir / "out"
        self.out.mkdir()
        self.server = self.workdir / "merovingian-server"
        self.server.write_text(FAKE_SERVER, encoding="utf-8")
        self.server.chmod(self.server.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def run_gate(self, mode: str, *extra: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, FAKE_MODE=mode, FAKE_OUT=str(self.out))
        return subprocess.run(
            ["sh", str(GATE_SCRIPT), "--timeout", "5", *extra, str(self.server)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_passes_when_every_check_is_enabled_and_the_server_serves(self) -> None:
        # GIVEN a server that reports every hardening check enabled and opens
        # its listeners.
        # WHEN the gate runs it.
        result = self.run_gate("ready")

        # THEN the gate passes and stops the server.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hands_the_server_a_bootable_config_and_an_owner_only_master_key(self) -> None:
        # GIVEN a server binary under test.
        # WHEN the gate starts it.
        self.run_gate("ready")

        # THEN the server gets a SQLite config bound to loopback, with a
        # 32-byte master key that only its owner can read.
        config = (self.out / "config").read_text(encoding="utf-8")
        self.assertIn("database.backend=sqlite\n", config)
        self.assertRegex(config, r"(?m)^listeners\.client\.bind=127\.0\.0\.1:\d+$")
        self.assertRegex(config, r"(?m)^listeners\.federation\.bind=127\.0\.0\.1:\d+$")
        self.assertEqual((self.out / "key_bytes").read_text(encoding="utf-8").strip(), "32")
        self.assertEqual((self.out / "key_mode").read_text(encoding="utf-8").strip(), "-r--------")

    def test_uses_the_packaged_federation_worker_unless_told_otherwise(self) -> None:
        # GIVEN no explicit worker path.
        # WHEN the gate starts the server.
        self.run_gate("ready")

        # THEN the config leaves the worker path to the binary's built-in
        # libexec default, so the gate also proves the package installed it.
        config = (self.out / "config").read_text(encoding="utf-8")
        self.assertNotIn("federation.worker.binary=", config)

        # WHEN a worker path is given explicitly.
        self.run_gate("ready", "--federation-worker", "/opt/worker")

        # THEN the config names it.
        config = (self.out / "config").read_text(encoding="utf-8")
        self.assertIn("federation.worker.binary=/opt/worker\n", config)

    def test_fails_when_the_server_refuses_to_start(self) -> None:
        # GIVEN a debug build whose FORTIFY_SOURCE check reports unknown.
        # WHEN the gate runs it.
        result = self.run_gate("refused")

        # THEN the gate fails and names the check that was not enabled.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FORTIFY_SOURCE=unknown", result.stdout + result.stderr)

    def test_fails_when_any_check_is_not_enabled_even_if_readiness_says_ready(self) -> None:
        # GIVEN a server whose readiness line disagrees with one of its checks.
        # WHEN the gate runs it.
        result = self.run_gate("unknown_but_ready")

        # THEN the per-check result wins and the gate fails.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FORTIFY_SOURCE=unknown", result.stdout + result.stderr)

    def test_fails_when_fewer_checks_report_than_the_server_ran(self) -> None:
        # GIVEN a server that ran three checks but reported only two.
        # WHEN the gate runs it.
        result = self.run_gate("missing_check")

        # THEN the gate fails rather than trusting an incomplete report.
        self.assertNotEqual(result.returncode, 0)

    def test_fails_within_its_timeout_when_the_server_never_becomes_ready(self) -> None:
        # GIVEN a server that never finishes starting.
        started = time.monotonic()

        # WHEN the gate runs it with a 5 second timeout.
        result = self.run_gate("hang")

        # THEN the gate fails once the timeout passes instead of hanging.
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 30)


if __name__ == "__main__":
    unittest.main()
