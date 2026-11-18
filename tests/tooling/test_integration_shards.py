#!/usr/bin/env python3
"""The integration binary's Meson shards run every scenario exactly once.

tests/meson.build splits merovingian-integration-tests into Catch2 shards, plus a
[postgresql] test and a [serial] test. scripts/check-integration-shards.sh lists
what each selects and fails unless the union is the whole binary. The fake binary
below shards the way Catch2 3.16 does: sort by a seeded hash, filter, then take a
contiguous slice (createShard in catch_sharding.hpp).
"""
from __future__ import annotations

import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_MESON = REPO_ROOT / "tests" / "meson.build"
SCRIPT = REPO_ROOT / "scripts" / "check-integration-shards.sh"
STARTUP_TEST = REPO_ROOT / "tests" / "integration" / "test_server_startup_hardening_flow.cpp"

FAKE_LISTER = r"""
import sys
import zlib
from pathlib import Path

here = Path(__file__).parent
filter_spec, count, index, seed = "", 1, 0, ""
arguments = sys.argv[1:]
while arguments:
    argument = arguments.pop(0)
    if argument == "--order":
        arguments.pop(0)
    elif argument == "--rng-seed":
        seed = arguments.pop(0)
    elif argument == "--shard-count":
        count = int(arguments.pop(0))
    elif argument == "--shard-index":
        index = int(arguments.pop(0))
    elif argument == "--verbosity":
        if arguments.pop(0) != "quiet":
            sys.exit("the fake lists names only at quiet verbosity, as Catch2 3 does")
    elif argument != "--list-tests":
        filter_spec = argument
if (here / "BROKEN").exists():
    import os
    seed = str(os.getpid())  # each process orders differently
text = (here / "SCENARIOS").read_text(encoding="utf-8")
rows = [line.split("\t") for line in text.splitlines() if line]
rows.sort(key=lambda row: zlib.crc32((seed + row[0]).encode()))
wanted = {
    "": lambda tags: True,
    "~[postgresql]~[serial]": lambda tags: "postgresql" not in tags and "serial" not in tags,
    "[postgresql]": lambda tags: "postgresql" in tags,
    "[serial]": lambda tags: "serial" in tags,
}.get(filter_spec, lambda tags: False)
names = [name for name, tags in rows if wanted(tags)]
size, extra = divmod(len(names), count)  # Catch2's createShard: contiguous, sizes differ by one
start = index * size + min(index, extra)
end = (index + 1) * size + min(index + 1, extra)
print("\n".join(names[start:end]))
"""


def scenarios(total: int = 40) -> str:
    lines = []
    for number in range(total):
        tags = "[integration]"
        if number % 9 == 0:
            tags += "[postgresql]"
        if number == 5:
            tags += "[serial]"
        lines.append(f"Scenario: scenario {number}\t{tags}")
    return "\n".join(lines) + "\n"


class IntegrationShardRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.meson = TESTS_MESON.read_text(encoding="utf-8")

    def test_every_shard_shares_one_count_one_order_and_one_seed(self) -> None:
        # GIVEN the integration Meson tests.
        # WHEN the shard registration is read.
        count = re.search(r"integration_shard_count = (\d+)", self.meson)
        seed = re.search(r"integration_shard_seed = '(\d+)'", self.meson)

        # THEN one loop registers every shard from one count, and every shard gets the
        # same numeric seed: shards that do not agree on the order overlap and lose scenarios.
        self.assertIsNotNone(count)
        self.assertIsNotNone(seed)
        self.assertGreaterEqual(int(count.group(1)), 2)
        self.assertLess(int(seed.group(1)), 2**32)
        self.assertIn("foreach shard_index : range(integration_shard_count)", self.meson)
        self.assertIn("['--order', 'rand', '--rng-seed', integration_shard_seed]", self.meson)
        self.assertIn("'--shard-count', integration_shard_count.to_string(),", self.meson)
        self.assertIn("'--shard-index', shard_index.to_string(),", self.meson)
        self.assertNotIn("test('integration-tests',", self.meson)

    def test_coverage_check_is_given_the_registration_it_checks(self) -> None:
        # GIVEN the shard registration.
        # WHEN the coverage test is read.
        block = re.search(r"'integration-shard-coverage',(?P<body>.*?)\n  \)\n", self.meson, re.DOTALL)

        # THEN it receives the same binary, count, seed and filters the tests above use.
        self.assertIsNotNone(block)
        body = block.group("body")
        for expected in (
            "integration_tests.full_path()",
            "integration_shard_count.to_string()",
            "integration_shard_seed,",
            "integration_shard_filter,",
            "'[postgresql]',",
            "'[serial]',",
        ):
            self.assertIn(expected, body)
        self.assertIn("integration_shard_filter = '~[postgresql]~[serial]'", self.meson)
        self.assertIn("args: ['[postgresql]'],", self.meson)
        self.assertIn("args: ['[serial]'],", self.meson)
        self.assertIn("is_parallel: false", self.meson)

    def test_the_port_probing_startup_scenario_carries_the_serial_tag(self) -> None:
        # GIVEN the scenario that probes a free port and lets a spawned server bind it.
        source = STARTUP_TEST.read_text(encoding="utf-8")

        # WHEN its tags are read.
        # THEN it is in the serial group, which no shard runs.
        self.assertIn("[startup][binary][serial]", source)


class CheckIntegrationShardsTests(unittest.TestCase):
    def run_check(self, broken: str = "", scenario_text: str | None = None, count: int = 4,
                  filters: tuple[str, ...] = ("[postgresql]", "[serial]")) -> subprocess.CompletedProcess[str]:
        shell = shutil.which("sh")
        if shell is None or sys.platform == "win32" and shell.lower().endswith("system32\\sh.exe"):
            self.skipTest("POSIX sh is not available")
        root = Path(tempfile.mkdtemp(prefix="shard-check-"))
        self.addCleanup(shutil.rmtree, root, True)
        binary = root / "fake-integration-tests"
        (root / "lister.py").write_text(FAKE_LISTER, encoding="utf-8")
        launcher = f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "$(dirname "$0")/lister.py" "$@"\n'
        binary.write_text(launcher, encoding="utf-8", newline="\n")
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        (root / "SCENARIOS").write_text(scenarios() if scenario_text is None else scenario_text, encoding="utf-8", newline="\n")
        if broken:
            (root / "BROKEN").write_text(broken, encoding="utf-8")
        return subprocess.run(
            [shell, str(SCRIPT), str(binary), str(count), "271828", "~[postgresql]~[serial]", *filters],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_shards_and_filtered_tests_that_cover_the_binary_once_pass(self) -> None:
        # GIVEN a binary whose shards and filtered tests partition its scenarios.
        # WHEN the check runs.
        result = self.run_check()

        # THEN it passes and counts the scenarios.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("40 scenarios", result.stdout)

    def test_a_scenario_no_test_selects_fails(self) -> None:
        # GIVEN the [serial] filtered test is left out of the registration.
        result = self.run_check(filters=("[postgresql]",))

        # THEN the scenario nothing runs is reported, and the check fails.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("do not run every scenario exactly once", result.stderr)
        self.assertIn("Scenario: scenario 5", result.stderr)

    def test_a_scenario_selected_twice_fails(self) -> None:
        # GIVEN a filter that selects scenarios the shards already run.
        result = self.run_check(filters=("[postgresql]", "[serial]", "[integration]"))

        # THEN the check fails rather than running a scenario twice unnoticed.
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_shards_that_do_not_agree_on_the_order_fail(self) -> None:
        # GIVEN a binary that orders each process differently (no fixed seed).
        # WHEN the check lists each shard in its own process.
        result = self.run_check(broken="unseeded")

        # THEN the shards overlap and miss scenarios, and the check fails.
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_an_empty_binary_fails_closed(self) -> None:
        # GIVEN a binary that lists no scenario.
        result = self.run_check(scenario_text="")

        # THEN the check refuses to pass.
        self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
