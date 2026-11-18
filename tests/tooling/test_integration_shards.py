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
broken = (here / "BROKEN").exists()
if broken:
    seed = "fixed"  # healthy mode keeps the caller's seed; broken mode orders every process the same way
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
if broken and count > 1 and index == 0 and len(names) > count:
    # The one inconsistent invocation: shard 0 sees the names either side of its boundary swapped, so it lists the
    # first name of shard 1 (a duplicate, as shard 1 lists it too) and omits its own last name.
    boundary = len(names) // count + (1 if len(names) % count else 0)
    names[boundary - 1], names[boundary] = names[boundary], names[boundary - 1]
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


def active_lines(text: str) -> list[str]:
    """The non-empty lines of `text` with every Meson `#` comment removed, so a comment never satisfies a match."""
    lines = (re.sub(r"\s*#.*$", "", line).strip() for line in text.splitlines())
    return [line for line in lines if line]


class IntegrationShardRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.meson = TESTS_MESON.read_text(encoding="utf-8")
        self.active = "\n".join(active_lines(self.meson))

    def test_every_shard_shares_one_count_one_order_and_one_seed(self) -> None:
        # GIVEN the integration Meson tests.
        # WHEN the shard registration is read.
        count = re.search(r"(?m)^integration_shard_count = (\d+)$", self.active)
        seed = re.search(r"(?m)^integration_shard_seed = '(\d+)'$", self.active)
        shards = active_lines(self.registration("integration-tests-shard-@0@-of-@1@"))

        # THEN one loop registers every shard from one count, and every shard gets the
        # same numeric seed: shards that do not agree on the order overlap and lose scenarios.
        self.assertIsNotNone(count)
        self.assertIsNotNone(seed)
        self.assertGreaterEqual(int(count.group(1)), 2)
        self.assertLess(int(seed.group(1)), 2**32)
        self.assertIn("foreach shard_index : range(integration_shard_count)", self.active)
        self.assertIn("['--order', 'rand', '--rng-seed', integration_shard_seed]", self.active)
        # AND the shard's own active arguments hand Catch2 the shared count and this iteration's index.
        self.assertIn("'--shard-count', integration_shard_count.to_string(),", shards)
        self.assertIn("'--shard-index', shard_index.to_string(),", shards)
        self.assertNotIn("test('integration-tests',", self.active)

    def test_coverage_check_is_given_the_registration_it_checks(self) -> None:
        # GIVEN the shard registration.
        # WHEN the coverage test is read.
        block = re.search(r"'integration-shard-coverage',(?P<body>.*?)\n  \)\n", self.meson, re.DOTALL)

        # THEN it receives the same binary, count, seed and filters the tests above use.
        self.assertIsNotNone(block)
        # AND the checker's arguments are in the order its usage line fixes: binary, count, seed, shard filter,
        # then the other filters; swapping the seed and the filter would make the checker list the wrong thing.
        arguments = [line for line in active_lines(block.group("body")) if line not in ("shell,", "args: [", "],")]
        self.assertEqual(
            arguments[:7],
            [
                "meson.project_source_root() / 'scripts' / 'check-integration-shards.sh',",
                "integration_tests.full_path(),",
                "integration_shard_count.to_string(),",
                "integration_shard_seed,",
                "integration_shard_filter,",
                "'[postgresql]',",
                "'[serial]',",
            ],
        )
        self.assertIn("integration_shard_filter = '~[postgresql]~[serial]'", self.active)
        self.assertIn("args: ['[postgresql]'],", self.active)
        self.assertIn("args: ['[serial]'],", self.active)

    def registration(self, name: str) -> str:
        """The text of the `test(...)` call that registers `name`, or of the foreach that registers the shards."""
        start = self.meson.index(f"'{name}'")
        end = re.search(r"\n {2,4}\)\n", self.meson[start:])
        self.assertIsNotNone(end, name)
        return self.meson[start : start + end.start()]

    def test_the_shards_the_postgresql_test_and_the_serial_test_each_pass_their_own_filter(self) -> None:
        # GIVEN the three kinds of registration of the integration binary.
        shards = "\n".join(active_lines(self.registration("integration-tests-shard-@0@-of-@1@")))
        postgresql = "\n".join(active_lines(self.registration("integration-tests-postgresql")))
        serial = "\n".join(active_lines(self.registration("integration-tests-serial")))

        # WHEN their active lines are read, comments removed.
        # THEN the shards take the filter that leaves the other two groups out, and the order arguments that hold the
        # shared seed, so no shard runs a scenario another shard or the filtered tests run.
        self.assertIn("args: [integration_shard_filter] + integration_shard_order_args + [", shards)
        self.assertIn("integration_shard_filter = '~[postgresql]~[serial]'", self.active)
        self.assertRegex(self.active, r"integration_shard_order_args = \[[^\]]*'--rng-seed', integration_shard_seed")
        # AND the PostgreSQL scenarios run in one process, selected by their tag.
        self.assertIn("args: ['[postgresql]'],", postgresql)
        # AND the serial scenarios run in one process with no other test running.
        self.assertIn("args: ['[serial]'],", serial)
        self.assertIn("is_parallel: false,", serial)
        self.assertNotIn("is_parallel: false,", shards)
        self.assertNotIn("is_parallel: false,", postgresql)

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

        # WHEN the check runs.
        # THEN the scenario nothing runs is reported, and the check fails.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("do not run every scenario exactly once", result.stderr)
        self.assertIn("Scenario: scenario 5", result.stderr)

    def test_a_scenario_selected_twice_fails(self) -> None:
        # GIVEN a scenario tagged both [postgresql] and [serial], with the default filters: the PostgreSQL test and the
        # serial test both select it.
        text = scenarios().replace("scenario 5\t[integration][serial]", "scenario 5\t[integration][postgresql][serial]")
        self.assertIn("scenario 5\t[integration][postgresql][serial]", text)
        result = self.run_check(scenario_text=text)

        # WHEN the check runs.
        # THEN the check fails rather than running a scenario twice unnoticed, and names that scenario.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Scenario: scenario 5", result.stderr)

    def test_shards_that_do_not_agree_on_the_order_fail(self) -> None:
        # GIVEN a binary whose first shard swaps two scenarios across its boundary with the second shard, while every
        # process otherwise agrees on one fixed order.
        # WHEN the check lists each shard in its own process.
        result = self.run_check(broken="unseeded")

        # THEN one scenario is listed twice and its neighbour not at all, and the check fails.
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("do not run every scenario exactly once", result.stderr)
        diff_lines = [line for line in result.stderr.splitlines() if re.match(r"[<>] Scenario: ", line)]
        self.assertEqual(sorted(line[0] for line in diff_lines), ["<", ">"])

    def test_an_empty_binary_fails_closed(self) -> None:
        # GIVEN a binary that lists no scenario.
        result = self.run_check(scenario_text="")

        # WHEN the check runs.
        # THEN the check refuses to pass.
        self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
