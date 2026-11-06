#!/usr/bin/env python3
"""Every fuzz target is built, seeded and run by the CI runner, and the runner instruments the libraries
under test (ADR-0503)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FUZZ_DIR = REPO_ROOT / "tests" / "fuzz"
RUNNER = REPO_ROOT / "scripts" / "run-fuzz-targets.sh"


def target_names_in_meson() -> set[str]:
    meson = (FUZZ_DIR / "meson.build").read_text(encoding="utf-8")
    return set(re.findall(r"'(fuzz-[a-z0-9-]+)'", meson))


class FuzzTargetTests(unittest.TestCase):
    def test_the_runner_runs_every_registered_target(self) -> None:
        # GIVEN the targets registered in tests/fuzz/meson.build and the CI runner script.
        registered = target_names_in_meson()
        runner = RUNNER.read_text(encoding="utf-8")
        run = set(re.findall(r"^run_target (fuzz-[a-z0-9-]+) ", runner, re.MULTILINE))

        # WHEN the two are compared.
        # THEN no registered target is built and then never run, and none is run without being built.
        self.assertTrue(registered, "no fuzz target found in tests/fuzz/meson.build")
        self.assertEqual(registered, run)

    def test_every_registered_target_has_a_source_and_a_seed_corpus(self) -> None:
        # GIVEN the registered targets.
        for name in sorted(target_names_in_meson()):
            # WHEN the source and corpus of each are looked for.
            source = FUZZ_DIR / (name.replace("-", "_") + ".cpp")
            corpus = FUZZ_DIR / "corpus" / name

            # THEN the source exists, and the corpus holds at least one seed.
            self.assertTrue(source.is_file(), f"{name}: {source.name} is missing")
            self.assertTrue(
                corpus.is_dir() and any(corpus.iterdir()),
                f"{name}: tests/fuzz/corpus/{name}/ holds no seed",
            )

    def test_the_runner_instruments_the_code_under_test(self) -> None:
        # GIVEN the CI runner script.
        runner = RUNNER.read_text(encoding="utf-8")

        # WHEN its meson setup commands and the options they take are read.
        setups = re.findall(r"meson setup .*?(?=\n(?:else|fi))", runner, re.DOTALL)

        # THEN both commands build the libraries with sanitizers and coverage counters, so a finding in
        # a parser is seen and the fuzzer is guided by the parser, not only by the target's own file.
        self.assertIn("-Db_sanitize=address,undefined", runner)
        self.assertIn("-fsanitize-coverage=", runner)
        self.assertEqual(len(setups), 2)
        for command in setups:
            self.assertIn("$instrumentation", command)
            self.assertIn("-Dc_args=$coverage_flags", command)
            self.assertIn("-Dcpp_args=$coverage_flags", command)


if __name__ == "__main__":
    unittest.main()
