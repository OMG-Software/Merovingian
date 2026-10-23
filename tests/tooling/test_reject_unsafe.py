#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "reject-unsafe.sh"


class RejectUnsafeVoidCastTests(unittest.TestCase):
    """reject-unsafe.sh refuses void-cast discards (AGENTS.md: use std::ignore).

    GCC, unlike clang, does not let a void cast silence warn_unused_result, so a
    cast that builds on clang fails the GCC coverage job under -Werror.
    """

    def run_gate(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        with tempfile.TemporaryDirectory(prefix="reject-unsafe-") as scratch:
            root = Path(scratch)
            for directory in ("include", "src", "tests"):
                (root / directory).mkdir()
            for relative, text in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
            return subprocess.run(
                [bash, str(GATE)],
                cwd=root,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

    def assert_rejected(self, files: dict[str, str]) -> None:
        result = self.run_gate(files)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("void cast", result.stdout)

    def assert_accepted(self, files: dict[str, str]) -> None:
        result = self.run_gate(files)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_static_cast_to_void_is_rejected(self) -> None:
        # GIVEN production code that discards a result with static_cast<void>.
        # WHEN the gate runs.
        # THEN it rejects the file.
        self.assert_rejected({"src/a.cpp": "void f() {\n    static_cast<void>(compute());\n}\n"})

    def test_c_style_void_cast_is_rejected_in_every_root(self) -> None:
        # GIVEN a C-style (void) discard in src/, include/ or tests/.
        for path in ("src/a.cpp", "include/merovingian/a.hpp", "tests/unit/test_a.cpp"):
            with self.subTest(path=path):
                # WHEN the gate runs.
                # THEN it rejects the file.
                self.assert_rejected({path: "void f() {\n    (void)compute();\n}\n"})

    def test_void_cast_after_an_assignment_or_return_is_rejected(self) -> None:
        # GIVEN void casts that do not start the line.
        # WHEN the gate runs.
        # THEN each is rejected.
        self.assert_rejected({"src/a.cpp": "auto g() { return (void) compute(); }\n"})
        self.assert_rejected({"src/b.cpp": "void h() { if (x) static_cast< void >(compute()); }\n"})

    def test_std_ignore_and_void_in_types_are_accepted(self) -> None:
        # GIVEN std::ignore discards, function types and C-style empty parameter lists.
        source = (
            "#include <functional>\n"
            "#include <tuple>\n"
            "using Callback = std::function<void(int)>;\n"
            "int legacy(void);\n"
            "void (*pointer)(void) = nullptr;\n"
            "auto method(void) const -> int;\n"
            "void f() {\n"
            "    std::ignore = compute();\n"
            "}\n"
        )
        # WHEN the gate runs.
        # THEN none of them is mistaken for a void cast.
        self.assert_accepted({"src/a.cpp": source})

    def test_comments_that_name_the_rule_are_accepted(self) -> None:
        # GIVEN comments that mention the banned forms.
        source = (
            "// Never write (void)expr or static_cast<void>(expr); use std::ignore.\n"
            "int x = 0; // was (void)compute();\n"
        )
        # WHEN the gate runs.
        # THEN comments are not code and are not rejected.
        self.assert_accepted({"src/a.cpp": source})

    # The repository's own tree is not scanned here: the pre-commit hook and the
    # CI jobs already run the gate over it, and doing it again on a slow mount
    # costs longer than this suite's timeout.


if __name__ == "__main__":
    unittest.main()
