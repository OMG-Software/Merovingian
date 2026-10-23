#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "reject-unsafe.sh"


def pcre_grep_available() -> bool:
    """True when the gate can find a grep with -P, as it looks for one: grep, then ggrep.

    The BSD greps have no -P (NetBSD, FreeBSD and OpenBSD CI hosts), and there the
    gate refuses to run at all; see RejectUnsafeNeedsPcreGrepTests.
    """
    for candidate in ("grep", "ggrep"):
        path = shutil.which(candidate)
        if path is None:
            continue
        probe = subprocess.run([path, "-qP", "x"], input="x\n", text=True, capture_output=True, check=False)
        if probe.returncode == 0:
            return True
    return False


@unittest.skipUnless(pcre_grep_available(), "no grep with -P on this host; the gate refuses to run here")
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

    def test_void_cast_after_a_string_holding_double_slash_is_rejected(self) -> None:
        # GIVEN a void cast after a string or character literal that contains "//",
        # which is not a comment.
        # WHEN the gate runs.
        # THEN the cast is still rejected.
        self.assert_rejected(
            {"src/a.cpp": 'void f() { auto url = "https://example.org"; (void)write(fd, data, size); }\n'}
        )
        self.assert_rejected(
            {"src/b.cpp": 'void g() { auto s = "a \\" // b"; static_cast<void>(compute()); }\n'}
        )

    def test_raw_string_literals_are_read_whole(self) -> None:
        # GIVEN raw string literals, which may hold unescaped quotes and parentheses.
        # WHEN the gate runs.
        # THEN a cast spelled inside one is not code and is accepted...
        self.assert_accepted({"src/a.cpp": 'auto const s = R"tag(text " (void)x )tag";\n'})
        self.assert_accepted({"src/b.cpp": 'auto const s = u8R"q(say "static_cast<void>(x)")q";\n'})
        # AND a real cast after one is still rejected.
        self.assert_rejected({"src/c.cpp": 'void f() { auto s = R"(a "b")"; (void)compute(); }\n'})

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

    def test_cast_spelled_inside_a_string_is_accepted(self) -> None:
        # GIVEN string and character literals that merely spell the banned forms.
        source = (
            'auto const message = "write std::ignore, not static_cast<void>(x) or (void)x";\n'
            "char const quote = '\"'; int y = 0; // (void)y\n"
        )
        # WHEN the gate runs.
        # THEN text inside a literal is not code and is not rejected.
        self.assert_accepted({"src/a.cpp": source})

    # The repository's own tree is not scanned here: the pre-commit hook and the
    # CI jobs already run the gate over it, and doing it again on a slow mount
    # costs longer than this suite's timeout.


class RejectUnsafeNeedsPcreGrepTests(unittest.TestCase):
    """Without a grep that has -P the gate fails closed instead of checking nothing.

    Every rule uses -P. A BSD grep exits 2 for each pattern, which the rules would
    read as "no match", so the gate passed on NetBSD without checking anything.
    """

    def test_gate_refuses_to_run_without_a_pcre_grep(self) -> None:
        bash = shutil.which("bash")
        real_grep = shutil.which("grep")
        if bash is None or real_grep is None:
            self.skipTest("bash or grep is not available")
        with tempfile.TemporaryDirectory(prefix="reject-unsafe-nopcre-") as scratch:
            root = Path(scratch)
            # GIVEN a host whose grep and ggrep both refuse -P, as the BSD greps do.
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for name in ("grep", "ggrep"):
                fake = fake_bin / name
                fake.write_text(
                    "#!/bin/sh\n"
                    'for arg in "$@"; do\n'
                    '  case "$arg" in -P|--perl-regexp|-[A-Za-z]*P*) '
                    'echo "grep: The -P option is not supported" >&2; exit 2;; esac\n'
                    "done\n"
                    f'exec "{real_grep}" "$@"\n',
                    encoding="utf-8",
                    newline="\n",
                )
                fake.chmod(0o755)
            # AND a tree with nothing to reject, so a silent pass would look like success.
            for directory in ("include", "src", "tests"):
                (root / "tree" / directory).mkdir(parents=True)
            (root / "tree" / "src" / "a.cpp").write_text("int f() { return 0; }\n", encoding="utf-8")
            environment = dict(os.environ, PATH=f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}")

            # WHEN the gate runs.
            result = subprocess.run(
                [bash, str(GATE)],
                cwd=root / "tree",
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

        # THEN it fails and says why, rather than passing without checking.
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("grep with -P", result.stdout)


if __name__ == "__main__":
    unittest.main()
