#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""scripts/check-elf-hardening.sh against the readelf of each platform (ADR-0757).

The FreeBSD release evidence reported BIND_NOW missing from a binary that had it:
the BSDs' elftoolchain readelf prints the dynamic flags as "(FLAGS) BIND_NOW" and
"(FLAGS_1) NOW", and the gate knew only GNU binutils' "(FLAGS_1) Flags: NOW". These
tests run the gate with a fake readelf on PATH that prints each tool's output.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check-elf-hardening.sh"

GNU_HEADER_PIE = """ELF Header:
  Class:                             ELF64
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
"""

ELFTOOLCHAIN_HEADER_PIE = """ELF Header:
  Class:                             ELF64
  Type:                              DYN (Shared object file)
  Machine:                           AMD x86-64
"""

ELFTOOLCHAIN_HEADER_EXEC = """ELF Header:
  Class:                             ELF64
  Type:                              EXEC (Executable file)
  Machine:                           AMD x86-64
"""

PROGRAM_HEADERS = """Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x001000 0x001000 R   0x1000
  GNU_RELRO      0x002000 0x0000000000002000 0x0000000000002000 0x000100 0x001000 R   0x1
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0
"""

GNU_DYNAMIC_NOW = """Dynamic section at offset 0x2000 contains 4 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x0000000000000000 (NULL)               0x0
"""

# What /usr/bin/readelf printed on FreeBSD 15.1 for a build linked with -Wl,-z,now.
ELFTOOLCHAIN_DYNAMIC_NOW = """Dynamic section at offset 0x2000 contains 4 entries:
  Tag                Type          Name/Value
  0x0000000000000001 (NEEDED)        Shared library: [libc.so.7]
  0x000000000000001e (FLAGS)        BIND_NOW
  0x000000006ffffffb (FLAGS_1)      NOW
  0x0000000000000000 (NULL)          0x0
"""

ELFTOOLCHAIN_DYNAMIC_LAZY = """Dynamic section at offset 0x2000 contains 3 entries:
  Tag                Type          Name/Value
  0x0000000000000001 (NEEDED)        Shared library: [libc.so.7]
  0x000000006ffffffb (FLAGS_1)      PIE
  0x0000000000000000 (NULL)          0x0
"""


class CheckElfHardeningTests(unittest.TestCase):
    def run_gate(self, header: str, dynamic: str) -> subprocess.CompletedProcess[str]:
        sh = shutil.which("sh")
        if sh is None:
            self.skipTest("sh is not available")
        with tempfile.TemporaryDirectory(prefix="check-elf-hardening-") as scratch:
            root = Path(scratch)
            outputs = {"header": header, "program": PROGRAM_HEADERS, "dynamic": dynamic}
            for name, text in outputs.items():
                (root / f"{name}.txt").write_text(text, encoding="utf-8", newline="\n")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            readelf = fake_bin / "readelf"
            readelf.write_text(
                "#!/bin/sh\n"
                'case "$1" in\n'
                f'    -h) cat "{root}/header.txt" ;;\n'
                f'    -lW) cat "{root}/program.txt" ;;\n'
                f'    -d) cat "{root}/dynamic.txt" ;;\n'
                "    *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
                newline="\n",
            )
            readelf.chmod(readelf.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            binary = root / "merovingian-server"
            binary.write_bytes(b"\x7fELF")
            environment = dict(os.environ)
            environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
            return subprocess.run(
                [sh, str(GATE), str(binary)],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
            )

    def test_a_hardened_binary_passes_with_gnu_readelf(self) -> None:
        # GIVEN GNU binutils' output for a PIE binary with BIND_NOW
        # WHEN the gate reads it
        result = self.run_gate(GNU_HEADER_PIE, GNU_DYNAMIC_NOW)

        # THEN every check passes
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("OK: BIND_NOW", result.stdout)

    def test_a_hardened_binary_passes_with_the_bsd_elftoolchain_readelf(self) -> None:
        # GIVEN FreeBSD's elftoolchain output for a PIE binary with BIND_NOW
        # WHEN the gate reads it
        result = self.run_gate(ELFTOOLCHAIN_HEADER_PIE, ELFTOOLCHAIN_DYNAMIC_NOW)

        # THEN BIND_NOW is recognised and every check passes
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("OK: BIND_NOW", result.stdout)
        self.assertIn("OK: PIE", result.stdout)

    def test_lazy_binding_still_fails_with_the_bsd_elftoolchain_readelf(self) -> None:
        # GIVEN elftoolchain output whose FLAGS_1 holds PIE but not NOW, and no DT_FLAGS
        # WHEN the gate reads it
        result = self.run_gate(ELFTOOLCHAIN_HEADER_PIE, ELFTOOLCHAIN_DYNAMIC_LAZY)

        # THEN BIND_NOW fails, so the wider match did not let lazy binding through
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("FAIL: BIND_NOW", result.stderr)

    def test_an_executable_that_is_not_pie_fails(self) -> None:
        # GIVEN elftoolchain output for an ET_EXEC binary, as FreeBSD's clang links without -pie
        # WHEN the gate reads it
        result = self.run_gate(ELFTOOLCHAIN_HEADER_EXEC, ELFTOOLCHAIN_DYNAMIC_NOW)

        # THEN PIE fails and nothing else does
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("FAIL: PIE", result.stderr)
        self.assertIn("1 check(s) failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
