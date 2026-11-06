#!/usr/bin/env python3
"""Check include grouping through the project's actual clang-format configuration."""
from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


class IncludeOrderTests(unittest.TestCase):
    def format_includes(self, source: str) -> str:
        formatter = shutil.which("clang-format")
        if formatter is None:
            self.skipTest("clang-format is not available")
        result = subprocess.run(
            [formatter, "--style=file", "--assume-filename=src/core/Widget.cpp"],
            input=source,
            text=True,
            capture_output=True,
            check=True,
            cwd=REPO_ROOT,
            timeout=30,
        )
        return result.stdout.strip()

    def test_own_project_external_and_standard_headers_form_four_groups(self) -> None:
        # GIVEN shuffled matching, project, third-party, and standard headers.
        source = '''#include <vector>
#include "merovingian/core/Other.hpp"
#include <sodium.h>
#include "merovingian/core/Widget.hpp"
#include <curl/curl.h>
#include <algorithm>
'''
        # WHEN clang-format groups the includes using the project configuration.
        actual = self.format_includes(source)
        # THEN the matching header is first, followed by project, external, and STL.
        self.assertEqual(actual, '''#include "merovingian/core/Widget.hpp"

#include "merovingian/core/Other.hpp"

#include <curl/curl.h>
#include <sodium.h>

#include <algorithm>
#include <vector>''')

    def test_flat_library_and_system_headers_precede_standard_headers(self) -> None:
        # GIVEN flat library and OS headers mixed with standard library headers.
        source = '''#include <string>
#include <unistd.h>
#include <yyjson.h>
#include <sys/socket.h>
#include <libpq-fe.h>
#include <array>
'''
        # WHEN the formatter sorts the includes.
        actual = self.format_includes(source)
        # THEN every external header is in one group before the standard library.
        self.assertEqual(actual, '''#include <libpq-fe.h>
#include <sys/socket.h>
#include <unistd.h>
#include <yyjson.h>

#include <array>
#include <string>''')

    def test_cpp26_headers_and_c_wrappers_remain_standard_library_headers(self) -> None:
        # GIVEN C++26 headers, C library wrappers, and a dotless external header.
        source = '''#include <text_encoding>
#include <cstdint>
#include <vendor_header>
#include <inplace_vector>
#include <cassert>
#include <hive>
#include <stddef.h>
'''
        # WHEN the formatter groups these header names.
        actual = self.format_includes(source)
        # THEN spelling without a dot does not make an external header standard.
        self.assertEqual(actual, '''#include <vendor_header>

#include <cassert>
#include <cstdint>
#include <hive>
#include <inplace_vector>
#include <stddef.h>
#include <text_encoding>''')


if __name__ == "__main__":
    unittest.main()
