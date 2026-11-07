// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "NonCapturingXmlReporter.hpp"

#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace merovingian::tests
{

// Environment variable naming a directory. When it is set, each Catch2 test binary also writes an XML report
// there, which scripts/check_expected_skips.py reads to find the test cases that skipped (ADR-0546).
inline constexpr auto catch_report_directory_variable = "MEROVINGIAN_CATCH_REPORT_DIR";

// The command line Catch2 should run with: argv unchanged, plus -- only when the variable above names a directory --
// the console reporter the developer already sees and an XML reporter writing <dir>/<binary>-<pid>.xml. That is
// NonCapturingXmlReporter, which each test_main.cpp registers: the stock xml reporter captures stdout. The
// process id keeps two runs of one binary (meson may run the same executable twice) from overwriting each other.
// With the variable unset the command line is exactly argv, so a local run behaves as before.
[[nodiscard]] inline auto catch_report_arguments(int argc, char const* const* argv) -> std::vector<std::string>
{
    auto arguments = std::vector<std::string>{argv, argv + argc};
    auto const* const directory = std::getenv(catch_report_directory_variable);
    if (directory == nullptr || *directory == '\0' || argc < 1)
    {
        return arguments;
    }
    auto const binary = std::filesystem::path{argv[0]}.filename().string();
    auto const report = std::filesystem::path{directory} / (binary + "-" + std::to_string(::getpid()) + ".xml");
    arguments.emplace_back("--reporter");
    arguments.emplace_back("console");
    arguments.emplace_back("--reporter");
    arguments.emplace_back(std::string{non_capturing_xml_reporter_name} + "::out=" + report.string());
    return arguments;
}

} // namespace merovingian::tests
