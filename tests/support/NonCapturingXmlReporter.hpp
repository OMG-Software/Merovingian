// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <catch2/reporters/catch_reporter_xml.hpp>

#include <string>
#include <utility>

namespace merovingian::tests
{

// Catch2's XML reporter with output capture turned off (ADR-0546). The stock one sets shouldRedirectStdOut, so Catch
// redirects std::cout during every test and puts its own buffer back around each reported assertion. That replaces a
// buffer a test installed with std::cout.rdbuf(), and the logger tests that capture the console that way then read
// nothing after their first assertion. The report format is unchanged: scripts/check_expected_skips.py reads it as
// before, and a report only lacks the StdOut and StdErr elements the capture filled.
class NonCapturingXmlReporter final : public Catch::XmlReporter
{
public:
    explicit NonCapturingXmlReporter(Catch::ReporterConfig&& config)
        : Catch::XmlReporter{std::move(config)}
    {
        m_preferences.shouldRedirectStdOut = false;
    }

    [[nodiscard]] static auto getDescription() -> std::string
    {
        return "Catch2's XML reporter without stdout and stderr capture, for the skip reports (ADR-0546)";
    }
};

// The name the test mains register it under and catch_report_arguments asks for.
inline constexpr auto non_capturing_xml_reporter_name = "merovingian-xml";

} // namespace merovingian::tests
