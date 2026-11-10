// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/NonCapturingXmlReporter.hpp"
#include "../support/CatchReportArguments.hpp"

#include <catch2/catch_session.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <string>
#include <vector>

// The XML reporter catch_report_arguments asks for when MEROVINGIAN_CATCH_REPORT_DIR is set (ADR-0546).
CATCH_REGISTER_REPORTER(merovingian::tests::non_capturing_xml_reporter_name,
                        merovingian::tests::NonCapturingXmlReporter)

auto main(int argc, char* argv[]) -> int
{
    auto const arguments = merovingian::tests::catch_report_arguments(argc, argv);
    auto pointers = std::vector<char const*>{};
    for (auto const& argument : arguments)
    {
        pointers.push_back(argument.c_str());
    }
    return Catch::Session{}.run(static_cast<int>(pointers.size()), pointers.data());
}
