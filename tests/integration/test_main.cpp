// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/NonCapturingXmlReporter.hpp"
#include "../support/CatchReportArguments.hpp"

#include <catch2/catch_session.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <csignal>
#include <string>
#include <vector>

// The XML reporter catch_report_arguments asks for when MEROVINGIAN_CATCH_REPORT_DIR is set (ADR-0546).
CATCH_REGISTER_REPORTER(merovingian::tests::non_capturing_xml_reporter_name,
                        merovingian::tests::NonCapturingXmlReporter)

auto main(int argc, char* argv[]) -> int
{
    // Network-facing integration tests open TLS sockets that the remote side
    // can close abruptly when, for example, the client rejects the server's
    // certificate. Default SIGPIPE handling would kill the test process when
    // the server thread later writes to the closed peer. Ignoring SIGPIPE
    // keeps the failures observable through return values without losing
    // any test fidelity.
    std::signal(SIGPIPE, SIG_IGN);
    auto const arguments = merovingian::tests::catch_report_arguments(argc, argv);
    auto pointers = std::vector<char const*>{};
    for (auto const& argument : arguments)
    {
        pointers.push_back(argument.c_str());
    }
    return Catch::Session{}.run(static_cast<int>(pointers.size()), pointers.data());
}
