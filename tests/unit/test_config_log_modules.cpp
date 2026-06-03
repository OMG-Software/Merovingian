// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  LOG MODULES CONFIG                                                       |
// |                                                                         |
// |  These scenarios cover the parser wiring of `log_modules.<name>=<L>`   |
// |  keys. Each entry maps a logger name to a level. The wildcard key `*` |
// |  sets the default level (the floor every other module sees). Bad      |
// |  level names become findings; the engine consumes the map at startup  |
// |  via `apply_log_modules` and the result is not hot-reloadable.         |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::config::parse_key_value_config;

} // namespace

SCENARIO("Parsing a log_modules.<name>=<level> line populates the per-module map",
         "[config][log-modules]")
{
    GIVEN("a config that bumps a module to info and silences another")
    {
        auto const input = std::string{"log_modules.http_server=info\n"
                                       "log_modules.auth=warning\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parser populates the per-module map with no findings")
            {
                REQUIRE(result.findings.empty());
                auto const& modules = result.config.log_modules();
                REQUIRE(modules.levels.contains("http_server"));
                REQUIRE(modules.levels.contains("auth"));
            }
        }
    }
}

SCENARIO("Parsing log_modules.<name>=bogus is rejected as a finding",
         "[config][log-modules]")
{
    GIVEN("a config that names an unknown log level")
    {
        auto const input = std::string{"log_modules.http_server=bogus\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parser emits a finding on the offending key")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "log_modules.http_server");
            }
        }
    }
}

SCENARIO("The wildcard key log_modules.*= sets the default level", "[config][log-modules]")
{
    GIVEN("a config that sets the wildcard default level")
    {
        auto const input = std::string{"log_modules.*=warning\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the wildcard entry lands in the map and is reachable as a normal key")
            {
                REQUIRE(result.findings.empty());
                auto const& modules = result.config.log_modules();
                // The parser does not special-case `*`; the runtime
                // applies the wildcard default via `apply_log_modules`.
                REQUIRE(modules.levels.contains("*"));
            }
        }
    }
}
