// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// presence.enabled: presence is tracked and exchanged unless the operator turns it off.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>

namespace
{
[[nodiscard]] auto has_finding(merovingian::config::ConfigParseResult const& result, std::string_view field) -> bool
{
    return std::ranges::any_of(result.findings, [field](merovingian::config::ConfigValidationFinding const& finding) {
        return finding.field == field;
    });
}
} // namespace

SCENARIO("Presence is enabled by default", "[config][presence]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the presence section is read")
        {
            THEN("presence is on")
            {
                REQUIRE(config.presence().enabled);
            }
        }
    }
}

SCENARIO("presence.enabled is read from the config", "[config][presence]")
{
    GIVEN("a config that turns presence off")
    {
        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("presence.enabled=false\n");

            THEN("presence is off and no finding is raised")
            {
                REQUIRE_FALSE(result.config.presence().enabled);
                REQUIRE_FALSE(has_finding(result, "presence.enabled"));
            }
        }
    }

    GIVEN("a config that spells the default out")
    {
        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("presence.enabled=true\n");

            THEN("presence is on and no finding is raised")
            {
                REQUIRE(result.config.presence().enabled);
                REQUIRE_FALSE(has_finding(result, "presence.enabled"));
            }
        }
    }

    GIVEN("a value that is not a boolean")
    {
        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("presence.enabled=sometimes\n");

            THEN("it is refused rather than read as one of the two")
            {
                REQUIRE(has_finding(result, "presence.enabled"));
            }
        }
    }
}

SCENARIO("A presence.enabled change takes effect only on restart", "[config][presence][reload]")
{
    GIVEN("a running config with presence on and one that turns it off")
    {
        auto const current = merovingian::config::parse_key_value_config("").config;
        auto const next = merovingian::config::parse_key_value_config("presence.enabled=false\n").config;

        WHEN("the reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the key is a change and needs a restart, as the main process and the worker read it at start")
            {
                REQUIRE(std::ranges::any_of(plan.changes(), [](auto const& change) {
                    return change.key == "presence.enabled";
                }));
                REQUIRE(merovingian::config::reload_policy_for_key("presence.enabled") ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}
