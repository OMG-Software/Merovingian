// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// CS8 (ADR-0548): security.login_token.enabled is a boolean, off by default, and a live reload.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("security.login_token.enabled is a reloadable boolean that defaults to off", "[cs8][login-token][config]")
{
    GIVEN("the default configuration")
    {
        WHEN("the login token switch is read")
        {
            THEN("the feature is off")
            {
                REQUIRE_FALSE(merovingian::config::SecurityConfig{}.login_token.enabled);
            }
        }
    }

    GIVEN("a config file that turns the feature on")
    {
        WHEN("it is parsed and compared with the defaults")
        {
            auto const parsed = merovingian::config::parse_key_value_config("security.login_token.enabled=true\n");
            auto const plan = merovingian::config::build_reload_plan(merovingian::config::Config{}, parsed.config);

            THEN("the feature is on and the change is a live reload")
            {
                REQUIRE(parsed.findings.empty());
                REQUIRE(parsed.config.security().login_token.enabled);
                REQUIRE(plan.changes().size() == 1U);
                REQUIRE(plan.reloadable_change_count() == 1U);
                REQUIRE(merovingian::config::reload_policy_for_key("security.login_token.enabled") ==
                        merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }

    GIVEN("a config file whose value is not a boolean")
    {
        WHEN("it is parsed")
        {
            auto const parsed = merovingian::config::parse_key_value_config("security.login_token.enabled=maybe\n");

            THEN("the parser reports the key")
            {
                REQUIRE_FALSE(parsed.findings.empty());
                REQUIRE(parsed.findings.front().field == "security.login_token.enabled");
                REQUIRE_FALSE(parsed.config.security().login_token.enabled);
            }
        }
    }
}
