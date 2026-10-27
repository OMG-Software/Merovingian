// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.password_policy (ADR-0236): the password rule is configurable, and
// strict unless the operator says otherwise.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace
{
[[nodiscard]] auto has_finding(merovingian::config::ConfigParseResult const& result, std::string_view field) -> bool
{
    return std::ranges::any_of(result.findings, [field](merovingian::config::ConfigValidationFinding const& finding) {
        return finding.field == field;
    });
}
} // namespace

SCENARIO("The password policy is strict by default", "[config][password-policy]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the password policy is read")
        {
            auto const& policy = config.security().password_policy;

            THEN("it is the rule the server enforced before it was configurable")
            {
                REQUIRE(policy.min_length == 12U);
                REQUIRE(policy.require_character_classes);
            }
        }
    }
}

SCENARIO("The password policy is read from the config", "[config][password-policy]")
{
    GIVEN("a config that relaxes both parts of the policy")
    {
        auto const input = std::string_view{"security.password_policy.min_length=1\n"
                                            "security.password_policy.require_character_classes=false\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("both settings are read and raise no finding")
            {
                REQUIRE(result.config.security().password_policy.min_length == 1U);
                REQUIRE_FALSE(result.config.security().password_policy.require_character_classes);
                REQUIRE_FALSE(has_finding(result, "security.password_policy.min_length"));
                REQUIRE_FALSE(has_finding(result, "security.password_policy.require_character_classes"));
            }
        }
    }

    GIVEN("the longest minimum the server accepts")
    {
        auto const input = std::string_view{"security.password_policy.min_length=1024\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("it is accepted")
            {
                REQUIRE(result.config.security().password_policy.min_length == 1024U);
                REQUIRE_FALSE(has_finding(result, "security.password_policy.min_length"));
            }
        }
    }
}

SCENARIO("A password policy value outside its range is a startup finding", "[config][password-policy][security]")
{
    struct Case
    {
        std::string_view input;
        std::string_view field;
    };
    auto const cases = {
        // An empty password must never be acceptable.
        Case{"security.password_policy.min_length=0\n",                        "security.password_policy.min_length"},
        // A minimum no client could meet locks registration shut by accident.
        Case{"security.password_policy.min_length=1025\n",                     "security.password_policy.min_length"},
        Case{"security.password_policy.min_length=twelve\n",                   "security.password_policy.min_length"},
        Case{"security.password_policy.min_length=-3\n",                       "security.password_policy.min_length"},
        Case{"security.password_policy.require_character_classes=sometimes\n",
             "security.password_policy.require_character_classes"                                                   },
    };
    for (auto const& item : cases)
    {
        GIVEN("the setting " + std::string{item.input.substr(0U, item.input.size() - 1U)})
        {
            WHEN("the config is parsed")
            {
                auto const result = merovingian::config::parse_key_value_config(item.input);

                THEN("it is refused")
                {
                    REQUIRE(has_finding(result, item.field));
                }
            }
        }
    }
}

SCENARIO("A password policy change takes effect only on restart", "[config][password-policy][reload]")
{
    GIVEN("a running config and one that relaxes the password policy")
    {
        auto const current = merovingian::config::parse_key_value_config("").config;
        auto const next =
            merovingian::config::parse_key_value_config("security.password_policy.min_length=1\n"
                                                        "security.password_policy.require_character_classes=false\n")
                .config;

        WHEN("the reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("both keys change and both need a restart, where the relaxed policy is logged")
            {
                auto const keys = std::vector<std::string>{"security.password_policy.min_length",
                                                           "security.password_policy.require_character_classes"};
                for (auto const& key : keys)
                {
                    REQUIRE(std::ranges::any_of(plan.changes(), [&key](auto const& change) {
                        return change.key == key;
                    }));
                    REQUIRE(merovingian::config::reload_policy_for_key(key) ==
                            merovingian::config::ReloadPolicy::restart_required);
                }
            }
        }
    }
}
