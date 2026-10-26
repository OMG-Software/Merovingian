// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.registration.allow_open_registration (ADR-0232): registration
// without a token is refused at startup unless the operator acknowledges it.

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

SCENARIO("Open registration is not acknowledged by default", "[config][registration][open-registration]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the registration policy is read")
        {
            auto const& registration = config.security().registration;

            THEN("registration is off, token-gated, and open registration is not acknowledged")
            {
                REQUIRE_FALSE(registration.enabled);
                REQUIRE(registration.require_token);
                REQUIRE_FALSE(registration.allow_open_registration);
            }
        }
    }
}

SCENARIO("Registration without a token needs the explicit acknowledgement",
         "[config][registration][open-registration][security]")
{
    GIVEN("registration enabled without a token and without the acknowledgement")
    {
        auto const input = std::string_view{"security.registration.enabled=true\n"
                                            "security.registration.require_token=false\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("it is a startup finding")
            {
                REQUIRE(has_finding(result, "security.registration.require_token"));
            }
        }
    }

    GIVEN("registration enabled without a token and with the acknowledgement")
    {
        auto const input = std::string_view{"security.registration.enabled=true\n"
                                            "security.registration.require_token=false\n"
                                            "security.registration.allow_open_registration=true\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the setting is read and registration raises no finding")
            {
                REQUIRE(result.config.security().registration.allow_open_registration);
                REQUIRE_FALSE(has_finding(result, "security.registration.require_token"));
                REQUIRE_FALSE(has_finding(result, "security.registration.token_file"));
                REQUIRE_FALSE(has_finding(result, "security.registration.allow_open_registration"));
            }
        }
    }

    GIVEN("an acknowledgement that is not a boolean")
    {
        auto const input = std::string_view{"security.registration.allow_open_registration=yes please\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("it is a parse finding and the acknowledgement stays off")
            {
                REQUIRE(has_finding(result, "security.registration.allow_open_registration"));
                REQUIRE_FALSE(result.config.security().registration.allow_open_registration);
            }
        }
    }
}

SCENARIO("The open-registration acknowledgement reloads like the token requirement",
         "[config][registration][open-registration][reload]")
{
    GIVEN("a running config and a next config that acknowledges open registration")
    {
        auto const current = merovingian::config::Config{};
        auto const next =
            merovingian::config::parse_key_value_config("security.registration.allow_open_registration=true\n").config;

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the change is reported with the same policy as require_token")
            {
                auto const change = std::ranges::find_if(plan.changes(), [](auto const& candidate) {
                    return candidate.key == "security.registration.allow_open_registration";
                });
                REQUIRE(change != plan.changes().end());
                REQUIRE(change->policy ==
                        merovingian::config::reload_policy_for_key("security.registration.require_token"));
            }
        }
    }
}
