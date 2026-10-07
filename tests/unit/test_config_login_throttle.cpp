// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// AUTH-2 (security-audit-report-2026-09-29.md): the login failure throttle's
// per-source threshold, per-account ceiling and window are operator-tunable.

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <string>

namespace
{

[[nodiscard]] auto finding_text(merovingian::config::ConfigParseResult const& parsed) -> std::string
{
    auto text = std::string{};
    for (auto const& finding : parsed.findings)
    {
        text += finding.field + ": " + finding.message + "\n";
    }
    return text;
}

[[nodiscard]] auto validation_mentions(merovingian::config::Config const& config, std::string const& key) -> bool
{
    auto const findings = merovingian::config::validate(config);
    return std::ranges::any_of(findings, [&key](auto const& finding) {
        return finding.field == key;
    });
}

} // namespace

SCENARIO("The login throttle defaults to 5 per source, 50 per account, in 15 minutes",
         "[config][auth][login-throttle][auth-2]")
{
    GIVEN("a default configuration")
    {
        auto const config = merovingian::config::Config{};

        THEN("the throttle uses the audited defaults and validates")
        {
            auto const& throttle = config.security().login_throttle;
            REQUIRE(throttle.max_failures_per_source == 5U);
            REQUIRE(throttle.max_failures_per_account == 50U);
            REQUIRE(throttle.window == "15m");
            REQUIRE_FALSE(validation_mentions(config, "security.login_throttle.max_failures_per_source"));
            REQUIRE_FALSE(validation_mentions(config, "security.login_throttle.max_failures_per_account"));
            REQUIRE_FALSE(validation_mentions(config, "security.login_throttle.window"));
        }
    }
}

SCENARIO("The login throttle can be tuned and a change is reloadable", "[config][auth][login-throttle][auth-2]")
{
    GIVEN("an operator override of all three keys")
    {
        auto const input = std::string{"security.login_throttle.max_failures_per_source=3\n"
                                       "security.login_throttle.max_failures_per_account=20\n"
                                       "security.login_throttle.window=30m\n"};

        WHEN("it is parsed, validated and compared with the defaults")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);
            auto const plan = merovingian::config::build_reload_plan(merovingian::config::Config{}, parsed.config);

            THEN("the overrides survive, validation passes and every key is a live reload")
            {
                INFO(finding_text(parsed));
                REQUIRE(parsed.findings.empty());
                REQUIRE(merovingian::config::validate(parsed.config).empty());
                REQUIRE(parsed.config.security().login_throttle.max_failures_per_source == 3U);
                REQUIRE(parsed.config.security().login_throttle.max_failures_per_account == 20U);
                REQUIRE(parsed.config.security().login_throttle.window == "30m");
                REQUIRE(plan.changes().size() == 3U);
                REQUIRE(plan.reloadable_change_count() == 3U);
                REQUIRE(plan.restart_required_change_count() == 0U);
            }
        }

        THEN("the reload policy classifies the keys as reloadable")
        {
            REQUIRE(merovingian::config::reload_policy_for_key("security.login_throttle.max_failures_per_source") ==
                    merovingian::config::ReloadPolicy::reloadable);
            REQUIRE(merovingian::config::reload_policy_for_key("security.login_throttle.max_failures_per_account") ==
                    merovingian::config::ReloadPolicy::reloadable);
            REQUIRE(merovingian::config::reload_policy_for_key("security.login_throttle.window") ==
                    merovingian::config::ReloadPolicy::reloadable);
        }
    }
}

SCENARIO("The login throttle rejects zero, oversized and malformed values", "[config][auth][login-throttle][auth-2]")
{
    GIVEN("an invalid override")
    {
        auto const input =
            GENERATE(as<std::string>{}, "security.login_throttle.max_failures_per_source=0\n",
                     "security.login_throttle.max_failures_per_source=1001\n",
                     "security.login_throttle.max_failures_per_account=0\n",
                     "security.login_throttle.max_failures_per_account=100001\n", "security.login_throttle.window=0s\n",
                     "security.login_throttle.window=0m\n", "security.login_throttle.window=1441m\n",
                     "security.login_throttle.window=25h\n", "security.login_throttle.window=forever\n",
                     "security.login_throttle.window=15\n", "security.login_throttle.max_failures_per_source=abc\n",
                     "security.login_throttle.max_failures_per_account=-1\n");

        WHEN("it is parsed and validated")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);
            auto const validation = merovingian::config::validate(parsed.config);

            THEN("the value is rejected at parse or validation time")
            {
                INFO(input);
                REQUIRE((!parsed.findings.empty() || !validation.empty()));
            }
        }
    }

    GIVEN("a per-account ceiling lower than the per-source threshold")
    {
        auto const input = std::string{"security.login_throttle.max_failures_per_source=10\n"
                                       "security.login_throttle.max_failures_per_account=5\n"};

        WHEN("it is parsed and validated")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);

            THEN("validation names the ceiling, because it could never be the binding limit")
            {
                REQUIRE(validation_mentions(parsed.config, "security.login_throttle.max_failures_per_account"));
            }
        }
    }

    GIVEN("values exactly at the documented maxima")
    {
        auto const input = std::string{"security.login_throttle.max_failures_per_source=1000\n"
                                       "security.login_throttle.max_failures_per_account=100000\n"
                                       "security.login_throttle.window=1440m\n"};

        WHEN("it is parsed and validated")
        {
            auto const parsed = merovingian::config::parse_key_value_config(input);

            THEN("they are accepted")
            {
                INFO(finding_text(parsed));
                REQUIRE(parsed.findings.empty());
                REQUIRE(merovingian::config::validate(parsed.config).empty());
            }
        }
    }
}
