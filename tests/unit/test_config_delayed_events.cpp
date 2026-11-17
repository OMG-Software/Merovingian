// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.delayed_events.*: the operator's switch and limits for delayed events (MSC4140; ADR-0826). The routes are not
// in Matrix v1.19, so these are project-level checks of parsing, validation and reload classification.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/DelayedEventsConfig.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/ServerConfig.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto has_finding(std::vector<merovingian::config::ConfigValidationFinding> const& findings,
                               std::string_view field) -> bool
{
    for (auto const& finding : findings)
    {
        if (finding.field == field)
        {
            return true;
        }
    }
    return false;
}

[[nodiscard]] auto parse_key(std::string_view key, std::string_view value) -> merovingian::config::ConfigParseResult
{
    return merovingian::config::parse_key_value_config(std::string{key} + "=" + std::string{value} + "\n");
}

[[nodiscard]] auto reported_in_plan(merovingian::config::ReloadPlan const& plan, std::string_view key) -> bool
{
    for (auto const& change : plan.changes())
    {
        if (change.key == key)
        {
            return true;
        }
    }
    return false;
}

constexpr auto enabled_key = std::string_view{"server.delayed_events.enabled"};
constexpr auto delay_key = std::string_view{"server.delayed_events.max_delay_ms"};
constexpr auto scheduled_key = std::string_view{"server.delayed_events.max_scheduled_per_user"};
constexpr auto finalised_key = std::string_view{"server.delayed_events.max_finalised_per_user"};

constexpr auto all_non_default = std::string_view{"server.delayed_events.enabled=false\n"
                                                  "server.delayed_events.max_delay_ms=3600000\n"
                                                  "server.delayed_events.max_scheduled_per_user=7\n"
                                                  "server.delayed_events.max_finalised_per_user=9\n"};

} // namespace

SCENARIO("server.delayed_events.* default to on with a one-day delay and 100 events per user",
         "[config][delayed-events]")
{
    GIVEN("a configuration that does not mention the section")
    {
        auto const parsed = merovingian::config::parse_key_value_config("");

        THEN("delayed events are enabled with the documented limits and nothing is reported")
        {
            auto const& delayed = parsed.config.server().delayed_events;
            CHECK(delayed.enabled);
            CHECK(delayed.max_delay_ms == std::uint64_t{86'400'000U});
            CHECK(delayed.max_scheduled_per_user == 100U);
            CHECK(delayed.max_finalised_per_user == 100U);
            CHECK(parsed.findings.empty());
            CHECK(merovingian::config::is_valid(parsed.config));
        }
    }
}

SCENARIO("each server.delayed_events.* key is parsed", "[config][delayed-events]")
{
    GIVEN("a configuration that sets every key to a non-default value")
    {
        auto const parsed = merovingian::config::parse_key_value_config(all_non_default);

        THEN("the values are held and the configuration is valid")
        {
            auto const& delayed = parsed.config.server().delayed_events;
            CHECK_FALSE(delayed.enabled);
            CHECK(delayed.max_delay_ms == std::uint64_t{3'600'000U});
            CHECK(delayed.max_scheduled_per_user == 7U);
            CHECK(delayed.max_finalised_per_user == 9U);
            CHECK(parsed.findings.empty());
            CHECK(merovingian::config::is_valid(parsed.config));
        }
    }

    GIVEN("enabled written as true")
    {
        auto const parsed = parse_key(enabled_key, "true");

        THEN("it is on")
        {
            CHECK(parsed.config.server().delayed_events.enabled);
            CHECK(parsed.findings.empty());
        }
    }
}

SCENARIO("server.delayed_events.enabled refuses anything that is not a boolean", "[config][delayed-events]")
{
    GIVEN("values that are not true or false")
    {
        THEN("each is refused with a finding naming the key")
        {
            for (auto const* bad : {"", "yes", "1", "0", "TRUE", "True", "on", "2"})
            {
                INFO(bad);
                auto const parsed = parse_key(enabled_key, bad);
                REQUIRE(has_finding(parsed.findings, enabled_key));
            }
        }
    }
}

SCENARIO("server.delayed_events.max_delay_ms accepts 1000 to 2678400000 milliseconds", "[config][delayed-events]")
{
    GIVEN("values at and inside the boundaries")
    {
        THEN("each is accepted and held exactly")
        {
            for (auto const value :
                 {std::uint64_t{1'000U}, std::uint64_t{1'001U}, std::uint64_t{3'600'000U}, std::uint64_t{86'400'000U},
                  std::uint64_t{2'678'399'999U}, std::uint64_t{2'678'400'000U}})
            {
                INFO(value);
                auto const parsed = parse_key(delay_key, std::to_string(value));
                REQUIRE_FALSE(has_finding(parsed.findings, delay_key));
                REQUIRE(parsed.config.server().delayed_events.max_delay_ms == value);
                REQUIRE(merovingian::config::is_valid(parsed.config));
            }
        }
    }

    GIVEN("values outside the range, or not an unsigned integer")
    {
        THEN("each is refused with a finding naming the key")
        {
            for (auto const* bad : {"0", "1", "999", "2678400001", "4294967296", "99999999999999999999", "-1",
                                    "-86400000", "", "abc", "1.5", "1e6", "+1000", "0x3e8", "1h"})
            {
                INFO(bad);
                auto const parsed = parse_key(delay_key, bad);
                REQUIRE(has_finding(parsed.findings, delay_key));
            }
        }
    }
}

SCENARIO("the per-user delayed event counts accept 1 to 1000", "[config][delayed-events]")
{
    GIVEN("values at and inside the boundaries")
    {
        THEN("each is accepted and held exactly for both counts")
        {
            for (auto const value : {1U, 2U, 100U, 999U, 1000U})
            {
                INFO(value);
                auto const scheduled = parse_key(scheduled_key, std::to_string(value));
                REQUIRE_FALSE(has_finding(scheduled.findings, scheduled_key));
                REQUIRE(scheduled.config.server().delayed_events.max_scheduled_per_user == value);
                REQUIRE(merovingian::config::is_valid(scheduled.config));

                auto const finalised = parse_key(finalised_key, std::to_string(value));
                REQUIRE_FALSE(has_finding(finalised.findings, finalised_key));
                REQUIRE(finalised.config.server().delayed_events.max_finalised_per_user == value);
                REQUIRE(merovingian::config::is_valid(finalised.config));
            }
        }
    }

    GIVEN("values outside the range, or not an unsigned integer")
    {
        THEN("each is refused with a finding naming its own key")
        {
            for (auto const* bad : {"0", "1001", "1000000", "4294967296", "-1", "-100", "", "abc", "1.5"})
            {
                INFO(bad);
                auto const scheduled = parse_key(scheduled_key, bad);
                REQUIRE(has_finding(scheduled.findings, scheduled_key));
                REQUIRE_FALSE(has_finding(scheduled.findings, finalised_key));

                auto const finalised = parse_key(finalised_key, bad);
                REQUIRE(has_finding(finalised.findings, finalised_key));
                REQUIRE_FALSE(has_finding(finalised.findings, scheduled_key));
            }
        }
    }
}

SCENARIO("server.delayed_events.* changes are diffed by the reload plan and need a restart", "[config][delayed-events]")
{
    GIVEN("two configurations that differ in every delayed-events key")
    {
        auto const before = merovingian::config::parse_key_value_config("");
        auto const after = merovingian::config::parse_key_value_config(all_non_default);

        WHEN("a reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);

            THEN("each key is named and the plan needs a restart")
            {
                CHECK(reported_in_plan(plan, enabled_key));
                CHECK(reported_in_plan(plan, delay_key));
                CHECK(reported_in_plan(plan, scheduled_key));
                CHECK(reported_in_plan(plan, finalised_key));
                CHECK(plan.has_restart_required_changes());
            }

            THEN("the policy classifies each key restart-required")
            {
                for (auto const key : {enabled_key, delay_key, scheduled_key, finalised_key})
                {
                    INFO(key);
                    CHECK(merovingian::config::reload_policy_for_key(key) ==
                          merovingian::config::ReloadPolicy::restart_required);
                }
            }
        }
    }

    GIVEN("two configurations that differ in one key only")
    {
        auto const before = merovingian::config::parse_key_value_config("");

        THEN("the plan names exactly that key")
        {
            for (auto const key : {enabled_key, delay_key, scheduled_key, finalised_key})
            {
                INFO(key);
                auto const after = parse_key(key, key == enabled_key ? "false" : "5000");
                auto const plan = merovingian::config::build_reload_plan(before.config, after.config);
                REQUIRE(plan.changes().size() == 1U);
                REQUIRE(reported_in_plan(plan, key));
            }
        }
    }
}
