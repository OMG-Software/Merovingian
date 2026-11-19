// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.sticky_events.*: the operator's switch and the per-sender and per-room caps for sticky events (MSC4354;
// ADR-0854, ADR-0857). The proposal is not in Matrix v1.19, so these are project-level checks of parsing, validation
// and reload classification.

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/config/StickyEventsConfig.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
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

constexpr auto enabled_key = std::string_view{"server.sticky_events.enabled"};
constexpr auto cap_key = std::string_view{"server.sticky_events.max_per_sender"};
constexpr auto room_cap_key = std::string_view{"server.sticky_events.max_per_room"};

constexpr auto all_non_default = std::string_view{"server.sticky_events.enabled=false\n"
                                                  "server.sticky_events.max_per_sender=7\n"
                                                  "server.sticky_events.max_per_room=9\n"};

} // namespace

SCENARIO("server.sticky_events.* default to on with 60 events per sender and 1000 per room", "[config][sticky-events]")
{
    GIVEN("a configuration that does not mention the section")
    {
        WHEN("it is parsed")
        {
            auto const parsed = merovingian::config::parse_key_value_config("");

            THEN("sticky events are enabled with the documented cap and nothing is reported")
            {
                auto const& sticky = parsed.config.server().sticky_events;
                CHECK(sticky.enabled);
                CHECK(sticky.max_per_sender == 60U);
                CHECK(sticky.max_per_room == 1000U);
                CHECK(parsed.findings.empty());
                CHECK(merovingian::config::is_valid(parsed.config));
            }
        }
    }
}

SCENARIO("each server.sticky_events.* key is parsed", "[config][sticky-events]")
{
    GIVEN("a configuration that sets every key to a non-default value")
    {
        WHEN("it is parsed")
        {
            auto const parsed = merovingian::config::parse_key_value_config(all_non_default);

            THEN("the values are held and the configuration is valid")
            {
                auto const& sticky = parsed.config.server().sticky_events;
                CHECK_FALSE(sticky.enabled);
                CHECK(sticky.max_per_sender == 7U);
                CHECK(sticky.max_per_room == 9U);
                CHECK(parsed.findings.empty());
                CHECK(merovingian::config::is_valid(parsed.config));
            }
        }
    }

    GIVEN("enabled written as true")
    {
        WHEN("it is parsed")
        {
            auto const parsed = parse_key(enabled_key, "true");

            THEN("it is on")
            {
                CHECK(parsed.config.server().sticky_events.enabled);
                CHECK(parsed.findings.empty());
            }
        }
    }
}

SCENARIO("server.sticky_events.enabled refuses anything that is not a boolean", "[config][sticky-events]")
{
    GIVEN("values that are not true or false")
    {
        auto const values = std::vector<std::string>{"", "yes", "1", "0", "TRUE", "True", "on", "2"};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const& bad : values)
            {
                parsed.push_back(parse_key(enabled_key, bad));
            }

            THEN("each is refused with a finding naming the key")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE(has_finding(parsed[index].findings, enabled_key));
                }
            }
        }
    }
}

SCENARIO("server.sticky_events.max_per_sender accepts 1 to 1000", "[config][sticky-events]")
{
    GIVEN("values at and inside the boundaries")
    {
        auto const values = std::vector<unsigned>{1U, 2U, 60U, 999U, 1000U};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const value : values)
            {
                parsed.push_back(parse_key(cap_key, std::to_string(value)));
            }

            THEN("each is accepted and held exactly")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE_FALSE(has_finding(parsed[index].findings, cap_key));
                    REQUIRE(parsed[index].config.server().sticky_events.max_per_sender == values[index]);
                    REQUIRE(merovingian::config::is_valid(parsed[index].config));
                }
            }
        }
    }

    GIVEN("values outside the range, or not an unsigned integer")
    {
        auto const values =
            std::vector<std::string>{"0", "1001", "1000000", "4294967296", "-1", "-60", "", "abc", "1.5", "+60", "1e2"};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const& bad : values)
            {
                parsed.push_back(parse_key(cap_key, bad));
            }

            THEN("each is refused with a finding naming the key, and the other key is not blamed")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE(has_finding(parsed[index].findings, cap_key));
                    REQUIRE_FALSE(has_finding(parsed[index].findings, enabled_key));
                }
            }
        }
    }
}

SCENARIO("server.sticky_events.max_per_room accepts 1 to 10000", "[config][sticky-events]")
{
    GIVEN("values at and inside the boundaries")
    {
        auto const values = std::vector<unsigned>{1U, 2U, 1000U, 9999U, 10'000U};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const value : values)
            {
                parsed.push_back(parse_key(room_cap_key, std::to_string(value)));
            }

            THEN("each is accepted and held exactly")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE_FALSE(has_finding(parsed[index].findings, room_cap_key));
                    REQUIRE(parsed[index].config.server().sticky_events.max_per_room == values[index]);
                    REQUIRE(merovingian::config::is_valid(parsed[index].config));
                }
            }
        }
    }

    GIVEN("values outside the range, or not an unsigned integer")
    {
        auto const values =
            std::vector<std::string>{"0", "10001", "1000000", "4294967296", "-1", "", "abc", "1.5", "+60"};

        WHEN("each is parsed")
        {
            auto parsed = std::vector<merovingian::config::ConfigParseResult>{};
            for (auto const& bad : values)
            {
                parsed.push_back(parse_key(room_cap_key, bad));
            }

            THEN("each is refused with a finding naming the key, and the per-sender key is not blamed")
            {
                for (auto index = std::size_t{0U}; index < values.size(); ++index)
                {
                    INFO(values[index]);
                    REQUIRE(has_finding(parsed[index].findings, room_cap_key));
                    REQUIRE_FALSE(has_finding(parsed[index].findings, cap_key));
                }
            }
        }
    }
}

SCENARIO("server.sticky_events.* changes are diffed by the reload plan and need a restart", "[config][sticky-events]")
{
    GIVEN("two configurations that differ in every sticky-events key")
    {
        auto const before = merovingian::config::parse_key_value_config("");
        auto const after = merovingian::config::parse_key_value_config(all_non_default);
        auto const keys = std::vector<std::string_view>{enabled_key, cap_key, room_cap_key};

        WHEN("a reload is planned and each key is classified")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);
            auto policies = std::vector<merovingian::config::ReloadPolicy>{};
            for (auto const key : keys)
            {
                policies.push_back(merovingian::config::reload_policy_for_key(key));
            }

            THEN("each key is named and the plan needs a restart")
            {
                CHECK(reported_in_plan(plan, enabled_key));
                CHECK(reported_in_plan(plan, cap_key));
                CHECK(reported_in_plan(plan, room_cap_key));
                CHECK(plan.has_restart_required_changes());
            }

            THEN("the policy classifies each key restart-required")
            {
                for (auto index = std::size_t{0U}; index < keys.size(); ++index)
                {
                    INFO(keys[index]);
                    CHECK(policies[index] == merovingian::config::ReloadPolicy::restart_required);
                }
            }
        }
    }

    GIVEN("two configurations that differ in one key only")
    {
        auto const before = merovingian::config::parse_key_value_config("");
        auto const keys = std::vector<std::string_view>{enabled_key, cap_key, room_cap_key};

        WHEN("a reload is planned for each key")
        {
            auto plans = std::vector<merovingian::config::ReloadPlan>{};
            for (auto const key : keys)
            {
                auto const after = parse_key(key, key == enabled_key ? "false" : "5");
                plans.push_back(merovingian::config::build_reload_plan(before.config, after.config));
            }

            THEN("the plan names exactly that key")
            {
                for (auto index = std::size_t{0U}; index < keys.size(); ++index)
                {
                    INFO(keys[index]);
                    REQUIRE(plans[index].changes().size() == 1U);
                    REQUIRE(reported_in_plan(plans[index], keys[index]));
                }
            }
        }
    }
}
