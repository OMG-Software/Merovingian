// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/events/state_resolution.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("State groups expose state events by type and state key", "[events][state]")
{
    GIVEN("a state group with create and power-level events")
    {
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const group = merovingian::events::StateGroup{
            "group-1",
            {
                {create_key, "$create", "@server:example.org"},
                {power_key, "$power", "@alice:example.org"},
            },
        };

        WHEN("state lookups are performed")
        {
            auto const contains_create = merovingian::events::state_group_contains(group, create_key);
            auto const* power_event = merovingian::events::state_group_event(group, power_key);

            THEN("matching state keys find their events")
            {
                REQUIRE(contains_create);
                REQUIRE(power_event != nullptr);
                REQUIRE(power_event->event_id == "$power");
            }
        }
    }
}

SCENARIO("State resolution merges non-conflicting state groups", "[events][state][resolution]")
{
    GIVEN("two state groups with compatible state")
    {
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const first = merovingian::events::StateGroup{
            "group-1",
            {{create_key, "$create", "@server:example.org"}},
        };
        auto const second = merovingian::events::StateGroup{
            "group-2",
            {{create_key, "$create", "@server:example.org"}, {power_key, "$power", "@alice:example.org"}},
        };
        auto const request = merovingian::events::StateResolutionRequest{"12", {first, second}};

        WHEN("state is resolved")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("the unique state map is produced")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.resolved_state.size() == 2U);
                REQUIRE(result.reason.empty());
            }
        }
    }
}

SCENARIO("State resolution reports conflicts for later full resolution", "[events][state][resolution]")
{
    GIVEN("two state groups with conflicting power-level events")
    {
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const first = merovingian::events::StateGroup{
            "group-1",
            {{power_key, "$power-a", "@alice:example.org"}},
        };
        auto const second = merovingian::events::StateGroup{
            "group-2",
            {{power_key, "$power-b", "@bob:example.org"}},
        };
        auto const request = merovingian::events::StateResolutionRequest{"12", {first, second}};

        WHEN("state is resolved")
        {
            auto const result = merovingian::events::resolve_state(request);
            auto const summary = merovingian::events::state_resolution_summary(result);

            THEN("the scaffold fails closed with a conflict reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "conflicting state requires full resolution");
                REQUIRE(summary.find("resolved=false") != std::string::npos);
            }
        }
    }
}

SCENARIO("State resolution rejects missing event IDs", "[events][state][resolution]")
{
    GIVEN("a state group containing an empty event ID")
    {
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const group = merovingian::events::StateGroup{
            "group-1",
            {{create_key, "", "@server:example.org"}},
        };
        auto const request = merovingian::events::StateResolutionRequest{"12", {group}};

        WHEN("state is resolved")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("the malformed state group is rejected")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "state event id is required");
            }
        }
    }
}
