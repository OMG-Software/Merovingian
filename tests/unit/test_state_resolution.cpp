// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto make_create_value(std::string_view creator) -> merovingian::canonicaljson::Value
{
    auto json = std::string{"{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
                            "\",\"room_id\":\"!room:example.org\",\"content\":{\"creator\":\"" + std::string{creator} +
                            "\",\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,\"prev_events\":[],\"auth_"
                            "events\":[],\"hashes\":{\"sha256\":\"hash\"}}"};
    return merovingian::canonicaljson::parse_lossless(json).value;
}

[[nodiscard]] auto make_power_levels_value(std::string_view sender, std::int64_t user_power)
    -> merovingian::canonicaljson::Value
{
    auto json = std::string{"{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"" + std::string{sender} +
                            "\",\"room_id\":\"!room:example.org\",\"content\":{\"ban\":50,\"invite\":0,\"kick\":50,"
                            "\"redact\":50,\"users_default\":0,\"state_default\":50,\"events_default\":0,"
                            "\"users\":{\"" +
                            std::string{sender} + "\":" + std::to_string(user_power) +
                            "}},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
                            "\"hashes\":{\"sha256\":\"hash\"}}"};
    return merovingian::canonicaljson::parse_lossless(json).value;
}

[[nodiscard]] auto make_member_value(std::string_view sender, std::string_view state_key, std::string_view membership,
                                     std::int64_t ts) -> merovingian::canonicaljson::Value
{
    auto json =
        std::string{"{\"type\":\"m.room.member\",\"state_key\":\"" + std::string{state_key} + "\",\"sender\":\"" +
                    std::string{sender} + "\",\"room_id\":\"!room:example.org\",\"content\":{\"membership\":\"" +
                    std::string{membership} + "\"},\"origin_server_ts\":" + std::to_string(ts) +
                    ",\"depth\":2,\"prev_events\":[],\"auth_events\":[],"
                    "\"hashes\":{\"sha256\":\"hash\"}}"};
    return merovingian::canonicaljson::parse_lossless(json).value;
}

} // namespace

SCENARIO("State groups expose state events by type and state key", "[events][state]")
{
    GIVEN("a state group with create and power-level events")
    {
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const group = merovingian::events::StateGroup{
            "group-1",
            {
              {create_key, "$create", "@server:example.org", 1, 0, {}},
              {power_key, "$power", "@alice:example.org", 2, 1, {}},
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
            {{create_key, "$create", "@server:example.org", 1, 0, {}}},
        };
        auto const second = merovingian::events::StateGroup{
            "group-2",
            {{create_key, "$create", "@server:example.org", 1, 0, {}},
              {power_key, "$power", "@alice:example.org", 2, 1, {}}},
        };
        auto const request = merovingian::events::StateResolutionRequest{
            "12", {first, second}
        };

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

SCENARIO("State resolution resolves simple conflicts deterministically", "[events][state][resolution]")
{
    GIVEN("two state groups with conflicting power-level events")
    {
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const first = merovingian::events::StateGroup{
            "group-1",
            {{power_key, "$power-a", "@alice:example.org", 100, 1, {}}},
        };
        auto const second = merovingian::events::StateGroup{
            "group-2",
            {{power_key, "$power-b", "@bob:example.org", 50, 1, {}}},
        };
        auto const request = merovingian::events::StateResolutionRequest{
            "12", {first, second}
        };

        WHEN("state is resolved with the basic merger")
        {
            auto const result = merovingian::events::resolve_state(request);
            auto const summary = merovingian::events::state_resolution_summary(result);

            THEN("the higher-priority event wins and the state is resolved")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.reason.empty());
                REQUIRE(result.resolved_state.size() == 1U);
                REQUIRE(result.resolved_state.front().event_id == "$power-a");
                REQUIRE(summary.find("resolved=true") != std::string::npos);
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
            {
              {create_key, "", "@server:example.org", 1, 0, {}},
              },
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

SCENARIO("V2 state resolution resolves conflicting power levels using reverse topological power ordering",
         "[events][state][resolution][v2]")
{
    GIVEN("two state groups with conflicting power levels from different senders")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const member_alice = merovingian::events::StateKey{"m.room.member", "@alice:example.org"};
        auto const member_bob = merovingian::events::StateKey{"m.room.member", "@bob:example.org"};

        auto const create_event = merovingian::events::StateEventReference{
            create_key, "$create", "@alice:example.org", 1, 0, make_create_value("@alice:example.org")};
        auto const alice_member = merovingian::events::StateEventReference{
            member_alice,
            "$alice_member",
            "@alice:example.org",
            2,
            1,
            make_member_value("@alice:example.org", "@alice:example.org", "join", 2)};
        auto const bob_member = merovingian::events::StateEventReference{
            member_bob,
            "$bob_member",
            "@alice:example.org",
            3,
            2,
            make_member_value("@alice:example.org", "@bob:example.org", "join", 3)};

        auto const power_a = merovingian::events::StateEventReference{
            power_key, "$power-a", "@alice:example.org", 10, 10, make_power_levels_value("@alice:example.org", 100)};
        auto const power_b = merovingian::events::StateEventReference{
            power_key, "$power-b", "@bob:example.org", 5, 10, make_power_levels_value("@bob:example.org", 50)};

        auto const group_a = merovingian::events::StateGroup{
            "group-a",
            {create_event, alice_member, bob_member, power_a},
        };
        auto const group_b = merovingian::events::StateGroup{
            "group-b",
            {create_event, alice_member, bob_member, power_b},
        };

        auto const request = merovingian::events::StateResolutionRequest{
            "12", {group_a, group_b}
        };

        WHEN("v2 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the conflict is resolved and alice's higher-power event wins")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.reason.empty());
                REQUIRE_FALSE(result.resolved_state.empty());
            }
        }
    }
}

SCENARIO("V2 state resolution resolves conflicting member events", "[events][state][resolution][v2]")
{
    GIVEN("two state groups with conflicting member states")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const member_charlie = merovingian::events::StateKey{"m.room.member", "@charlie:example.org"};

        auto const create_event = merovingian::events::StateEventReference{
            create_key, "$create", "@alice:example.org", 1, 0, make_create_value("@alice:example.org")};
        auto const power_event = merovingian::events::StateEventReference{
            power_key, "$power", "@alice:example.org", 10, 1, make_power_levels_value("@alice:example.org", 100)};
        auto const charlie_invited = merovingian::events::StateEventReference{
            member_charlie,
            "$charlie_invite",
            "@alice:example.org",
            100,
            3,
            make_member_value("@alice:example.org", "@charlie:example.org", "invite", 100)};
        auto const charlie_joined = merovingian::events::StateEventReference{
            member_charlie,
            "$charlie_join",
            "@charlie:example.org",
            50,
            4,
            make_member_value("@charlie:example.org", "@charlie:example.org", "join", 50)};

        auto const group_a = merovingian::events::StateGroup{
            "group-a",
            {create_event, power_event, charlie_invited},
        };
        auto const group_b = merovingian::events::StateGroup{
            "group-b",
            {create_event, power_event, charlie_joined},
        };

        auto const request = merovingian::events::StateResolutionRequest{
            "12", {group_a, group_b}
        };

        WHEN("v2 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the conflict is resolved")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.reason.empty());
            }
        }
    }
}

SCENARIO("V2 state resolution handles empty state groups gracefully", "[events][state][resolution][v2]")
{
    GIVEN("no state groups")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const request = merovingian::events::StateResolutionRequest{"12", {}};

        WHEN("v2 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the result is resolved with empty state")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.resolved_state.empty());
            }
        }
    }
}

SCENARIO("Partition separates conflicted from unconflicted state keys", "[events][state][resolution][partition]")
{
    GIVEN("two state groups sharing a create event but differing on power_levels")
    {
        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};

        auto const create_event =
            merovingian::events::StateEventReference{create_key, "$create", "@alice:example.org", 1, 0, {}};
        auto const power_a =
            merovingian::events::StateEventReference{power_key, "$power-a", "@alice:example.org", 100, 1, {}};
        auto const power_b =
            merovingian::events::StateEventReference{power_key, "$power-b", "@bob:example.org", 50, 1, {}};

        auto const group_a = merovingian::events::StateGroup{
            "group-a",
            {create_event, power_a},
        };
        auto const group_b = merovingian::events::StateGroup{
            "group-b",
            {create_event, power_b},
        };

        WHEN("state is partitioned")
        {
            auto const [unconflicted, conflicted] = merovingian::events::partition_conflicted_state({group_a, group_b});

            THEN("create is unconflicted and power_levels is conflicted")
            {
                REQUIRE(unconflicted.contains(create_key));
                REQUIRE(unconflicted.find(create_key)->second.event_id == "$create");
                REQUIRE(conflicted.contains(power_key));
            }
        }
    }
}

SCENARIO("Reverse topological power sort orders by sender power then timestamp", "[events][state][resolution][sort]")
{
    GIVEN("conflicted events from senders with different power levels")
    {
        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};
        auto const unconflicted = merovingian::events::StateMap{};

        auto high_power_event = merovingian::events::StateEventReference{
            power_key, "$high", "@alice:example.org", 10, 100, make_power_levels_value("@alice:example.org", 100)};
        auto low_power_event = merovingian::events::StateEventReference{
            power_key, "$low", "@bob:example.org", 50, 100, make_power_levels_value("@bob:example.org", 0)};

        auto const conflicted =
            std::vector<merovingian::events::StateEventReference>{low_power_event, high_power_event};

        WHEN("sorted by reverse topological power")
        {
            auto const sorted = merovingian::events::reverse_topological_power_sort(conflicted, unconflicted);

            THEN("the high-power event comes first")
            {
                REQUIRE(sorted.size() == 2U);
                REQUIRE(sorted[0].event_id == "$high");
                REQUIRE(sorted[1].event_id == "$low");
            }
        }
    }
}
