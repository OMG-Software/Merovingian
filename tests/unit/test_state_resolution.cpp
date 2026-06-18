// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
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

SCENARIO("State resolution rejects too many state groups", "[events][state][resolution][limits]")
{
    GIVEN("a request with more state groups than the resource cap allows")
    {
        auto const key = merovingian::events::StateKey{"m.room.create", ""};
        auto groups = std::vector<merovingian::events::StateGroup>{};
        groups.reserve(merovingian::events::max_state_groups + 1U);
        for (std::size_t i = 0; i < merovingian::events::max_state_groups + 1U; ++i)
        {
            groups.push_back(merovingian::events::StateGroup{
                std::string{"group-"} + std::to_string(i),
                {{key, "$create", "@server:example.org", 1, 0, {}}},
            });
        }
        auto const request = merovingian::events::StateResolutionRequest{"12", std::move(groups)};

        WHEN("v1 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("it fails fast with a clear resource-limit reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "too many state groups");
            }
        }

        WHEN("v2 state resolution is applied")
        {
            auto const* policy = merovingian::rooms::find_room_version_policy("12");
            REQUIRE(policy != nullptr);
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("it fails fast with a clear resource-limit reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "too many state groups");
            }
        }
    }
}

SCENARIO("State resolution rejects an oversized state group", "[events][state][resolution][limits]")
{
    GIVEN("a single state group with more events than the per-group cap")
    {
        auto const key = merovingian::events::StateKey{"m.room.member", "@user:example.org"};
        auto state = std::vector<merovingian::events::StateEventReference>{};
        state.reserve(merovingian::events::max_events_per_state_group + 1U);
        for (std::size_t i = 0; i < merovingian::events::max_events_per_state_group + 1U; ++i)
        {
            state.push_back(merovingian::events::StateEventReference{
                key, "$event-" + std::to_string(i), "@server:example.org", static_cast<std::int64_t>(i), i, {}});
        }
        auto const request = merovingian::events::StateResolutionRequest{
            "12", {merovingian::events::StateGroup{"group-1", std::move(state)}}};

        WHEN("v1 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("it fails fast with a clear resource-limit reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "too many events in state group");
            }
        }

        WHEN("v2 state resolution is applied")
        {
            auto const* policy = merovingian::rooms::find_room_version_policy("12");
            REQUIRE(policy != nullptr);
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("it fails fast with a clear resource-limit reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "too many events in state group");
            }
        }
    }
}

SCENARIO("State resolution v2 rejects too many conflicted state keys", "[events][state][resolution][v2][limits]")
{
    GIVEN("state groups whose distinct state keys exceed the conflicted-key cap")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        // Use the maximum allowed number of groups, each small enough to pass
        // max_events_per_state_group, but with enough distinct state keys in total
        // to exceed max_conflicted_state_keys.
        auto const events_per_group = 11U;
        auto const groups_needed = merovingian::events::max_state_groups;
        auto groups = std::vector<merovingian::events::StateGroup>{};
        groups.reserve(groups_needed);

        for (std::size_t g = 0; g < groups_needed; ++g)
        {
            auto state = std::vector<merovingian::events::StateEventReference>{};
            state.reserve(events_per_group);
            for (std::size_t i = 0; i < events_per_group; ++i)
            {
                auto const key_index = g * events_per_group + i;
                state.push_back(merovingian::events::StateEventReference{
                    merovingian::events::StateKey{"m.room.member",
                                                  "@user" + std::to_string(key_index) + ":example.org"},
                    "$event-" + std::to_string(key_index),
                    "@server:example.org",
                    static_cast<std::int64_t>(key_index),
                    key_index,
                    {}
                });
            }
            groups.push_back(
                merovingian::events::StateGroup{std::string{"group-"} + std::to_string(g), std::move(state)});
        }

        WHEN("v2 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state_v2(
                merovingian::events::StateResolutionRequest{"12", std::move(groups)}, *policy);

            THEN("partitioning fails fast with a clear resource-limit reason")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "too many state keys");
            }
        }
    }
}

SCENARIO("State resolution mainline depth is bounded", "[events][state][resolution][v2][limits][mainline]")
{
    GIVEN("a power_levels event with a huge auth_events list")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        auto const power_key = merovingian::events::StateKey{"m.room.power_levels", ""};

        // Build a power_levels event whose auth_events list is well beyond the
        // mainline depth cap. It must still parse and the resolver must not hang.
        auto auth_array = merovingian::canonicaljson::Array{};
        for (std::size_t i = 0; i < merovingian::events::max_mainline_auth_chain_depth + 100U; ++i)
        {
            auth_array.push_back(merovingian::canonicaljson::Value{std::string{"$auth-"} + std::to_string(i)});
        }

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "users",
            merovingian::canonicaljson::Value{
                merovingian::canonicaljson::Object{merovingian::canonicaljson::make_member(
                    "@alice:example.org", merovingian::canonicaljson::Value{static_cast<std::int64_t>(100)})}}));

        auto power_json = merovingian::canonicaljson::Object{};
        power_json.push_back(merovingian::canonicaljson::make_member(
            "type", merovingian::canonicaljson::Value{std::string{"m.room.power_levels"}}));
        power_json.push_back(
            merovingian::canonicaljson::make_member("state_key", merovingian::canonicaljson::Value{std::string{""}}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "sender", merovingian::canonicaljson::Value{std::string{"@alice:example.org"}}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "room_id", merovingian::canonicaljson::Value{std::string{"!room:example.org"}}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "event_id", merovingian::canonicaljson::Value{std::string{"$power"}}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "origin_server_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1)}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "auth_events", merovingian::canonicaljson::Value{std::move(auth_array)}));
        power_json.push_back(
            merovingian::canonicaljson::make_member("content", merovingian::canonicaljson::Value{std::move(content)}));
        power_json.push_back(merovingian::canonicaljson::make_member(
            "depth", merovingian::canonicaljson::Value{static_cast<std::int64_t>(1)}));

        auto const serialized =
            merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{power_json});
        REQUIRE(serialized.error == merovingian::canonicaljson::CanonicalJsonError::none);
        auto const parsed = merovingian::canonicaljson::parse_lossless(serialized.output);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
        auto const create =
            merovingian::events::StateEventReference{create_key, "$create", "@server:example.org", 1, 0, {}};
        auto const power =
            merovingian::events::StateEventReference{power_key, "$power", "@alice:example.org", 1, 1, parsed.value};

        auto const request = merovingian::events::StateResolutionRequest{
            "12", {merovingian::events::StateGroup{"group-a", {create, power}}}};

        WHEN("v2 state resolution is applied")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution completes despite the oversized mainline input")
            {
                REQUIRE(result.resolved);
            }
        }
    }
}
