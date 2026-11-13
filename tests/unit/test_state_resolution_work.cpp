// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One state resolution must read each event's auth_events a bounded number of times: the work grows with
// the distinct events a resolution reaches, not with the state size times the depth of the auth chain.
// Each scenario builds K state events that all cite one chain of D events and asserts on
// StateResolutionResult::auth_walk_visits, a count of work, never on wall-clock time. ADR-0599.
// The iterative auth checks must copy and index each distinct auth event once, however many events they judge
// against it: StateResolutionResult::auth_events_prepared counts them. ADR-0693.
//
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions ("Auth chain", "Auth difference",
// "Mainline ordering"), Algorithm step 1.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/events/StateEventReference.hpp"
#include "merovingian/events/StateGroup.hpp"
#include "merovingian/events/StateKey.hpp"
#include "merovingian/events/StateResolution.hpp"
#include "merovingian/events/StateResolutionLimits.hpp"
#include "merovingian/events/StateResolutionRequest.hpp"
#include "merovingian/events/StateResolutionResult.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

using merovingian::events::StateEventReference;
using merovingian::events::StateGroup;
using merovingian::events::StateKey;
using merovingian::events::StateResolutionLimits;
using merovingian::events::StateResolutionRequest;
using merovingian::events::StateResolutionResult;

auto const alice = std::string{"@alice:example.org"};
auto const power_content = std::string{
    R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,"users":{"@alice:example.org":100}})"};

[[nodiscard]] auto make_ref(std::string const& event_type, std::string const& state_key, std::string const& event_id,
                            std::int64_t ts, std::vector<std::string> const& auth_ids, std::string const& content_json,
                            std::string const& sender = alice) -> StateEventReference
{
    auto auth = std::string{"["};
    for (auto const& id : auth_ids)
    {
        if (auth.size() > 1U)
        {
            auth += ",";
        }
        auth += "\"" + id + "\"";
    }
    auth += "]";
    auto const json = std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key +
                      "\",\"sender\":\"" + sender + "\",\"event_id\":\"" + event_id +
                      "\",\"origin_server_ts\":" + std::to_string(ts) + ",\"auth_events\":" + auth +
                      ",\"prev_events\":[],\"content\":" + content_json + "}";
    auto ref = StateEventReference{};
    ref.key = StateKey{event_type, state_key};
    ref.event_id = event_id;
    ref.sender = sender;
    ref.origin_server_ts = ts;
    ref.depth = 1U;
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    ref.event_json = std::move(parsed.value);
    return ref;
}

// The events a resolution may fetch beyond the submitted groups.
class EventDag final
{
public:
    auto add(StateEventReference ref) -> StateEventReference
    {
        events_.insert_or_assign(ref.event_id, ref);
        return ref;
    }

    [[nodiscard]] auto lookup() const -> merovingian::events::EventLookupFn
    {
        return [this](std::string_view event_id) -> std::optional<StateEventReference> {
            auto const it = events_.find(std::string{event_id});
            if (it == events_.end())
            {
                return std::nullopt;
            }
            return it->second;
        };
    }

private:
    std::unordered_map<std::string, StateEventReference> events_{};
};

// A room with a create event, one power_levels event and Alice's join.
struct Room final
{
    EventDag dag{};
    StateEventReference create{};
    StateEventReference power{};
    StateEventReference join{};
};

[[nodiscard]] auto make_room() -> Room
{
    auto room = Room{};
    room.create = room.dag.add(make_ref("m.room.create", "", "$create", 1, {}, R"({"creator":"@alice:example.org"})"));
    room.join = room.dag.add(make_ref("m.room.member", alice, "$join", 2, {"$create"}, R"({"membership":"join"})"));
    room.power = room.dag.add(make_ref("m.room.power_levels", "", "$power", 3, {"$create", "$join"}, power_content));
    return room;
}

[[nodiscard]] auto chain_id(std::string const& prefix, std::size_t index) -> std::string
{
    return "$" + prefix + "_" + std::to_string(index);
}

// A chain of `length` events of `event_type`, each citing the one before; the first cites `first_auth`.
auto add_chain(EventDag& dag, std::string const& prefix, std::string const& event_type, std::size_t length,
               std::vector<std::string> const& first_auth, std::string const& content_json) -> void
{
    for (std::size_t index = 1U; index <= length; ++index)
    {
        auto auth = index == 1U ? first_auth : std::vector<std::string>{"$create", chain_id(prefix, index - 1U)};
        std::ignore = dag.add(make_ref(event_type, "", chain_id(prefix, index), static_cast<std::int64_t>(100U + index),
                                       auth, content_json));
    }
}

[[nodiscard]] auto resolve(Room const& room, std::vector<StateGroup> groups, StateResolutionLimits const& limits = {})
    -> StateResolutionResult
{
    auto const* policy = merovingian::rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto request = StateResolutionRequest{};
    request.room_version = "10";
    request.state_groups = std::move(groups);
    request.event_lookup = room.dag.lookup();
    request.limits = limits;
    return merovingian::events::resolve_state_v2(request, *policy);
}

[[nodiscard]] auto event_at(StateResolutionResult const& result, std::string const& event_type,
                            std::string const& state_key) -> std::string
{
    for (auto const& event : result.resolved_state)
    {
        if (event.key.event_type == event_type && event.key.state_key == state_key)
        {
            return event.event_id;
        }
    }
    return {};
}

constexpr auto state_size = std::size_t{96U};
constexpr auto chain_depth = std::size_t{96U};
// Each path reads an event a small constant number of times. A resolution that walks the chain again
// for each state event reads state_size * chain_depth, 9216 events at least.
constexpr auto visit_bound = 8U * (state_size + chain_depth);

} // namespace

SCENARIO("One resolution reads a shared auth chain once for the auth difference", "[state_res_v2][auth_chain_work]")
{
    GIVEN("two groups that share many state events citing one deep chain, and one conflicted topic")
    {
        auto room = make_room();
        add_chain(room.dag, "chain", "x.chain", chain_depth, {"$create", "$power", "$join"}, "{}");
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join};
        for (std::size_t index = 0U; index < state_size; ++index)
        {
            base.push_back(room.dag.add(make_ref("x.filler", std::to_string(index), "$filler_" + std::to_string(index),
                                                 1000, {chain_id("chain", chain_depth)}, "{}")));
        }
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        group_a.state.push_back(room.dag.add(
            make_ref("m.room.topic", "", "$topic_a", 2000, {"$create", "$power", "$join"}, R"({"topic":"a"})")));
        group_b.state.push_back(room.dag.add(
            make_ref("m.room.topic", "", "$topic_b", 2001, {"$create", "$power", "$join"}, R"({"topic":"b"})")));

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {group_a, group_b});

            THEN("the later topic wins and the walk read each event a bounded number of times")
            {
                REQUIRE(result.resolved);
                REQUIRE(event_at(result, "m.room.topic", "") == "$topic_b");
                REQUIRE(result.auth_walk_visits <= visit_bound);
            }
        }
    }
}

SCENARIO("One resolution reads a side power_levels chain once for the mainline positions",
         "[state_res_v2][auth_chain_work]")
{
    GIVEN("many conflicted events citing a chain of power_levels events that is off the mainline")
    {
        auto room = make_room();
        add_chain(room.dag, "side", "m.room.power_levels", chain_depth, {"$create", "$power", "$join"}, power_content);
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join};
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        auto const top = chain_id("side", chain_depth);
        for (std::size_t index = 0U; index < state_size; ++index)
        {
            auto const key = std::to_string(index);
            group_a.state.push_back(room.dag.add(
                make_ref("x.value", key, "$a_" + key, 1000, {"$create", top, "$join"}, R"({"value":"a"})")));
            group_b.state.push_back(room.dag.add(
                make_ref("x.value", key, "$b_" + key, 1001, {"$create", top, "$join"}, R"({"value":"b"})")));
        }

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {group_a, group_b});

            THEN("the positions are the same as a full walk's and the chain was read a bounded number of times")
            {
                REQUIRE(result.resolved);
                REQUIRE(event_at(result, "m.room.power_levels", "") == "$power");
                REQUIRE(event_at(result, "x.value", "0") == "$b_0");
                REQUIRE(result.auth_walk_visits <= visit_bound);
            }
        }
    }
}

SCENARIO("One resolution reads a shared auth chain once while enlarging the power events",
         "[state_res_v2][auth_chain_work]")
{
    GIVEN("many conflicted power events citing one deep chain")
    {
        auto room = make_room();
        add_chain(room.dag, "chain", "x.chain", chain_depth, {"$create", "$power", "$join"}, "{}");
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join};
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        auto const top = chain_id("chain", chain_depth);
        for (std::size_t index = 0U; index < state_size; ++index)
        {
            auto const user = "@user" + std::to_string(index) + ":example.org";
            group_a.state.push_back(
                room.dag.add(make_ref("m.room.member", user, "$kick_" + std::to_string(index), 1000,
                                      {"$create", "$power", "$join", top}, R"({"membership":"leave"})")));
            group_b.state.push_back(
                room.dag.add(make_ref("m.room.member", user, "$ban_" + std::to_string(index), 1001,
                                      {"$create", "$power", "$join", top}, R"({"membership":"ban"})")));
        }

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {group_a, group_b});

            THEN("the enlarging read the chain a bounded number of times")
            {
                REQUIRE(result.resolved);
                REQUIRE(result.auth_walk_visits <= visit_bound);
            }
        }
    }
}

SCENARIO("The auth chain cap still refuses exactly when one group's chain exceeds it",
         "[state_res_v2][auth_chain_work][boundary]")
{
    GIVEN("a conflicted topic citing a chain of 8 events that reach no other event")
    {
        auto room = make_room();
        add_chain(room.dag, "chain", "x.chain", 8U, {}, "{}");
        auto base = std::vector<StateEventReference>{};
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        group_a.state.push_back(room.dag.add(make_ref("m.room.topic", "", "$topic_a", 2000, {}, R"({"topic":"a"})")));
        group_b.state.push_back(
            room.dag.add(make_ref("m.room.topic", "", "$topic_b", 2001, {chain_id("chain", 8U)}, R"({"topic":"b"})")));
        // Every chain event but the first also cites $create, so the chain holds 9 distinct events.
        auto limits = StateResolutionLimits{};

        WHEN("the cap equals the chain's size")
        {
            limits.max_auth_chain_walk_events = 9U;
            auto const result = resolve(room, {group_a, group_b}, limits);

            THEN("the walk completes")
            {
                REQUIRE(result.resolved);
            }
        }

        WHEN("the cap is one below the chain's size")
        {
            limits.max_auth_chain_walk_events = 8U;
            auto const result = resolve(room, {group_a, group_b}, limits);

            THEN("the resolution is refused")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "state-res v2: missing or unreachable event during auth-chain walk");
            }
        }
    }
}

SCENARIO("A missing auth chain event still refuses the resolution", "[state_res_v2][auth_chain_work][fail-closed]")
{
    GIVEN("a conflicted topic citing an event no lookup can find")
    {
        auto room = make_room();
        auto group_a = StateGroup{
            "a", {room.dag.add(make_ref("m.room.topic", "", "$topic_a", 2000, {"$absent"}, R"({"topic":"a"})"))}};
        auto group_b =
            StateGroup{"b", {room.dag.add(make_ref("m.room.topic", "", "$topic_b", 2001, {}, R"({"topic":"b"})"))}};

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {group_a, group_b});

            THEN("resolution fails closed")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "state-res v2: missing or unreachable event during auth-chain walk");
            }
        }
    }
}

SCENARIO("An event reached by some groups but not all is in the auth difference", "[state_res_v2][auth_chain_work]")
{
    GIVEN("a promotion in the auth chains of two groups of three, and a ban only that promotion authorises")
    {
        auto const bob = std::string{"@bob:example.org"};
        auto const charlie = std::string{"@charlie:example.org"};
        auto room = make_room();
        auto const rules = room.dag.add(
            make_ref("m.room.join_rules", "", "$rules", 20, {"$create", "$power"}, R"({"join_rule":"public"})"));
        auto const bob_join = room.dag.add(
            make_ref("m.room.member", bob, "$bob_join", 40, {"$create", "$rules"}, R"({"membership":"join"})", bob));
        auto const charlie_join = room.dag.add(make_ref("m.room.member", charlie, "$charlie_join", 50,
                                                        {"$create", "$rules"}, R"({"membership":"join"})", charlie));
        std::ignore = room.dag.add(make_ref(
            "m.room.power_levels", "", "$promotion", 15, {"$create", "$power", "$join"},
            R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,"users":{"@alice:example.org":100,"@bob:example.org":100}})"));
        auto const ban = room.dag.add(make_ref("m.room.member", charlie, "$ban", 1000,
                                               {"$create", "$promotion", "$bob_join", "$charlie_join"},
                                               R"({"membership":"ban"})", bob));
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join, rules, bob_join};
        auto with_ban = StateGroup{"with-ban", base};
        with_ban.state.push_back(ban);
        auto also_with_ban = StateGroup{"also-with-ban", with_ban.state};
        auto without_ban = StateGroup{"without-ban", base};
        without_ban.state.push_back(charlie_join);

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {with_ban, also_with_ban, without_ban});

            THEN("the promotion joined the conflicted set, so the ban it authorises wins")
            {
                REQUIRE(result.resolved);
                REQUIRE(event_at(result, "m.room.member", charlie) == "$ban");
            }
        }
    }
}

SCENARIO("The mainline depth cap counts every hop an event's position needs",
         "[state_res_v2][auth_chain_work][boundary]")
{
    GIVEN("two conflicted values citing a side power_levels chain of 4 events off a mainline of one event")
    {
        auto room = make_room();
        add_chain(room.dag, "side", "m.room.power_levels", 4U, {"$create", "$power", "$join"}, power_content);
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join};
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        auto const top = chain_id("side", 4U);
        // The shorter walk runs first and fills in the positions the longer walk then reuses, so a memo
        // that forgot how far it had come would let the longer walk through.
        group_a.state.push_back(room.dag.add(
            make_ref("x.value", "k", "$a", 1000, {"$create", chain_id("side", 1U), "$join"}, R"({"value":"a"})")));
        group_b.state.push_back(
            room.dag.add(make_ref("x.value", "k", "$z", 1001, {"$create", top, "$join"}, R"({"value":"b"})")));
        group_a.state.push_back(
            room.dag.add(make_ref("x.anchor", "", "$anchor_a", 1002, {"$create", top, "$join"}, "{}")));
        group_b.state.push_back(room.dag.add(
            make_ref("x.anchor", "", "$anchor_b", 1003, {"$create", chain_id("side", 1U), "$join"}, "{}")));
        auto limits = StateResolutionLimits{};

        WHEN("the depth cap equals the longest walk's reads")
        {
            limits.max_mainline_auth_chain_depth = 5U;
            auto const result = resolve(room, {group_a, group_b}, limits);

            THEN("the positions are found")
            {
                REQUIRE(result.resolved);
            }
        }

        WHEN("the depth cap is one below the longest walk's reads")
        {
            limits.max_mainline_auth_chain_depth = 4U;
            auto const result = resolve(room, {group_a, group_b}, limits);

            THEN("the resolution is refused")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE(result.reason == "state-res v2: mainline ordering auth-chain walk failed");
            }
        }
    }
}

namespace
{

// A power_levels content naming Alice at 100 and `members` other users at 50, less the member numbered `omit`.
[[nodiscard]] auto large_power_content(std::size_t members, std::optional<std::size_t> omit = std::nullopt)
    -> std::string
{
    auto content = std::string{
        R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,"users":{"@alice:example.org":100)"};
    for (std::size_t index = 0U; index < members; ++index)
    {
        if (omit.has_value() && *omit == index)
        {
            continue;
        }
        content += R"(,"@member)" + std::to_string(index) + R"(:example.org":50)";
    }
    return content + "}}";
}

// A room whose power_levels event lists `members` users besides Alice.
[[nodiscard]] auto make_room_with_large_power(std::size_t members) -> Room
{
    auto room = Room{};
    room.create = room.dag.add(make_ref("m.room.create", "", "$create", 1, {}, R"({"creator":"@alice:example.org"})"));
    room.join = room.dag.add(make_ref("m.room.member", alice, "$join", 2, {"$create"}, R"({"membership":"join"})"));
    room.power = room.dag.add(
        make_ref("m.room.power_levels", "", "$power", 3, {"$create", "$join"}, large_power_content(members)));
    return room;
}

constexpr auto power_members = std::size_t{1000U};
constexpr auto conflicted_keys = std::size_t{200U};

} // namespace

SCENARIO("The iterative auth checks read each auth event once, however many events they judge",
         "[state_res_v2][auth_event_work]")
{
    GIVEN("a room whose power_levels event lists many users, and two groups conflicting on many keys")
    {
        auto room = make_room_with_large_power(power_members);
        auto base = std::vector<StateEventReference>{room.create, room.power, room.join};
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};
        for (std::size_t index = 0U; index < conflicted_keys; ++index)
        {
            auto const key = std::to_string(index);
            group_a.state.push_back(room.dag.add(
                make_ref("x.custom", key, "$a_" + key, 1000, {"$create", "$power", "$join"}, R"({"value":"a"})")));
            group_b.state.push_back(room.dag.add(
                make_ref("x.custom", key, "$b_" + key, 1001, {"$create", "$power", "$join"}, R"({"value":"b"})")));
        }

        WHEN("the groups are resolved")
        {
            auto const result = resolve(room, {group_a, group_b});

            THEN("every key resolves as before, and only the create, power_levels and member events were read")
            {
                REQUIRE(result.resolved);
                for (std::size_t index = 0U; index < conflicted_keys; ++index)
                {
                    REQUIRE(event_at(result, "x.custom", std::to_string(index)) == "$b_" + std::to_string(index));
                }
                REQUIRE(event_at(result, "m.room.power_levels", "") == "$power");
                REQUIRE(result.auth_events_prepared == 3U);
            }
        }
    }
}

SCENARIO("Conflicting power_levels events with many users are judged by the auth rules as before",
         "[state_res_v2][auth_event_work]")
{
    GIVEN("a room whose power_levels event lists many users")
    {
        auto room = make_room_with_large_power(power_members);
        // Each fork holds its own power_levels event; both cite the room's first one, which the checks reach
        // through each event's own auth_events.
        auto base = std::vector<StateEventReference>{room.create, room.join};
        auto member_join = [&room](std::size_t index) {
            auto const user = "@member" + std::to_string(index) + ":example.org";
            return room.dag.add(make_ref("m.room.member", user, "$member_join_" + std::to_string(index), 4,
                                         {"$create", "$power"}, R"({"membership":"join"})", user));
        };
        base.push_back(member_join(1U));
        auto group_a = StateGroup{"a", base};
        auto group_b = StateGroup{"b", base};

        WHEN("Alice removes one user and a member at 50 removes another at 50 in a later fork")
        {
            group_a.state.push_back(
                room.dag.add(make_ref("m.room.power_levels", "", "$power_alice", 1000, {"$create", "$power", "$join"},
                                      large_power_content(power_members, 0U))));
            group_b.state.push_back(room.dag.add(
                make_ref("m.room.power_levels", "", "$power_member", 1001, {"$create", "$power", "$member_join_1"},
                         large_power_content(power_members, 2U), "@member1:example.org")));
            auto const result = resolve(room, {group_a, group_b});

            THEN("Alice's change stands and the member's removal of an equal is refused (rule 9.8)")
            {
                REQUIRE(result.resolved);
                REQUIRE(event_at(result, "m.room.power_levels", "") == "$power_alice");
                REQUIRE(result.auth_events_prepared <= 6U);
            }
        }
    }
}
