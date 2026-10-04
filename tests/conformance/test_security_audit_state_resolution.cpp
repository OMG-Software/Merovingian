// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

using merovingian::events::StateEventReference;
using merovingian::events::StateGroup;
using merovingian::events::StateKey;
using merovingian::events::StateResolutionRequest;

[[nodiscard]] auto make_event(std::string_view type, std::string_view state_key, std::string const& event_id,
                              std::string_view sender, std::int64_t timestamp, std::vector<std::string> const& auth_ids,
                              std::string_view content, std::string_view room_id = {},
                              std::vector<std::string> const& prev_ids = {}) -> StateEventReference
{
    auto auth_json = std::string{"["};
    for (auto const& auth_id : auth_ids)
    {
        if (auth_json.size() > 1U)
        {
            auth_json += ',';
        }
        auth_json += "\"" + auth_id + "\"";
    }
    auth_json += ']';
    auto prev_json = std::string{"["};
    for (auto const& prev_id : prev_ids)
    {
        if (prev_json.size() > 1U)
        {
            prev_json += ',';
        }
        prev_json += "\"" + prev_id + "\"";
    }
    prev_json += ']';
    auto const room_field = room_id.empty() ? std::string{} : ",\"room_id\":\"" + std::string{room_id} + "\"";
    auto const json = std::string{"{\"type\":\""} + std::string{type} + "\",\"state_key\":\"" + std::string{state_key} +
                      "\",\"event_id\":\"" + event_id + "\",\"sender\":\"" + std::string{sender} +
                      "\",\"origin_server_ts\":" + std::to_string(timestamp) + ",\"auth_events\":" + auth_json +
                      ",\"prev_events\":" + prev_json + ",\"content\":" + std::string{content} + room_field + "}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

    auto result = StateEventReference{};
    result.key = {std::string{type}, std::string{state_key}};
    result.event_id = event_id;
    result.sender = sender;
    result.origin_server_ts = timestamp;
    result.depth = 1U;
    result.event_json = parsed.value;
    return result;
}

[[nodiscard]] auto make_create(std::string_view version, std::string_view room_id) -> StateEventReference
{
    auto const create_id = version == "12" ? "$" + std::string{room_id.substr(1U)} : "$create";
    auto content = std::string{"{\"room_version\":\""} + std::string{version} + "\"";
    if (version != "11" && version != "12")
    {
        content += ",\"creator\":\"@alice:example.org\"";
    }
    content += '}';
    auto create = make_event("m.room.create", "", create_id, "@alice:example.org", 1, {}, content,
                             version == "12" ? std::string_view{} : room_id);
    return create;
}

[[nodiscard]] auto make_power_levels(std::string const& event_id, std::vector<std::string> const& auth_ids,
                                     std::string_view room_id, bool v12 = false) -> StateEventReference
{
    auto const content =
        v12 ? R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":0,"users":{},"users_default":0})"
            : R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":0,"users":{"@alice:example.org":100},"users_default":0})";
    return make_event("m.room.power_levels", "", event_id, "@alice:example.org", 10, auth_ids, content, room_id);
}

[[nodiscard]] auto make_member_join(std::string_view room_id, std::string_view create_auth_id,
                                    std::string_view create_prev_id) -> StateEventReference
{
    auto auth_ids = std::vector<std::string>{};
    if (!create_auth_id.empty())
    {
        auth_ids.emplace_back(create_auth_id);
    }
    auto prev_ids = std::vector<std::string>{};
    if (!create_prev_id.empty())
    {
        prev_ids.emplace_back(create_prev_id);
    }
    return make_event("m.room.member", "@alice:example.org", "$alice_join", "@alice:example.org", 2, auth_ids,
                      R"({"membership":"join"})", room_id, prev_ids);
}

[[nodiscard]] auto make_member_invite(std::string const& target, std::string const& event_id,
                                      std::vector<std::string> const& auth_ids, std::string_view room_id,
                                      std::int64_t timestamp) -> StateEventReference
{
    return make_event("m.room.member", target, event_id, "@alice:example.org", timestamp, auth_ids,
                      R"({"membership":"invite"})", room_id);
}

[[nodiscard]] auto make_mainline_request(std::string_view version, bool include_pl1) -> StateResolutionRequest
{
    auto const room_id = version == "12" ? "!mainlinehash" : "!mainline:example.org";
    auto const create = make_create(version, room_id);
    auto const v12 = version == "12";
    auto const create_id = v12 ? std::string_view{} : std::string_view{create.event_id};
    auto const alice_join = make_member_join(room_id, create_id, create.event_id);
    auto p0_auth = std::vector<std::string>{"$alice_join"};
    auto p1_auth = std::vector<std::string>{"$pl0", "$alice_join"};
    auto p2_auth = std::vector<std::string>{"$pl1", "$alice_join"};
    if (!v12)
    {
        p0_auth.emplace_back(create.event_id);
        p1_auth.emplace_back(create.event_id);
        p2_auth.emplace_back(create.event_id);
    }
    auto const p0 = make_power_levels("$pl0", p0_auth, room_id, v12);
    auto const p1 = make_power_levels("$pl1", p1_auth, room_id, v12);
    auto const p2 = make_power_levels("$pl2", p2_auth, room_id, v12);
    auto const p2b = make_power_levels("$pl2b", p2_auth, room_id, v12);
    auto p0_topic_auth = std::vector<std::string>{"$pl0", "$alice_join"};
    auto p1_topic_auth = std::vector<std::string>{"$pl1", "$alice_join"};
    if (!create_id.empty())
    {
        p0_topic_auth.emplace_back(create_id);
        p1_topic_auth.emplace_back(create_id);
    }
    auto const older_topic = make_event("m.room.topic", "", "$topic_pl0", "@alice:example.org", 200, p0_topic_auth,
                                        R"({"topic":"anchored at P0"})", room_id);
    auto const newer_topic = make_event("m.room.topic", "", "$topic_pl1", "@alice:example.org", 100, p1_topic_auth,
                                        R"({"topic":"anchored at P1"})", room_id);

    auto group_a = StateGroup{};
    group_a.group_id = "branch-a";
    group_a.state = {create, alice_join, p2, older_topic};
    auto group_b = StateGroup{};
    group_b.group_id = "branch-b";
    group_b.state = {create, alice_join, v12 ? p2b : p2, newer_topic};

    auto request = StateResolutionRequest{};
    request.room_version = version;
    request.room_id = room_id;
    request.state_groups = {group_a, group_b};
    auto external = std::vector<StateEventReference>{};
    if (include_pl1)
    {
        external.push_back(p1);
    }
    external.push_back(p0);
    request.event_lookup = [external = std::move(external), create,
                            version](std::string_view event_id) -> std::optional<StateEventReference> {
        if (version == "12" && event_id == create.event_id)
        {
            return create;
        }
        auto const found = std::ranges::find_if(external, [event_id](StateEventReference const& ref) {
            return ref.event_id == event_id;
        });
        return found == external.end() ? std::nullopt : std::optional<StateEventReference>{*found};
    };
    return request;
}

[[nodiscard]] auto result_event_for(merovingian::events::StateResolutionResult const& result, std::string_view type,
                                    std::string_view state_key) -> StateEventReference const*
{
    auto const found = std::ranges::find_if(result.resolved_state, [&](StateEventReference const& event) {
        return event.key == StateKey{std::string{type}, std::string{state_key}};
    });
    return found == result.resolved_state.end() ? nullptr : &*found;
}

[[nodiscard]] auto make_v12_request(StateGroup group_a, StateGroup group_b,
                                    std::vector<StateEventReference> lookup_events = {}) -> StateResolutionRequest
{
    auto request = StateResolutionRequest{};
    request.room_version = "12";
    request.room_id = "!evt9hash";
    request.state_groups = {std::move(group_a), std::move(group_b)};
    auto create = make_create("12", request.room_id);
    request.event_lookup = [lookup_events = std::move(lookup_events),
                            create](std::string_view event_id) -> std::optional<StateEventReference> {
        if (event_id == create.event_id)
        {
            return create;
        }
        auto const found = std::ranges::find_if(lookup_events, [event_id](StateEventReference const& event) {
            return event.event_id == event_id;
        });
        return found == lookup_events.end() ? std::nullopt : std::optional<StateEventReference>{*found};
    };
    return request;
}

} // namespace

// Spec: Matrix room versions 10, 11 and 12 — Mainline ordering.
// URLs: ../../docs/matrix-v1.19-spec/rooms/v10.md#mainline-ordering
//       ../../docs/matrix-v1.19-spec/rooms/v11.md#mainline-ordering
//       ../../docs/matrix-v1.19-spec/rooms/v12.md#mainline-ordering
// Mainline ancestors are repeatedly fetched from auth_events, even when they
// are absent from the submitted state groups.
SCENARIO("Mainline ordering fetches external power-level ancestors in v10, v11 and v12",
         "[conformance][state-resolution][mainline][security_audit_state_resolution][room-v10][room-v11][room-v12]")
{
    GIVEN("a P2 to P1 to P0 power-level mainline where only P2 is in the state groups")
    {
        auto const versions = std::vector<std::string_view>{"10", "11", "12"};

        WHEN("topic conflicts reference the external P0 and P1 ancestors")
        {
            auto winners = std::vector<std::pair<std::string, std::string>>{};
            for (auto const version : versions)
            {
                auto const request = make_mainline_request(version, true);
                auto const* policy = merovingian::rooms::find_room_version_policy(version);
                REQUIRE(policy != nullptr);
                auto const result = merovingian::events::resolve_state_v2(request, *policy);
                INFO("room version " << version << " failed: " << result.reason);
                auto const* topic = result_event_for(result, "m.room.topic", "");
                winners.emplace_back(std::string{version}, topic == nullptr ? std::string{} : topic->event_id);
                REQUIRE((result.resolved && topic != nullptr));
            }

            THEN("the P1-anchored event sorts after P0 and wins despite its earlier timestamp")
            {
                // Spec MUST: mainline position 2 (P0) sorts before position 1 (P1).
                REQUIRE(winners.size() == 3U);
                REQUIRE(winners[0].second == "$topic_pl1");
                REQUIRE(winners[1].second == "$topic_pl1");
                REQUIRE(winners[2].second == "$topic_pl1");
            }
        }
    }
}

// Spec: Matrix room versions 10, 11 and 12 — Mainline ordering.
// URLs: ../../docs/matrix-v1.19-spec/rooms/v10.md#mainline-ordering
//       ../../docs/matrix-v1.19-spec/rooms/v11.md#mainline-ordering
//       ../../docs/matrix-v1.19-spec/rooms/v12.md#mainline-ordering
// A required power-level ancestor cannot be silently treated as absent.
SCENARIO("Mainline ordering fails closed when the required P1 ancestor is unavailable",
         "[conformance][state-resolution][mainline][security_audit_state_resolution]")
{
    GIVEN("a v11 room whose shared P2 power event cites P1")
    {
        auto const request = make_mainline_request("11", false);
        auto const* policy = merovingian::rooms::find_room_version_policy("11");
        REQUIRE(policy != nullptr);

        WHEN("P1 cannot be resolved from the submitted groups or event lookup")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution refuses to continue with a partial mainline")
            {
                // Spec MUST: mainline ordering repeatedly fetches each power-level ancestor.
                REQUIRE_FALSE(result.resolved);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

// Spec: Matrix room version 12 — Definitions, “Conflicted state subgraph”.
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md#definitions
// The subgraph is the union of paths between conflicted roots; shared
// branches are bounded by distinct events, not by the number of paths.
SCENARIO("Room v12 resolves a shared 30-rung auth ladder with 100 conflicted endpoints",
         "[conformance][state-resolution][room-v12][conflicted-subgraph][security_audit_state_resolution]")
{
    GIVEN("two room states with 100 conflicted events arranged as a shared and forked auth ladder")
    {
        auto constexpr room_id = std::string_view{"!evt9hash"};
        auto const create = make_create("12", room_id);
        auto members = std::vector<StateEventReference>{make_member_join(room_id, {}, create.event_id)};
        auto powers =
            std::vector<StateEventReference>{make_power_levels("$p0", {members.front().event_id}, room_id, true)};
        auto historical = std::vector<StateEventReference>{members.front(), powers.front()};
        for (std::size_t rung = 1U; rung < 30U; ++rung)
        {
            auto const member =
                make_event("m.room.member", "@alice:example.org", "$m" + std::to_string(rung), "@alice:example.org",
                           static_cast<std::int64_t>(rung), {powers.back().event_id, members.back().event_id},
                           R"({"membership":"join"})", room_id, {members.back().event_id});
            auto const power = make_power_levels("$p" + std::to_string(rung), {powers.back().event_id, member.event_id},
                                                 room_id, true);
            members.push_back(member);
            powers.push_back(power);
            historical.push_back(member);
            historical.push_back(power);
        }
        auto group_a = StateGroup{
            "latest", {members.back(), powers.back()}
        };
        auto group_b = StateGroup{
            "older", {members.front(), powers.front()}
        };
        for (std::size_t index = 0; index < 50U; ++index)
        {
            auto const target = "@target" + std::to_string(index) + ":example.org";
            group_a.state.push_back(make_member_invite(target, "$invite-new-" + std::to_string(index),
                                                       {powers.back().event_id, members.back().event_id}, room_id,
                                                       100));
            group_b.state.push_back(make_member_invite(target, "$invite-old-" + std::to_string(index),
                                                       {powers.front().event_id, members.front().event_id}, room_id,
                                                       1));
        }
        auto request = make_v12_request(std::move(group_a), std::move(group_b), std::move(historical));
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("the v12 conflicted-state subgraph is built and resolved")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("each shared ladder vertex is processed once and resolution completes")
            {
                // Spec MUST: the subgraph contains the union of paths, not an unbounded path enumeration.
                REQUIRE(result.resolved);
                auto const* last_invite = result_event_for(result, "m.room.member", "@target49:example.org");
                REQUIRE(last_invite != nullptr);
                REQUIRE(last_invite->event_id == "$invite-new-49");
                auto const* resolved_power = result_event_for(result, "m.room.power_levels", "");
                REQUIRE(resolved_power != nullptr);
                REQUIRE(resolved_power->event_id == "$p29");
            }
        }
    }
}

// Spec: Matrix room version 12 — Definitions, “Conflicted state subgraph”.
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md#definitions
// Malformed or cyclic auth graphs cannot be partially used for resolution.
SCENARIO("Room v12 fails closed on missing and cyclic conflicted auth paths",
         "[conformance][state-resolution][room-v12][conflicted-subgraph][security_audit_state_resolution]")
{
    GIVEN("conflicted v12 events with a missing referenced node or a cycle")
    {
        auto const room_id = std::string_view{"!evt9hash"};
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("a conflicted event names an auth event that cannot be fetched")
        {
            auto const missing = make_event("com.example.conflict", "topic", "$missing_root", "@alice:example.org", 1,
                                            {"$not-stored"}, "{}", room_id);
            auto const peer =
                make_event("com.example.conflict", "topic", "$peer_root", "@alice:example.org", 2, {}, "{}", room_id);
            auto group_a = StateGroup{"missing-a", {missing}};
            auto group_b = StateGroup{"missing-b", {peer}};
            auto request = make_v12_request(std::move(group_a), std::move(group_b));
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution rejects the incomplete graph")
            {
                // Spec MUST: a missing auth-chain event cannot be ignored in favor of partial data.
                REQUIRE_FALSE(result.resolved);
            }
        }

        WHEN("two conflicted events cite each other")
        {
            auto const first = make_event("com.example.conflict", "topic", "$cycle_a", "@alice:example.org", 1,
                                          {"$cycle_b"}, "{}", room_id);
            auto const second = make_event("com.example.conflict", "topic", "$cycle_b", "@alice:example.org", 2,
                                           {"$cycle_a"}, "{}", room_id);
            auto group_a = StateGroup{"cycle-a", {first}};
            auto group_b = StateGroup{"cycle-b", {second}};
            auto request = make_v12_request(std::move(group_a), std::move(group_b));
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution rejects the cyclic graph rather than recursing through paths")
            {
                // Spec MUST: the auth_events graph used for resolution is a DAG.
                REQUIRE_FALSE(result.resolved);
            }
        }
    }
}

// Spec: Matrix room version 12 — Definitions, “Auth chain” and “Conflicted state subgraph”.
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md#definitions
// Distinct fetched vertices are capped to keep adversarial auth chains bounded.
SCENARIO("State resolution fails closed after the distinct auth-chain event cap",
         "[conformance][state-resolution][room-v12][security_audit_state_resolution]")
{
    GIVEN("conflicted roots whose shared auth ancestry exceeds the distinct-event budget")
    {
        auto const room_id = std::string_view{"!evt9hash"};
        auto lookup_events = std::unordered_map<std::string, StateEventReference>{};
        lookup_events.reserve(merovingian::events::max_auth_chain_walk_events + 1U);
        auto previous_id = std::string{};
        for (std::size_t index = 0; index <= merovingian::events::max_auth_chain_walk_events; ++index)
        {
            auto const event_id = "$cap-" + std::to_string(index);
            auto const auth_ids =
                previous_id.empty() ? std::vector<std::string>{} : std::vector<std::string>{previous_id};
            lookup_events.emplace(event_id,
                                  make_event("com.example.auth", std::to_string(index), event_id, "@alice:example.org",
                                             static_cast<std::int64_t>(index), auth_ids, "{}", room_id));
            previous_id = event_id;
        }
        auto const root_a = make_event("com.example.conflict", "topic", "$cap-root-a", "@alice:example.org", 1,
                                       {previous_id}, "{}", room_id);
        auto const root_b = make_event("com.example.conflict", "topic", "$cap-root-b", "@alice:example.org", 2,
                                       {previous_id}, "{}", room_id);
        auto request = make_v12_request(StateGroup{"cap-a", {root_a}}, StateGroup{"cap-b", {root_b}});
        request.event_lookup =
            [lookup_events = std::move(lookup_events), create_id = std::string{"$evt9hash"},
             room_id = std::string{room_id}](std::string_view event_id) -> std::optional<StateEventReference> {
            if (event_id == create_id)
            {
                return make_create("12", room_id);
            }
            auto const found = lookup_events.find(std::string{event_id});
            return found == lookup_events.end() ? std::nullopt : std::optional<StateEventReference>{found->second};
        };
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("resolution traverses the oversized auth ancestry")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the resolver refuses to use a partial auth chain")
            {
                // Spec MUST: required auth-chain lookups fail closed at the configured distinct-event cap.
                REQUIRE_FALSE(result.resolved);
            }
        }
    }
}
