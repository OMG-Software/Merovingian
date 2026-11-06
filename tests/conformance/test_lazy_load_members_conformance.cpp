// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Lazy-loading of room members on GET /sync and GET /rooms/{roomId}/context/{eventId}
// (client-server-api.md, "Lazy-loading room members" and the GET /sync note). Redundancy is tracked on
// /sync by acknowledgement (ADR-0450), and not at all on /messages and /context (ADR-0451).
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto k_lazy_state = std::string_view{R"({"room":{"state":{"lazy_load_members":true}}})"};
// One timeline event, so the members of everyone who spoke earlier are not senders of it.
constexpr auto k_lazy_one_event =
    std::string_view{R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};

[[nodiscard]] auto lazy_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto user_id(std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":example.org";
}

[[nodiscard]] auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "access_token");
}

[[nodiscard]] auto login_device(ClientServerRuntime& rt, std::string const& localpart, std::string const& device)
    -> std::string
{
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + user_id(localpart) +
                 R"("},"password":"CorrectHorse7!","device_id":")" + device + R"("})");
    REQUIRE(login.status == 200U);
    return *string_member(parse_object(login.body), "access_token");
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& preset)
    -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":")" + preset + R"("})");
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

auto join_room(ClientServerRuntime& rt, std::string const& token, std::string const& room_id) -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", token, "{}").status == 200U);
}

[[nodiscard]] auto say(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                       std::string const& text) -> std::string
{
    static auto counter = std::uint64_t{0U};
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/lz" + std::to_string(++counter),
             token, R"({"msgtype":"m.text","body":")" + text + R"("})");
    REQUIRE(sent.status == 200U);
    return *string_member(parse_object(sent.body), "event_id");
}

struct Synced final
{
    merovingian::canonicaljson::Object body{};
    std::string next_batch{};
};

[[nodiscard]] auto sync(ClientServerRuntime& rt, std::string const& token, std::string_view filter,
                        std::string const& since = {}, std::string const& extra = {}) -> Synced
{
    auto target =
        std::string{"/_matrix/client/v3/sync?filter="} + merovingian::core::percent_encode_path_component(filter);
    if (!since.empty())
    {
        target += "&since=" + merovingian::core::percent_encode_path_component(since);
    }
    target += extra;
    auto const reply = call(rt, "GET", target, token);
    REQUIRE(reply.status == 200U);
    auto body = parse_object(reply.body);
    auto next = *string_member(body, "next_batch");
    return {std::move(body), std::move(next)};
}

// rooms.<section>.<room_id>, or nullptr.
[[nodiscard]] auto room_section(Synced const& synced, std::string_view section, std::string const& room_id)
    -> merovingian::canonicaljson::Object const*
{
    auto const* rooms = object_member_as_object(synced.body, "rooms");
    auto const* group = rooms == nullptr ? nullptr : object_member_as_object(*rooms, section);
    return group == nullptr ? nullptr : object_member_as_object(*group, room_id);
}

// The events of `room.<part>` (state or timeline).
[[nodiscard]] auto events_of(merovingian::canonicaljson::Object const& room, std::string_view part)
    -> std::vector<merovingian::canonicaljson::Object>
{
    auto out = std::vector<merovingian::canonicaljson::Object>{};
    auto const* section = object_member_as_object(room, part);
    auto const* events = section == nullptr ? nullptr : object_member_as_array(*section, "events");
    if (events != nullptr)
    {
        for (auto const& entry : *events)
        {
            out.push_back(std::get<merovingian::canonicaljson::Object>(entry.storage()));
        }
    }
    return out;
}

[[nodiscard]] auto events_of_array(merovingian::canonicaljson::Array const& events)
    -> std::vector<merovingian::canonicaljson::Object>
{
    auto out = std::vector<merovingian::canonicaljson::Object>{};
    for (auto const& entry : events)
    {
        out.push_back(std::get<merovingian::canonicaljson::Object>(entry.storage()));
    }
    return out;
}

// The state_key of every m.room.member event.
[[nodiscard]] auto member_keys(std::vector<merovingian::canonicaljson::Object> const& events)
    -> std::multiset<std::string>
{
    auto keys = std::multiset<std::string>{};
    for (auto const& event : events)
    {
        auto const* type = string_member(event, "type");
        auto const* key = string_member(event, "state_key");
        if (type != nullptr && *type == "m.room.member" && key != nullptr)
        {
            keys.insert(*key);
        }
    }
    return keys;
}

[[nodiscard]] auto state_members(Synced const& synced, std::string_view section, std::string const& room_id)
    -> std::multiset<std::string>
{
    auto const* room = room_section(synced, section, room_id);
    REQUIRE(room != nullptr);
    return member_keys(events_of(*room, "state"));
}

[[nodiscard]] auto state_types(Synced const& synced, std::string const& room_id) -> std::set<std::string>
{
    auto const* room = room_section(synced, "join", room_id);
    REQUIRE(room != nullptr);
    auto types = std::set<std::string>{};
    for (auto const& event : events_of(*room, "state"))
    {
        types.insert(*string_member(event, "type"));
    }
    return types;
}

using Keys = std::multiset<std::string>;

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Lazy-loading room members; GET /sync
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#lazy-loading-room-members
//
// "When enabled, lazy-loading aware endpoints will only include membership events for the sender of
// events being included in the response ... the server will only return membership events for the sender
// of events in the timeline, not all members of a room." And "servers MUST include the syncing user's own
// membership event ... when the full state of rooms is requested".
SCENARIO("An initial sync with lazy-loading returns the timeline senders' and the user's own membership",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("a room of four members where only bob spoke last")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        join_room(rt, dave, room);
        std::ignore = say(rt, bob, room, "hello");

        WHEN("dave, who never spoke, syncs with lazy_load_members on the state filter and a one event timeline")
        {
            auto const synced = sync(rt, dave, k_lazy_one_event);

            THEN("the members in state are the timeline sender and dave himself")
            {
                // Spec MUST: only the senders of the timeline, plus the user's own membership.
                REQUIRE(state_members(synced, "join", room) == Keys{user_id("bob"), user_id("dave")});
            }
            THEN("all non-member state is still sent")
            {
                auto const types = state_types(synced, room);
                REQUIRE(types.contains("m.room.create"));
                REQUIRE(types.contains("m.room.power_levels"));
                REQUIRE(types.contains("m.room.join_rules"));
            }
            THEN("the room summary still reports the true member counts")
            {
                auto const* summary = object_member_as_object(*room_section(synced, "join", room), "summary");
                REQUIRE(summary != nullptr);
                auto const* joined = int_member(*summary, "m.joined_member_count");
                REQUIRE(joined != nullptr);
                REQUIRE(*joined == 4);
            }
        }
        WHEN("dave syncs the same way with lazy-loading off")
        {
            auto const synced = sync(rt, dave, R"({"room":{"timeline":{"limit":1}}})");

            THEN("the whole member list is in state, as before")
            {
                REQUIRE(state_members(synced, "join", room) ==
                        Keys{user_id("alice"), user_id("bob"), user_id("carol"), user_id("dave")});
            }
        }
        WHEN("lazy_load_members is set on the timeline filter only")
        {
            auto const synced = sync(rt, dave, R"({"room":{"timeline":{"limit":1,"lazy_load_members":true}}})");

            THEN("it does nothing for /sync: the spec supports lazy-loading only on the state filter")
            {
                // Spec: "Lazy-loading members is only supported on the `state` part of a RoomFilter for
                // this endpoint."
                REQUIRE(state_members(synced, "join", room).size() == 4U);
            }
        }
    }
}

// Spec: same section. "the server MAY assume that clients will remember membership events they have
// already been sent, and choose to skip sending membership events for members whose membership has not
// changed ... Clients may request that redundant membership events are always included ... by setting
// include_redundant_members to true."
SCENARIO("An incremental sync sends a sender's membership once, unless redundant members are requested",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("carol, who never speaks, has synced a room where alice spoke last")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        std::ignore = say(rt, alice, room, "first");
        auto const initial = sync(rt, carol, k_lazy_one_event);

        WHEN("bob speaks for the first time and carol syncs")
        {
            std::ignore = say(rt, bob, room, "hi");
            auto const first = sync(rt, carol, k_lazy_one_event, initial.next_batch);

            THEN("bob's membership arrives in state although it did not change since the last sync")
            {
                REQUIRE(state_members(first, "join", room) == Keys{user_id("bob")});
            }
            AND_WHEN("bob speaks again and carol syncs with the token she was given")
            {
                std::ignore = say(rt, bob, room, "again");
                auto const second = sync(rt, carol, k_lazy_one_event, first.next_batch);

                THEN("the state holds no membership: she has bob's already, and her own is not forced")
                {
                    // Spec MAY: skip members whose membership has not changed.
                    REQUIRE(state_members(second, "join", room).empty());
                }
            }
        }
        WHEN("bob speaks twice and carol syncs with include_redundant_members each time")
        {
            constexpr auto redundant = std::string_view{
                R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true,"include_redundant_members":true}}})"};
            std::ignore = say(rt, bob, room, "one");
            auto const first = sync(rt, carol, redundant, initial.next_batch);
            std::ignore = say(rt, bob, room, "two");
            auto const second = sync(rt, carol, redundant, first.next_batch);

            THEN("bob's membership is in the state of both")
            {
                REQUIRE(state_members(first, "join", room) == Keys{user_id("bob")});
                REQUIRE(state_members(second, "join", room) == Keys{user_id("bob")});
            }
        }
        WHEN("bob changes his display name, then speaks")
        {
            std::ignore = say(rt, bob, room, "before");
            auto const known = sync(rt, carol, k_lazy_one_event, initial.next_batch);
            REQUIRE(call(rt, "PUT", "/_matrix/client/v3/profile/" + user_id("bob") + "/displayname", bob,
                         R"({"displayname":"Bobby"})")
                        .status == 200U);
            auto const changed = sync(rt, carol, k_lazy_one_event, known.next_batch);
            std::ignore = say(rt, bob, room, "after");
            auto const later = sync(rt, carol, k_lazy_one_event, changed.next_batch);

            THEN("his changed membership is not redundant when he speaks again")
            {
                auto const members = state_members(later, "join", room);
                REQUIRE(members == Keys{user_id("bob")});
                auto const* room_section_later = room_section(later, "join", room);
                auto const state = events_of(*room_section_later, "state");
                REQUIRE(state.size() == 1U);
                auto const* content = object_member_as_object(state.front(), "content");
                REQUIRE(content != nullptr);
                REQUIRE(*string_member(*content, "displayname") == "Bobby");
            }
        }
    }
}

// Spec: GET /sync note. "When a sync is limited, the server MUST return membership events for events in
// the gap (between since and the start of the returned timeline), regardless as to whether or not they
// are redundant."
SCENARIO("A limited incremental sync returns the membership changes in the gap",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("carol has synced with bob's membership already sent to her")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        std::ignore = say(rt, bob, room, "hello");
        auto const initial = sync(rt, carol, k_lazy_one_event);

        WHEN("dave joins in the gap and never speaks, and bob then sends two messages, so the sync is limited")
        {
            join_room(rt, dave, room);
            std::ignore = say(rt, bob, room, "one");
            std::ignore = say(rt, bob, room, "two");
            auto const synced = sync(rt, carol, k_lazy_one_event, initial.next_batch);

            THEN("dave's join is in state, and bob's already-sent membership is not forced by the gap rule")
            {
                auto const* section = room_section(synced, "join", room);
                REQUIRE(section != nullptr);
                auto const* timeline = object_member_as_object(*section, "timeline");
                REQUIRE(*bool_member(*timeline, "limited"));
                // Spec MUST: membership events for events in the gap, redundant or not.
                REQUIRE(state_members(synced, "join", room) == Keys{user_id("dave")});
            }
        }
    }
}

// Spec: GET /sync note: "servers MUST include the syncing user's own membership event when they join a
// room, or when the full state of rooms is requested ... the user's own membership event is eligible for
// being considered redundant."
SCENARIO("The user's own membership is sent when they join in the window and when full state is requested",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("a public room where bob speaks and erin has not joined")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        std::ignore = say(rt, bob, room, "hello");
        auto const before_join = sync(rt, erin, k_lazy_one_event);

        WHEN("erin joins and bob speaks, and her timeline shows only the last event")
        {
            join_room(rt, erin, room);
            std::ignore = say(rt, bob, room, "welcome");
            auto const synced = sync(rt, erin, k_lazy_one_event, before_join.next_batch);

            THEN("her own membership is in state, with bob's")
            {
                REQUIRE(state_members(synced, "join", room) == Keys{user_id("bob"), user_id("erin")});
            }
        }
        WHEN("erin joins and her whole window is returned, join event included")
        {
            join_room(rt, erin, room);
            std::ignore = say(rt, bob, room, "welcome");
            auto const synced = sync(rt, erin, k_lazy_state, before_join.next_batch);

            THEN("the join is in the timeline and her membership is not duplicated into state")
            {
                auto const members = state_members(synced, "join", room);
                REQUIRE(std::ranges::count(members, user_id("erin")) == 0);
                auto const timeline = events_of(*room_section(synced, "join", room), "timeline");
                REQUIRE(member_keys(timeline).contains(user_id("erin")));
            }
        }
        WHEN("erin, already in the room and up to date, asks for the full state")
        {
            join_room(rt, erin, room);
            auto const joined = sync(rt, erin, k_lazy_one_event, before_join.next_batch);
            std::ignore = say(rt, bob, room, "again");
            auto const synced = sync(rt, erin, k_lazy_one_event, joined.next_batch, "&full_state=true");

            THEN("the state is all state at the start of the timeline: her own and bob's membership, tracker ignored")
            {
                // Spec: full_state=true returns "all state up to the start of the timeline".
                REQUIRE(state_members(synced, "join", room) == Keys{user_id("bob"), user_id("erin")});
                REQUIRE(state_types(synced, room).contains("m.room.create"));
            }
        }
        WHEN("erin has synced and bob speaks, so nothing makes her own membership newly relevant")
        {
            join_room(rt, erin, room);
            auto const joined = sync(rt, erin, k_lazy_one_event, before_join.next_batch);
            std::ignore = say(rt, bob, room, "again");
            auto const synced = sync(rt, erin, k_lazy_one_event, joined.next_batch);

            THEN("her own membership is absent from state")
            {
                REQUIRE_FALSE(state_members(synced, "join", room).contains(user_id("erin")));
            }
        }
    }
}

// Spec: Lazy-loading room members: it is valid for a server to send redundant members, so a lost response
// must never lose one. The tracker acknowledges by the `since` token (ADR-0450).
SCENARIO("A member sent in a response the client never received is sent again",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("carol has synced, and bob has since spoken")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        std::ignore = say(rt, alice, room, "first");
        auto const initial = sync(rt, carol, k_lazy_one_event);
        std::ignore = say(rt, bob, room, "hi");

        WHEN("the response carrying bob's membership is lost and carol retries with the older since")
        {
            auto const lost = sync(rt, carol, k_lazy_one_event, initial.next_batch);
            REQUIRE(state_members(lost, "join", room) == Keys{user_id("bob")});
            auto const retry = sync(rt, carol, k_lazy_one_event, initial.next_batch);

            THEN("bob's membership is in the retry")
            {
                REQUIRE(state_members(retry, "join", room) == Keys{user_id("bob")});
            }
            AND_WHEN("bob speaks again and she syncs from the retry's token")
            {
                std::ignore = say(rt, bob, room, "more");
                auto const next = sync(rt, carol, k_lazy_one_event, retry.next_batch);

                THEN("it is now redundant")
                {
                    REQUIRE(state_members(next, "join", room).empty());
                }
            }
        }
        WHEN("a limited retry pushes bob's message into the gap, then bob speaks again")
        {
            auto const lost = sync(rt, carol, k_lazy_one_event, initial.next_batch);
            REQUIRE(state_members(lost, "join", room) == Keys{user_id("bob")});
            std::ignore = say(rt, alice, room, "x1");
            std::ignore = say(rt, alice, room, "x2");
            auto const retry = sync(rt, carol, k_lazy_one_event, initial.next_batch);
            REQUIRE(*bool_member(*object_member_as_object(*room_section(retry, "join", room), "timeline"), "limited"));
            std::ignore = say(rt, bob, room, "back");
            auto const next = sync(rt, carol, k_lazy_one_event, retry.next_batch);

            THEN("bob's membership, which carol never received, is sent with his next message")
            {
                REQUIRE(state_members(next, "join", room).contains(user_id("bob")));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Lazy-loading room members; GET /sync
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#lazy-loading-room-members
//
// Skipping redundant members is permitted, not required: "the server MAY assume that clients will remember
// membership events they have already been sent". Which sync stream a client's memory belongs to is this
// server's choice, not a spec rule: it keeps one record per user, device and filter, so a second device or a
// different filter, which may hold nothing, is never told that a member was already sent.
SCENARIO("Streams are tracked apart by filter and by device", "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("carol syncs a room with two filters and from two devices, all up to date")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const carol_second = login_device(rt, "carol", "SECOND");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        std::ignore = say(rt, alice, room, "first");
        constexpr auto filter_b =
            std::string_view{R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true,"limit":50}}})"};
        auto const a_initial = sync(rt, carol, k_lazy_one_event);
        auto const b_initial = sync(rt, carol, filter_b);
        auto const second_initial = sync(rt, carol_second, k_lazy_one_event);

        WHEN("bob speaks and every stream syncs, then bob speaks again and every stream syncs again")
        {
            std::ignore = say(rt, bob, room, "one");
            auto const a1 = sync(rt, carol, k_lazy_one_event, a_initial.next_batch);
            std::ignore = say(rt, bob, room, "two");
            auto const a2 = sync(rt, carol, k_lazy_one_event, a1.next_batch);
            auto const b2 = sync(rt, carol, filter_b, b_initial.next_batch);
            auto const second2 = sync(rt, carol_second, k_lazy_one_event, second_initial.next_batch);

            THEN("the stream that saw bob does not repeat him, the others have never been sent him")
            {
                REQUIRE(state_members(a1, "join", room) == Keys{user_id("bob")});
                REQUIRE(state_members(a2, "join", room).empty());
                REQUIRE(state_members(b2, "join", room) == Keys{user_id("bob")});
                REQUIRE(state_members(second2, "join", room) == Keys{user_id("bob")});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Lazy-loading room members; GET /sync
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#lazy-loading-room-members
//
// The server "will only return membership events for the `sender` of events in the timeline". An event the
// timeline filter drops, or that the user ignores and so is never delivered, is not in the timeline, so its
// sender's membership is not returned on its account.
SCENARIO("A sender whose event was not delivered contributes no membership",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("a room where carol spoke and then bob spoke last")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        join_room(rt, dave, room);
        std::ignore = say(rt, carol, room, "carol");
        std::ignore = say(rt, bob, room, "bob");

        WHEN("the timeline filter drops bob's events")
        {
            constexpr auto filter = std::string_view{
                R"({"room":{"timeline":{"limit":1,"not_senders":["@bob:example.org"]},"state":{"lazy_load_members":true}}})"};
            auto const synced = sync(rt, dave, filter);

            THEN("the delivered sender is carol and bob has no membership in state")
            {
                REQUIRE(state_members(synced, "join", room) == Keys{user_id("carol"), user_id("dave")});
            }
        }
        WHEN("dave ignores bob")
        {
            REQUIRE(call(rt, "PUT", "/_matrix/client/v3/user/" + user_id("dave") + "/account_data/m.ignored_user_list",
                         dave, R"({"ignored_users":{"@bob:example.org":{}}})")
                        .status == 200U);
            auto const synced = sync(rt, dave, k_lazy_one_event);

            THEN("bob's message is withheld and so is his membership")
            {
                REQUIRE_FALSE(state_members(synced, "join", room).contains(user_id("bob")));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /sync, RoomFilter state; Lazy-loading room members
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// The spec has lazy-loading enabled by `lazy_load_members` on a RoomEventFilter, the type of the /sync
// `state` filter. That the same filter's `types`, `not_types` and `senders` then also decide which member
// events are returned, the user's own included, is this server's reading, not a quoted rule.
SCENARIO("The state filter applies to lazy-loaded members on /sync", "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("a room where bob spoke last")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        std::ignore = say(rt, bob, room, "bob");

        WHEN("the state filter excludes m.room.member")
        {
            constexpr auto filter = std::string_view{
                R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true,"not_types":["m.room.member"]}}})"};
            auto const synced = sync(rt, bob, filter);

            THEN("no member event is returned, not even bob's own, and the other state is")
            {
                REQUIRE(state_members(synced, "join", room).empty());
                REQUIRE(state_types(synced, room).contains("m.room.create"));
            }
        }
        WHEN("the state filter lists only another type")
        {
            constexpr auto filter = std::string_view{
                R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true,"types":["m.room.create"]}}})"};
            auto const synced = sync(rt, bob, filter);

            THEN("no member event is returned")
            {
                REQUIRE(state_members(synced, "join", room).empty());
                REQUIRE(state_types(synced, room) == std::set<std::string>{"m.room.create"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /sync, rooms.leave and rooms.invite; Lazy-loading room members
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// Lazy-loading limits `state` for the rooms a /sync returns, and a left room's `state` is likewise only the
// timeline's senders' members plus the user's own. Applying it to rooms.leave is this server's reading; the
// spec names no section. An invite carries `invite_state` (stripped state), not `state`, and is not touched.
SCENARIO("Lazy-loading applies to rooms the user has left, and leaves invites alone",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("a room dave left, and a private room that erin is invited to")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const dave = register_user(rt, "dave");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, dave, room);
        std::ignore = say(rt, bob, room, "bob");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room + "/leave", dave, "{}").status == 200U);
        auto const private_room = create_room(rt, alice, "private_chat");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + private_room + "/invite", alice,
                     R"({"user_id":")" + user_id("erin") + R"("})")
                    .status == 200U);

        WHEN("dave syncs with include_leave and lazy-loading")
        {
            constexpr auto lazy = std::string_view{
                R"({"room":{"include_leave":true,"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};
            auto const synced = sync(rt, dave, lazy);

            THEN("the left room's state holds only the timeline sender's and his own membership")
            {
                REQUIRE(state_members(synced, "leave", room) == Keys{user_id("dave")});
            }
        }
        WHEN("erin syncs with and without lazy-loading")
        {
            auto const lazy = sync(rt, erin, k_lazy_state);
            auto const plain = sync(rt, erin, "{}");

            THEN("the invite's stripped state is the same")
            {
                auto const* lazy_invite = room_section(lazy, "invite", private_room);
                auto const* plain_invite = room_section(plain, "invite", private_room);
                REQUIRE(lazy_invite != nullptr);
                REQUIRE(plain_invite != nullptr);
                REQUIRE(
                    object_member_as_array(*object_member_as_object(*lazy_invite, "invite_state"), "events")->size() ==
                    object_member_as_array(*object_member_as_object(*plain_invite, "invite_state"), "events")->size());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /sync, rooms.leave; Lazy-loading room members
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// A left room's `state` is "The state updates for the room up to the **start** of the timeline". That this server
// also carries the user's own leave there, when the timeline filter keeps it out of the timeline, is its own
// choice, and it makes the leave the last word on their membership. Lazy-loading adds the timeline senders' member
// events, but the user's own earlier join must not follow the leave, or a client applying `state` in order shows
// them as joined.
SCENARIO("A left room's state ends with the user's leave, not an earlier join of theirs",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("dave, bob and alice in a room, dave synced, then bob and dave speak and dave leaves")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, dave, room);
        auto const initial = sync(rt, dave, k_lazy_state);
        std::ignore = say(rt, bob, room, "b1");
        std::ignore = say(rt, bob, room, "b2");
        std::ignore = say(rt, dave, room, "d1");
        std::ignore = say(rt, bob, room, "b3");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room + "/leave", dave, "{}").status == 200U);

        // The leave is not a timeline event for this filter, so it travels in `state`.
        auto const left_room = [&](std::string_view timeline_limit) {
            auto const filter = std::string{R"({"room":{"include_leave":true,"timeline":{"limit":)"} +
                                std::string{timeline_limit} +
                                R"(,"not_types":["m.room.member"]},"state":{"lazy_load_members":true}}})";
            auto const synced = sync(rt, dave, filter, initial.next_batch);
            auto const* section = room_section(synced, "leave", room);
            REQUIRE(section != nullptr);
            return events_of(*section, "state");
        };
        // The membership of every m.room.member event naming `member` in `state`, in order.
        auto const memberships_of = [](std::vector<merovingian::canonicaljson::Object> const& state,
                                       std::string const& member) {
            auto out = std::vector<std::string>{};
            for (auto const& event : state)
            {
                auto const* key = string_member(event, "state_key");
                auto const* type = string_member(event, "type");
                auto const* content = object_member_as_object(event, "content");
                if (type != nullptr && *type == "m.room.member" && key != nullptr && *key == member)
                {
                    out.push_back(*string_member(*content, "membership"));
                }
            }
            return out;
        };

        WHEN("the incremental sync's timeline holds every event")
        {
            auto const state = left_room("50");

            THEN("dave's membership appears once, as the leave, and bob's member event is still sent")
            {
                REQUIRE(memberships_of(state, user_id("dave")) == std::vector<std::string>{"leave"});
                REQUIRE(member_keys(state).contains(user_id("bob")));
            }
        }
        WHEN("the incremental sync's timeline is limited but still holds dave's message")
        {
            auto const state = left_room("2");

            THEN("dave's membership appears once, as the leave, and bob's member event is still sent")
            {
                REQUIRE(memberships_of(state, user_id("dave")) == std::vector<std::string>{"leave"});
                REQUIRE(member_keys(state).contains(user_id("bob")));
            }
        }
    }
}

// Spec: GET /rooms/{roomId}/context/{eventId}: "state ... lazy_load_members ... may contain the membership
// events for the senders of events in the chunk"; the filter's types and senders select chunk events.
SCENARIO("GET /context with lazy-loading returns only the senders' membership events",
         "[conformance][client-server][context][lazy-sync]")
{
    GIVEN("a room where bob, carol and alice each spoke, and dave joined silently before")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, dave, room);
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        std::ignore = say(rt, bob, room, "m1");
        auto const target = say(rt, carol, room, "m2");
        std::ignore = say(rt, alice, room, "m3");

        auto const context = [&](std::string_view filter) {
            auto const reply = call(rt, "GET",
                                    "/_matrix/client/v3/rooms/" + room + "/context/" + target +
                                        "?limit=2&filter=" + merovingian::core::percent_encode_path_component(filter),
                                    carol);
            REQUIRE(reply.status == 200U);
            return parse_object(reply.body);
        };
        auto const state_of = [](merovingian::canonicaljson::Object const& body) {
            auto const* state = object_member_as_array(body, "state");
            REQUIRE(state != nullptr);
            return events_of_array(*state);
        };

        WHEN("context is read with lazy_load_members")
        {
            auto const state = state_of(context(R"({"lazy_load_members":true})"));

            THEN("state holds exactly the members of the senders of before, event and after, and nothing else")
            {
                REQUIRE(state.size() == 3U);
                REQUIRE(member_keys(state) == Keys{user_id("alice"), user_id("bob"), user_id("carol")});
            }
        }
        WHEN("the chunk filter's types would exclude members")
        {
            auto const state = state_of(context(R"({"lazy_load_members":true,"types":["m.room.message"]})"));

            THEN("the members are still returned")
            {
                REQUIRE(member_keys(state) == Keys{user_id("alice"), user_id("bob"), user_id("carol")});
            }
        }
        WHEN("context is read without lazy-loading")
        {
            auto const state = state_of(context("{}"));

            THEN("the whole state is returned, as before")
            {
                REQUIRE(member_keys(state).contains(user_id("dave")));
                REQUIRE(state.size() > 4U);
            }
        }
    }
}

// Spec: Lazy-loading room members, "expected pattern": a client with display-name tab-completion "should call
// /members ... with an ?at parameter set to the /sync response's from token". The roster must be complete for the
// tokens a lazy-loaded /sync hands out (its next_batch, and the timeline's prev_batch).
SCENARIO("GET /members?at= returns the whole roster for the tokens of a lazy-loaded sync",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("dave has lazy-synced a room of four where only bob spoke last")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        join_room(rt, carol, room);
        join_room(rt, dave, room);
        std::ignore = say(rt, bob, room, "hello");
        auto const synced = sync(rt, dave, k_lazy_one_event);
        auto const* timeline = object_member_as_object(*room_section(synced, "join", room), "timeline");
        auto const prev_batch = *string_member(*timeline, "prev_batch");

        auto const roster_at = [&](std::string const& token) {
            auto const reply = call(rt, "GET",
                                    "/_matrix/client/v3/rooms/" + room +
                                        "/members?at=" + merovingian::core::percent_encode_path_component(token),
                                    dave);
            REQUIRE(reply.status == 200U);
            auto const body = parse_object(reply.body);
            auto const* chunk = object_member_as_array(body, "chunk");
            REQUIRE(chunk != nullptr);
            return member_keys(events_of_array(*chunk));
        };

        WHEN("the roster is read at the sync's next_batch or at the timeline's prev_batch")
        {
            THEN("all four members are returned")
            {
                auto const everyone = Keys{user_id("alice"), user_id("bob"), user_id("carol"), user_id("dave")};
                REQUIRE(roster_at(synced.next_batch) == everyone);
                REQUIRE(roster_at(prev_batch) == everyone);
            }
        }
    }
}

// Spec: Lazy-loading room members: the server "MAY assume that clients will remember membership events they
// have already been sent". A client may discard a room when it leaves it, so after a rejoin it may no longer
// hold a member the server acknowledged before; the tracker is not consulted for a room the user has just
// joined (ADR-0450), though the spec's redundancy permission is only ever a MAY.
SCENARIO("A rejoin sends the timeline senders' membership again although the client acknowledged it before",
         "[conformance][client-server][sync][lazy-sync]")
{
    GIVEN("alice has been sent bob's membership and has acknowledged it")
    {
        auto started = merovingian::homeserver::start_client_server(lazy_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room = create_room(rt, alice, "public_chat");
        join_room(rt, bob, room);
        std::ignore = say(rt, bob, room, "one");
        auto const first = sync(rt, alice, k_lazy_one_event);
        REQUIRE(state_members(first, "join", room).contains(user_id("bob")));
        std::ignore = say(rt, bob, room, "two");
        auto const second = sync(rt, alice, k_lazy_one_event, first.next_batch);
        REQUIRE(state_members(second, "join", room).empty());

        WHEN("alice leaves, rejoins, bob speaks, and alice syncs from her last token")
        {
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room + "/leave", alice, "{}").status == 200U);
            join_room(rt, alice, room);
            std::ignore = say(rt, bob, room, "three");
            auto const rejoined = sync(rt, alice, k_lazy_one_event, second.next_batch);

            THEN("bob's unchanged membership is in state, and so is her own")
            {
                REQUIRE(state_members(rejoined, "join", room) == Keys{user_id("alice"), user_id("bob")});
            }
        }
    }
}
