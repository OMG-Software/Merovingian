// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /sync rooms.leave: the rooms a user has left or been banned from, each with the timeline
// "up to the point when the user left". Complement TestArchivedRoomsHistory,
// TestOlderLeftRoomsNotInLeaveSection and TestUnbanViaInvite read these.
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto archive_config() -> merovingian::config::Config
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

[[nodiscard]] auto percent_encode(std::string_view text) -> std::string
{
    auto constexpr hex = std::string_view{"0123456789ABCDEF"};
    auto out = std::string{};
    for (auto const raw : text)
    {
        auto const byte = static_cast<unsigned char>(raw);
        auto const unreserved = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                                (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.';
        if (unreserved)
        {
            out.push_back(raw);
            continue;
        }
        out.push_back('%');
        out.push_back(hex[byte >> 4U]);
        out.push_back(hex[byte & 0x0FU]);
    }
    return out;
}

struct Account final
{
    std::string user_id{};
    std::string token{};
};

[[nodiscard]] auto register_account(ClientServerRuntime& rt, std::string const& localpart) -> Account
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    auto const body = parse_object(registered.body);
    return {*string_member(body, "user_id"), *string_member(body, "access_token")};
}

[[nodiscard]] auto create_public_room(ClientServerRuntime& rt, Account const& owner) -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", owner.token, R"({"preset":"public_chat"})");
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

auto send_text(ClientServerRuntime& rt, Account const& who, std::string const& room_id, std::string const& txn,
               std::string const& body) -> void
{
    REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, who.token,
                 R"({"msgtype":"m.text","body":")" + body + R"("})")
                .status == 200U);
}

// One /sync response: the parsed body and its next_batch.
struct Synced final
{
    merovingian::canonicaljson::Object body{};
    std::string next_batch{};
};

[[nodiscard]] auto sync_with(ClientServerRuntime& rt, Account const& who, std::string_view filter_json,
                             std::string const& since = {}) -> Synced
{
    auto target = std::string{"/_matrix/client/v3/sync?filter="} + percent_encode(filter_json);
    if (!since.empty())
    {
        target += "&since=" + percent_encode(since);
    }
    auto const reply = call(rt, "GET", target, who.token);
    REQUIRE(reply.status == 200U);
    auto body = parse_object(reply.body);
    auto const* next_batch = string_member(body, "next_batch");
    REQUIRE(next_batch != nullptr);
    auto const batch = *next_batch;
    return {std::move(body), batch};
}

[[nodiscard]] auto leave_section(Synced const& synced) -> merovingian::canonicaljson::Object const&
{
    auto const* rooms = object_member_as_object(synced.body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* leave = object_member_as_object(*rooms, "leave");
    REQUIRE(leave != nullptr);
    return *leave;
}

// The `type`/`body`-or-`membership` summary of each event under `section.events`, in order.
[[nodiscard]] auto event_summaries(merovingian::canonicaljson::Object const& section) -> std::vector<std::string>
{
    auto summaries = std::vector<std::string>{};
    auto const* events = object_member_as_array(section, "events");
    REQUIRE(events != nullptr);
    for (auto const& entry : *events)
    {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* type = string_member(event, "type");
        auto const* content = object_member_as_object(event, "content");
        REQUIRE(type != nullptr);
        REQUIRE(content != nullptr);
        auto const* text = string_member(*content, "body");
        auto const* membership = string_member(*content, "membership");
        auto const* state_key = string_member(event, "state_key");
        if (text != nullptr)
        {
            summaries.push_back(*type + ":" + *text);
        }
        else if (membership != nullptr && state_key != nullptr)
        {
            summaries.push_back(*type + ":" + *state_key + ":" + *membership);
        }
        else
        {
            summaries.push_back(*type);
        }
    }
    return summaries;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, LeftRoom `timeline`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// LeftRoom `timeline`: "The timeline of messages and state changes in the room up to the point
// when the user left." The RoomEventFilter's `types` selects what the timeline holds, and
// `limit` ("The maximum number of events to return") bounds it; LeftRoom `state`: "The state
// updates for the room up to the start of the timeline."
SCENARIO("A left room's timeline holds the filtered events up to the leave and none after it",
         "[conformance][client-server][sync][sync-archive]")
{
    GIVEN("a room bob joined, wrote in before leaving, and in which alice wrote after he left")
    {
        auto started = merovingian::homeserver::start_client_server(archive_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_account(rt, "alice");
        auto const bob = register_account(rt, "bob");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob.token, "{}").status == 200U);

        auto constexpr filter =
            std::string_view{R"({"room":{"timeline":{"types":["m.room.message","a.madeup.test.state"]},)"
                             R"("state":{"types":["a.madeup.test.state"]},"include_leave":true}})"};
        auto const since = sync_with(rt, bob, filter).next_batch;

        send_text(rt, alice, room_id, "t1", "before");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/a.madeup.test.state/", alice.token,
                     R"({"my_key":"before"})")
                    .status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob.token, "{}").status == 200U);
        send_text(rt, alice, room_id, "t2", "after");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/a.madeup.test.state/", alice.token,
                     R"({"my_key":"after"})")
                    .status == 200U);

        auto const expected = std::vector<std::string>{"m.room.message:before", "a.madeup.test.state"};
        auto const check = [&](Synced const& synced) {
            auto const* room = object_member_as_object(leave_section(synced), room_id);
            REQUIRE(room != nullptr);
            auto const* timeline = object_member_as_object(*room, "timeline");
            REQUIRE(timeline != nullptr);
            // Spec MUST: the timeline is the filtered events up to the point when the user left.
            REQUIRE(event_summaries(*timeline) == expected);
            auto const* state = object_member_as_object(*room, "state");
            REQUIRE(state != nullptr);
            // Spec MUST: state is "up to the start of the timeline", which precedes both events.
            REQUIRE(event_summaries(*state).empty());
        };

        WHEN("bob syncs for the first time with include_leave")
        {
            THEN("the room's timeline is the two events from before bob left")
            {
                check(sync_with(rt, bob, filter));
            }
        }

        WHEN("bob syncs from before he left")
        {
            THEN("the room's timeline is the two events from before bob left")
            {
                check(sync_with(rt, bob, filter, since));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, LeftRoom `timeline` and `state`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// A `limit` of 0 asks for no timeline events ("The maximum number of events to return"), so
// the state "up to the start of the timeline" is all the state up to the leave, the leave
// included.
SCENARIO("A left room with an empty timeline reports its state as of the leave",
         "[conformance][client-server][sync][sync-archive]")
{
    GIVEN("a room bob left after a state event, with another state event sent afterwards")
    {
        auto started = merovingian::homeserver::start_client_server(archive_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_account(rt, "alice");
        auto const bob = register_account(rt, "bob");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob.token, "{}").status == 200U);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/a.madeup.test.state/", alice.token,
                     R"({"my_key":"before"})")
                    .status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob.token, "{}").status == 200U);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/a.madeup.test.state/", alice.token,
                     R"({"my_key":"after"})")
                    .status == 200U);

        WHEN("bob syncs with include_leave and a timeline limit of 0")
        {
            auto const synced = sync_with(rt, bob, R"({"room":{"timeline":{"limit":0},"include_leave":true}})");
            auto const* room = object_member_as_object(leave_section(synced), room_id);
            REQUIRE(room != nullptr);
            auto const* timeline = object_member_as_object(*room, "timeline");
            auto const* state = object_member_as_object(*room, "state");
            REQUIRE(timeline != nullptr);
            REQUIRE(state != nullptr);

            THEN("the timeline is empty and the state holds the leave and the earlier state only")
            {
                // Spec MUST: a limit of 0 returns no events.
                REQUIRE(event_summaries(*timeline).empty());
                // Spec MUST: state is "up to the start of the timeline", here the point of leaving.
                auto const summaries = event_summaries(*state);
                auto found_leave = false;
                for (auto const& summary : summaries)
                {
                    found_leave = found_leave || summary == "m.room.member:" + bob.user_id + ":leave";
                }
                REQUIRE(found_leave);
                auto const* events = object_member_as_array(*state, "events");
                REQUIRE(events != nullptr);
                auto before_seen = false;
                for (auto const& entry : *events)
                {
                    auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
                    auto const* type = string_member(event, "type");
                    auto const* content = object_member_as_object(event, "content");
                    if (type != nullptr && *type == "a.madeup.test.state" && content != nullptr)
                    {
                        auto const* key = string_member(*content, "my_key");
                        REQUIRE(key != nullptr);
                        // Spec MUST: nothing from after the user left.
                        REQUIRE(*key == "before");
                        before_seen = true;
                    }
                }
                REQUIRE(before_seen);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, `rooms.leave`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `leave`: "The rooms that the user has left or been banned from". A leave the client has
// been told of is not told again: the response's `next_batch` starts after it.
SCENARIO("A room whose leave was already reported does not come back in the leave section",
         "[conformance][client-server][sync][sync-archive]")
{
    GIVEN("a room alice left and has been told so, and later activity in that and another room")
    {
        auto started = merovingian::homeserver::start_client_server(archive_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_account(rt, "alice");
        auto const bob = register_account(rt, "bob");
        auto const room_to_leave = create_public_room(rt, alice);
        auto const room_to_spam = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_to_leave, bob.token, "{}").status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_to_spam, bob.token, "{}").status == 200U);

        auto constexpr filter = std::string_view{R"({"room":{"timeline":{"limit":1},"include_leave":true}})"};
        auto const first = sync_with(rt, alice, filter);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_to_leave + "/leave", alice.token, "{}").status ==
                200U);
        auto const reported = sync_with(rt, alice, filter, first.next_batch);
        REQUIRE(object_member_as_object(leave_section(reported), room_to_leave) != nullptr);

        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_to_leave + "/state/m.room.member/" + bob.user_id,
                     bob.token, R"({"membership":"join","filler":"Welcome back"})")
                    .status == 200U);
        for (auto index = 0; index < 5; ++index)
        {
            send_text(rt, bob, room_to_spam, "s" + std::to_string(index), "Mr Anderson");
        }

        WHEN("alice syncs from the response that reported her leave")
        {
            auto const synced = sync_with(rt, alice, filter, reported.next_batch);

            THEN("no room is in the leave section")
            {
                // Spec MUST: a leave the client was told of is not reported again.
                REQUIRE(leave_section(synced).empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, `rooms.leave`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `leave`: "The rooms that the user has left or been banned from, mapped as room ID to room
// information." A banned user's room is in `leave`, with the ban as the last timeline event.
SCENARIO("A room the user was banned from is in the leave section", "[conformance][client-server][sync][sync-archive]")
{
    GIVEN("a room bob joined and alice then banned him from")
    {
        auto started = merovingian::homeserver::start_client_server(archive_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_account(rt, "alice");
        auto const bob = register_account(rt, "bob");
        auto const room_id = create_public_room(rt, alice);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room_id, bob.token, "{}").status == 200U);
        auto const before = sync_with(rt, bob, "{}");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", alice.token,
                     R"({"user_id":")" + bob.user_id + R"("})")
                    .status == 200U);

        WHEN("bob syncs from before the ban, without include_leave")
        {
            auto const synced = sync_with(rt, bob, "{}", before.next_batch);

            THEN("the room is in the leave section and its timeline ends with the ban")
            {
                // Spec MUST: `leave` holds "the rooms that the user has left or been banned from".
                auto const* room = object_member_as_object(leave_section(synced), room_id);
                REQUIRE(room != nullptr);
                auto const* timeline = object_member_as_object(*room, "timeline");
                REQUIRE(timeline != nullptr);
                auto const summaries = event_summaries(*timeline);
                REQUIRE_FALSE(summaries.empty());
                REQUIRE(summaries.back() == "m.room.member:" + bob.user_id + ":ban");
            }
        }

        WHEN("bob syncs for the first time with include_leave")
        {
            auto const synced = sync_with(rt, bob, R"({"room":{"include_leave":true}})");

            THEN("the room is in the leave section")
            {
                REQUIRE(object_member_as_object(leave_section(synced), room_id) != nullptr);
            }
        }
    }
}
