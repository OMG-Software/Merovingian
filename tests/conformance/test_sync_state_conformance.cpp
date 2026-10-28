// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /sync rooms.join.<roomId>.state on an initial sync is the room's state up to the start of
// the timeline, not its current state: a state event the timeline carries is not repeated in
// `state` with its later value. Complement TestKnocking, "Users in the room see a user's
// membership update when they knock", read the second knock from `state` before the first in
// the timeline.
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

[[nodiscard]] auto sync_state_config() -> merovingian::config::Config
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

// The `content.topic` of every m.room.topic event in `events`.
[[nodiscard]] auto topics_in(merovingian::canonicaljson::Object const& section) -> std::vector<std::string>
{
    auto topics = std::vector<std::string>{};
    auto const* events = object_member_as_array(section, "events");
    REQUIRE(events != nullptr);
    for (auto const& entry : *events)
    {
        auto const& event = std::get<merovingian::canonicaljson::Object>(entry.storage());
        auto const* type = string_member(event, "type");
        auto const* content = object_member_as_object(event, "content");
        auto const* topic = content == nullptr ? nullptr : string_member(*content, "topic");
        if (type != nullptr && *type == "m.room.topic" && topic != nullptr)
        {
            topics.emplace_back(*topic);
        }
    }
    return topics;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, JoinedRoom `state`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `state`: "Updates to the state, between the time indicated by the since parameter, and the
// start of the timeline (or all state up to the start of the timeline, if since is not given,
// or full_state is true)."
SCENARIO("An initial sync's room state is the state at the start of the timeline",
         "[conformance][client-server][sync][sync-state]")
{
    GIVEN("a room whose topic changed before and inside the last two events")
    {
        auto started = merovingian::homeserver::start_client_server(sync_state_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const registered =
            call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!"));
        REQUIRE(registered.status == 200U);
        auto const token = *string_member(parse_object(registered.body), "access_token");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, "{}");
        REQUIRE(created.status == 200U);
        auto const room_id = *string_member(parse_object(created.body), "room_id");
        auto const room_path = "/_matrix/client/v3/rooms/" + room_id;
        REQUIRE(call(rt, "PUT", room_path + "/state/m.room.topic/", token, R"({"topic":"first"})").status == 200U);
        REQUIRE(call(rt, "PUT", room_path + "/send/m.room.message/m1", token, R"({"msgtype":"m.text","body":"a"})")
                    .status == 200U);
        REQUIRE(call(rt, "PUT", room_path + "/state/m.room.topic/", token, R"({"topic":"second"})").status == 200U);
        REQUIRE(call(rt, "PUT", room_path + "/send/m.room.message/m2", token, R"({"msgtype":"m.text","body":"b"})")
                    .status == 200U);

        WHEN("alice syncs with a timeline of two events")
        {
            // {"room":{"timeline":{"limit":2}}}
            auto const synced =
                call(rt, "GET",
                     "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A2%7D%7D%7D",
                     token);
            REQUIRE(synced.status == 200U);
            auto const body = parse_object(synced.body);
            auto const* rooms = object_member_as_object(body, "rooms");
            REQUIRE(rooms != nullptr);
            auto const* join = object_member_as_object(*rooms, "join");
            REQUIRE(join != nullptr);
            auto const* room = object_member_as_object(*join, room_id);
            REQUIRE(room != nullptr);
            auto const* timeline = object_member_as_object(*room, "timeline");
            auto const* state = object_member_as_object(*room, "state");
            REQUIRE(timeline != nullptr);
            REQUIRE(state != nullptr);

            THEN("the timeline carries the second topic and the state the first, not the second")
            {
                // Spec MUST: the timeline is the last two events.
                REQUIRE(topics_in(*timeline) == std::vector<std::string>{"second"});
                // Spec MUST: state is "all state up to the start of the timeline".
                REQUIRE(topics_in(*state) == std::vector<std::string>{"first"});
            }
        }
    }
}
