// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C39 (ADR-0656): GET /rooms/{id}/context and GET /rooms/{id}/initialSync examine at most
// max_messages_events_examined rows, as /messages does, and hand back tokens at the last row examined; they no longer
// copy the room's events before walking them.
//
// Spec: client-server-api.md, GET /rooms/{roomId}/context/{eventId}: "start" and "end" are tokens that can be used
// with /messages to paginate backwards and forwards.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
namespace json = merovingian::canonicaljson;
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

struct Room final
{
    std::string id{};
    std::vector<std::string> events{};
};

// A room with `messages` messages by alice, oldest first in `events`.
[[nodiscard]] auto make_room(hs::ClientServerRuntime& runtime, std::string const& token, std::size_t messages) -> Room
{
    auto room = Room{};
    auto const created =
        hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(created.response.status == 200U);
    room.id = merovingian::tests::string_field(created.response.body, "room_id");
    for (auto number = std::size_t{0U}; number < messages; ++number)
    {
        auto const sent = hs::handle_client_server_request(
            runtime, {"PUT", "/_matrix/client/v3/rooms/" + room.id + "/send/m.room.message/m" + std::to_string(number),
                      token, R"({"msgtype":"m.text","body":"m)" + std::to_string(number) + R"("})"});
        REQUIRE(sent.response.status == 200U);
        room.events.push_back(merovingian::tests::string_field(sent.response.body, "event_id"));
    }
    return room;
}

// Marks the events as rejected, which clients never see, so a walk has to step over them.
auto reject(hs::ClientServerRuntime& runtime, std::vector<std::string> const& event_ids) -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    for (auto const& event_id : event_ids)
    {
        auto const row = store.events.find(event_id);
        REQUIRE(row != store.events.end());
        store.events.modify(row, [](db::PersistentEvent& event) {
            event.status = "rejected";
        });
    }
}

[[nodiscard]] auto count_of(json::Object const& body, std::string_view key) -> std::size_t
{
    auto const* value = object_member(body, key);
    REQUIRE(value != nullptr);
    return std::get<json::Array>(value->storage()).size();
}

} // namespace

SCENARIO("/context stops at its examination budget when the neighbouring rows are hidden", "[room][context][c39]")
{
    GIVEN("a room whose 150 events after the target are all rejected, followed by 3 visible ones")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room = make_room(runtime, token, 154U);
        reject(runtime, std::vector<std::string>(room.events.begin() + 1, room.events.begin() + 151));
        auto const request = "/_matrix/client/v3/rooms/" + room.id + "/context/" + room.events.front() + "?limit=10";

        WHEN("the examination budget is 50 rows")
        {
            runtime.limits.max_messages_events_examined = 50U;
            auto const response = hs::handle_client_server_request(runtime, {"GET", request, token, {}});

            THEN("no event after the target is returned, and the end token stands at the last row examined")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(count_of(body, "events_after") == 0U);
                auto const* end = string_member(body, "end");
                REQUIRE(end != nullptr);
                REQUIRE(*end != std::string{});
            }
        }

        WHEN("the budget covers the hidden rows")
        {
            runtime.limits.max_messages_events_examined = 1000U;
            auto const response = hs::handle_client_server_request(runtime, {"GET", request, token, {}});

            THEN("the visible events beyond them are returned")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                REQUIRE(count_of(body, "events_after") == 3U);
            }
        }
    }
}

SCENARIO("/initialSync stops at its examination budget when the newest rows are hidden", "[room][initialsync][c39]")
{
    GIVEN("a room whose 150 newest events are rejected, with 10 visible ones before them")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room = make_room(runtime, token, 160U);
        reject(runtime, std::vector<std::string>(room.events.begin() + 10, room.events.end()));
        auto const request = "/_matrix/client/v3/rooms/" + room.id + "/initialSync?limit=5";

        auto const messages_of = [](hs::LocalHttpResponse const& response) {
            auto const body = parse_object(response.body);
            auto const* messages = object_member_as_object(body, "messages");
            REQUIRE(messages != nullptr);
            return count_of(*messages, "chunk");
        };

        WHEN("the examination budget is 50 rows")
        {
            runtime.limits.max_messages_events_examined = 50U;
            auto const response = hs::handle_client_server_request(runtime, {"GET", request, token, {}}).response;

            THEN("the page is empty: the walk stopped at the budget")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(messages_of(response) == 0U);
            }
        }

        WHEN("the budget covers the hidden rows")
        {
            runtime.limits.max_messages_events_examined = 1000U;
            auto const response = hs::handle_client_server_request(runtime, {"GET", request, token, {}}).response;

            THEN("the newest visible events are returned")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(messages_of(response) == 5U);
            }
        }
    }
}
