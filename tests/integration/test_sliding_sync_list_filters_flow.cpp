// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C07: the list filters and the notification sort are answered from the request's lookups
// (ADR-0665) and still select exactly the rooms MSC4186 says.
//
// Spec: MSC4186 list `filters`: `is_dm`, `is_encrypted`, `room_types`, `not_room_types`.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
namespace json = merovingian::canonicaljson;
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

[[nodiscard]] auto call(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
                        std::string const& target, std::string const& body) -> hs::DispatchResult
{
    return hs::handle_client_server_request(rt, {method, target, token, body}, /*can_wait=*/false);
}

[[nodiscard]] auto make_room(hs::ClientServerRuntime& rt, std::string const& token, std::string const& body)
    -> std::string
{
    auto const created = call(rt, token, "POST", "/_matrix/client/v3/createRoom", body);
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

// The room IDs of one list's SYNC ops, sorted.
[[nodiscard]] auto list_rooms(json::Object const& body, std::string const& list) -> std::vector<std::string>
{
    auto rooms = std::vector<std::string>{};
    auto const* lists = object_member_as_object(body, "lists");
    REQUIRE(lists != nullptr);
    auto const* named = object_member_as_object(*lists, list);
    REQUIRE(named != nullptr);
    auto const* ops = object_member(*named, "ops");
    REQUIRE(ops != nullptr);
    for (auto const& op : std::get<json::Array>(ops->storage()))
    {
        auto const* ids = object_member(std::get<json::Object>(op.storage()), "room_ids");
        if (ids == nullptr)
        {
            continue;
        }
        for (auto const& id : std::get<json::Array>(ids->storage()))
        {
            rooms.push_back(std::get<std::string>(id.storage()));
        }
    }
    std::ranges::sort(rooms);
    return rooms;
}

[[nodiscard]] auto sorted(std::vector<std::string> rooms) -> std::vector<std::string>
{
    std::ranges::sort(rooms);
    return rooms;
}

} // namespace

SCENARIO("Sliding sync list filters select the rooms they name", "[homeserver][sliding-sync][c07][integration]")
{
    GIVEN("a user with a plain room, an encrypted room, a space and a direct message")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(rt);
        // public_chat rooms are not encrypted by default; the default private preset adds encryption.
        auto const plain = make_room(rt, token, R"({"preset":"public_chat"})");
        auto const encrypted = make_room(
            rt, token,
            R"({"preset":"public_chat","initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}]})");
        auto const space = make_room(rt, token, R"({"preset":"public_chat","creation_content":{"type":"m.space"}})");
        auto const direct = make_room(rt, token, R"({"preset":"public_chat"})");
        REQUIRE(call(rt, token, "PUT", "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
                     R"({"@bob:example.org":[")" + direct + R"("]})")
                    .response.status == 200U);

        WHEN("one request has a list for each filter and a list sorted by notification count")
        {
            auto const answered =
                call(rt, token, "POST", "/_matrix/client/unstable/org.matrix.msc4186/sync",
                     R"({"conn_id":"c","lists":{)"
                     R"("enc":{"ranges":[[0,9]],"filters":{"is_encrypted":true}},)"
                     R"("plain":{"ranges":[[0,9]],"filters":{"is_encrypted":false,"is_invite":false}},)"
                     R"("spaces":{"ranges":[[0,9]],"filters":{"room_types":["m.space"]}},)"
                     R"("rooms":{"ranges":[[0,9]],"filters":{"not_room_types":["m.space"],"is_dm":false}},)"
                     R"("dms":{"ranges":[[0,9]],"filters":{"is_dm":true}},)"
                     R"("unread":{"ranges":[[0,9]],"sort":["by_notification_count","by_recency"]}}})");
            REQUIRE(answered.response.status == 200U);
            auto const body = parse_object(answered.response.body);

            THEN("each list holds exactly the rooms its filter selects")
            {
                REQUIRE(list_rooms(body, "enc") == std::vector<std::string>{encrypted});
                REQUIRE(list_rooms(body, "plain") == sorted({plain, space, direct}));
                REQUIRE(list_rooms(body, "spaces") == std::vector<std::string>{space});
                REQUIRE(list_rooms(body, "rooms") == sorted({plain, encrypted}));
                REQUIRE(list_rooms(body, "dms") == std::vector<std::string>{direct});
                REQUIRE(list_rooms(body, "unread") == sorted({plain, encrypted, space, direct}));
            }
        }
    }
}
