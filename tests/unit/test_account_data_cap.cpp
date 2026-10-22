// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-1, sp02.account-data-unbounded-linear-scan. Every PUT of a new global
// account-data type added a row to the shared store that push fan-out (per recipient, per event)
// and every /sync scan while the runtime lock is held. Policy, as for the CSAZ-10 caps
// (ADR-0118): refuse a new type over the per-user cap with M_TOO_LARGE, store nothing, never
// evict; updating a type the user already holds is always allowed.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace
{

using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

[[nodiscard]] auto global_rows_for(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view user)
    -> std::size_t
{
    auto const& rows = runtime.homeserver.database.persistent_store.account_data;
    return static_cast<std::size_t>(std::ranges::count_if(rows, [user](auto const& row) {
        return row.user_id == user && row.room_id.empty();
    }));
}

[[nodiscard]] auto put_account_data(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                    std::string_view user_path, std::string_view type, std::string body)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime,
               {"PUT", "/_matrix/client/v3/user/" + std::string{user_path} + "/account_data/" + std::string{type},
                token, std::move(body)})
        .response;
}

[[nodiscard]] auto get_account_data(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                                    std::string_view type) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime,
               {"GET", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/" + std::string{type}, token, {}})
        .response;
}

constexpr auto alice_path = "%40alice%3Aexample.org";

} // namespace

SCENARIO("global account data is refused beyond the per-user cap, and existing types can still be updated",
         "[homeserver][client-server][account-data][limits][security][sp02]")
{
    GIVEN("a runtime capped at 2 global account-data types per user, and a logged-in user holding 2")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U, 2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        REQUIRE(put_account_data(runtime, token, alice_path, "org.example.first", R"({"n":1})").status == 200U);
        REQUIRE(put_account_data(runtime, token, alice_path, "org.example.second", R"({"n":2})").status == 200U);
        REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);

        WHEN("a third type, not yet held, is stored")
        {
            auto const refused = put_account_data(runtime, token, alice_path, "org.example.third", R"({"n":3})");

            THEN("it is refused with M_TOO_LARGE, nothing is stored and nothing is evicted")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);
                REQUIRE(get_account_data(runtime, token, "org.example.third").status == 404U);
                REQUIRE(get_account_data(runtime, token, "org.example.first").status == 200U);
            }
        }

        WHEN("a type the user already holds is updated")
        {
            auto const updated = put_account_data(runtime, token, alice_path, "org.example.first", R"({"n":10})");

            THEN("the update succeeds and the row count does not change")
            {
                REQUIRE(updated.status == 200U);
                REQUIRE(global_rows_for(runtime, "@alice:example.org") == 2U);
                auto const fetched = get_account_data(runtime, token, "org.example.first");
                REQUIRE(fetched.status == 200U);
                REQUIRE(fetched.body.find("10") != std::string::npos);
            }
        }
    }
}

namespace
{

[[nodiscard]] auto room_rows_for(merovingian::homeserver::ClientServerRuntime const& runtime, std::string_view user,
                                 std::string_view room_id) -> std::size_t
{
    auto const& rows = runtime.homeserver.database.persistent_store.account_data;
    return static_cast<std::size_t>(std::ranges::count_if(rows, [user, room_id](auto const& row) {
        return row.user_id == user && row.room_id == room_id;
    }));
}

[[nodiscard]] auto room_account_data_url(std::string_view room_id, std::string_view type) -> std::string
{
    return "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + std::string{room_id} + "/account_data/" +
           std::string{type};
}

[[nodiscard]] auto put_room_account_data(merovingian::homeserver::ClientServerRuntime& runtime,
                                         std::string const& token, std::string_view room_id, std::string_view type,
                                         std::string body) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"PUT", room_account_data_url(room_id, type), token, std::move(body)})
        .response;
}

[[nodiscard]] auto get_room_account_data(merovingian::homeserver::ClientServerRuntime& runtime,
                                         std::string const& token, std::string_view room_id, std::string_view type)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(runtime,
                                                                 {"GET", room_account_data_url(room_id, type), token, {}})
        .response;
}

[[nodiscard]] auto create_room_for(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> std::string
{
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"});
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

[[nodiscard]] auto register_and_login_bob(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("bob", "CorrectHorse7!")})
                .response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@bob:example.org"},"password":"CorrectHorse7!","device_id":"BOBDEV"})"});
    REQUIRE(login.response.status == 200U);
    return merovingian::tests::access_token_from(login.response.body);
}

} // namespace

// Conformance audit R10 (ADR-0197). Room account data is bounded twice: a user may only write it
// for a room they hold a membership in, and each room holds at most
// `max_room_account_data_per_room` distinct client-set types per user. The policy is the
// ADR-0173 one: refuse a new type with M_TOO_LARGE, store nothing, never evict, always allow an
// update of a type already held.
SCENARIO("room account data is refused beyond the per-room cap, and existing types can still be updated",
         "[homeserver][client-server][account-data][limits][security][r10]")
{
    GIVEN("a runtime capped at 2 room account-data types per room, and a user holding 2 in one of two rooms")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U, 1000U, 2U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);
        auto const room_id = create_room_for(runtime, token);
        auto const other_room_id = create_room_for(runtime, token);
        REQUIRE(put_room_account_data(runtime, token, room_id, "org.example.first", R"({"n":1})").status == 200U);
        REQUIRE(put_room_account_data(runtime, token, room_id, "org.example.second", R"({"n":2})").status == 200U);
        auto const rows_before = room_rows_for(runtime, "@alice:example.org", room_id);

        WHEN("a third type, not yet held in that room, is stored")
        {
            auto const refused = put_room_account_data(runtime, token, room_id, "org.example.third", R"({"n":3})");

            THEN("it is refused with M_TOO_LARGE, nothing is stored and nothing is evicted")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(refused.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(room_rows_for(runtime, "@alice:example.org", room_id) == rows_before);
                REQUIRE(get_room_account_data(runtime, token, room_id, "org.example.third").status == 404U);
                REQUIRE(get_room_account_data(runtime, token, room_id, "org.example.first").status == 200U);
            }
        }

        WHEN("a type the user already holds in that room is updated")
        {
            auto const updated = put_room_account_data(runtime, token, room_id, "org.example.first", R"({"n":10})");

            THEN("the update succeeds and the row count does not change")
            {
                REQUIRE(updated.status == 200U);
                REQUIRE(room_rows_for(runtime, "@alice:example.org", room_id) == rows_before);
                auto const fetched = get_room_account_data(runtime, token, room_id, "org.example.first");
                REQUIRE(fetched.status == 200U);
                REQUIRE(fetched.body.find("10") != std::string::npos);
            }
        }

        WHEN("a third type is stored in the other room")
        {
            auto const stored = put_room_account_data(runtime, token, other_room_id, "org.example.third", R"({"n":3})");

            THEN("it succeeds, because the cap is per room")
            {
                REQUIRE(stored.status == 200U);
                REQUIRE(get_room_account_data(runtime, token, other_room_id, "org.example.third").status == 200U);
            }
        }

        WHEN("the user tags the full room through the tags API")
        {
            auto const tagged = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id + "/tags/m.favourite", token,
                 R"({"order":0.5})"});

            THEN("the server-written m.tag row is not refused by the client cap")
            {
                REQUIRE(tagged.response.status == 200U);
                REQUIRE(get_room_account_data(runtime, token, room_id, "m.tag").status == 200U);
            }
        }
    }
}

SCENARIO("room account data can only be written for a room the user holds a membership in",
         "[homeserver][client-server][account-data][limits][security][r10]")
{
    GIVEN("alice, and a room created by bob that alice never joined")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login_alice(runtime);
        auto const bob = register_and_login_bob(runtime);
        auto const bobs_room = create_room_for(runtime, bob);
        auto const alices_room = create_room_for(runtime, alice);

        WHEN("alice writes account data for bob's room and for a room ID this server has never seen")
        {
            auto const foreign = put_room_account_data(runtime, alice, bobs_room, "org.example.x", R"({"x":1})");
            auto const unknown =
                put_room_account_data(runtime, alice, "!neverseen:example.org", "org.example.x", R"({"x":1})");

            THEN("both are refused with 404 M_NOT_FOUND and no row is stored")
            {
                REQUIRE(foreign.status == 404U);
                REQUIRE(foreign.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(unknown.status == 404U);
                REQUIRE(unknown.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(room_rows_for(runtime, "@alice:example.org", bobs_room) == 0U);
                REQUIRE(room_rows_for(runtime, "@alice:example.org", "!neverseen:example.org") == 0U);
            }
        }

        WHEN("alice leaves her own room and then updates its account data")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", "/_matrix/client/v3/rooms/" + alices_room + "/leave", alice, "{}"})
                        .response.status == 200U);
            auto const stored = put_room_account_data(runtime, alice, alices_room, "org.example.y", R"({"y":1})");

            THEN("the write succeeds, because a left room keeps its account data")
            {
                REQUIRE(stored.status == 200U);
                REQUIRE(get_room_account_data(runtime, alice, alices_room, "org.example.y").status == 200U);
            }
        }
    }
}
