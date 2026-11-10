// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// P1 (ADR-0440). A message used to cost every local recipient a scan of all account data, a rebuilt push ruleset,
// one committed INSERT and linear scans of the global notification table, all under runtime.mutex. These scenarios
// pin the cost by rows examined and transactions committed, never by time, and pin that the results are unchanged.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentAccountData.hpp"
#include "merovingian/database/PersistentNotification.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/trust_safety/ignore_list.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto register_user(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registered.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":"DEV"})"});
    REQUIRE(login.response.status == 200U);
    return merovingian::tests::access_token_from(login.response.body);
}

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string path, std::string const& token,
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {std::move(method), std::move(path), token, std::move(body)})
        .response;
}

// Creates a public room owned by `owner_token` and has each of `joiners` join it.
[[nodiscard]] auto room_with(ClientServerRuntime& runtime, std::string const& owner_token,
                             std::vector<std::string> const& joiner_tokens) -> std::string
{
    auto const created =
        call(runtime, "POST", "/_matrix/client/v3/createRoom", owner_token, R"({"preset":"public_chat"})");
    REQUIRE(created.status == 200U);
    auto const room_id = merovingian::tests::string_field(created.body, "room_id");
    for (auto const& token : joiner_tokens)
    {
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_id, token, "{}").status == 200U);
    }
    return room_id;
}

auto send_text(ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
               std::string const& body, std::string const& txn) -> void
{
    auto const sent = call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn, token,
                           R"({"msgtype":"m.text","body":")" + body + R"("})");
    REQUIRE(sent.status == 200U);
}

[[nodiscard]] auto count_of(ClientServerRuntime const& runtime, std::string_view user) -> std::size_t
{
    return merovingian::database::list_notifications_for_user(runtime.homeserver.database.persistent_store, user)
        .size();
}

} // namespace

SCENARIO("a message notifies each recipient by their own rules and ignores, in one commit per event",
         "[homeserver][push][notifications][push-fanout][p1]")
{
    GIVEN("a room of alice, bob, carol and dave where bob mutes the word hello and carol ignores alice")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(10U, 10U, 10U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto const bob = register_user(runtime, "bob");
        auto const carol = register_user(runtime, "carol");
        auto const dave = register_user(runtime, "dave");
        auto const room_id = room_with(runtime, alice, {bob, carol, dave});
        REQUIRE(
            call(
                runtime, "PUT", "/_matrix/client/v3/pushrules/global/override/mute_hello", bob,
                R"({"actions":["dont_notify"],"conditions":[{"kind":"event_match","key":"content.body","pattern":"hello"}]})")
                .status == 200U);
        REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/user/%40carol%3Aexample.org/account_data/m.ignored_user_list",
                     carol, R"({"ignored_users":{"@alice:example.org":{}}})")
                    .status == 200U);

        WHEN("alice says hello")
        {
            send_text(runtime, alice, room_id, "hello", "t1");

            THEN("only dave is notified")
            {
                CHECK(count_of(runtime, "@bob:example.org") == 0U);
                CHECK(count_of(runtime, "@carol:example.org") == 0U);
                CHECK(count_of(runtime, "@dave:example.org") == 1U);
                CHECK(count_of(runtime, "@alice:example.org") == 0U);
                auto const listed = call(runtime, "GET", "/_matrix/client/v3/notifications", dave);
                CHECK(listed.status == 200U);
                CHECK(listed.body.find(room_id) != std::string::npos);
            }
        }

        WHEN("alice says something else")
        {
            send_text(runtime, alice, room_id, "goodbye", "t2");

            THEN("bob and dave are notified, carol still hears nothing from the user she ignores")
            {
                CHECK(count_of(runtime, "@bob:example.org") == 1U);
                CHECK(count_of(runtime, "@carol:example.org") == 0U);
                CHECK(count_of(runtime, "@dave:example.org") == 1U);
            }
        }
    }

    GIVEN("two rooms, one with a single other member and one with five")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(10U, 10U, 10U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_user(runtime, "alice");
        auto tokens = std::vector<std::string>{};
        for (auto const* name : {"u1", "u2", "u3", "u4", "u5"})
        {
            tokens.push_back(register_user(runtime, name));
        }
        auto const small_room = room_with(runtime, alice, {tokens[0]});
        auto const large_room = room_with(runtime, alice, tokens);
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("one message is sent to each")
        {
            auto const before_small = merovingian::database::committed_transaction_count(store);
            send_text(runtime, alice, small_room, "hi", "s1");
            auto const small_cost = merovingian::database::committed_transaction_count(store) - before_small;
            auto const before_large = merovingian::database::committed_transaction_count(store);
            send_text(runtime, alice, large_room, "hi", "s2");
            auto const large_cost = merovingian::database::committed_transaction_count(store) - before_large;

            THEN("both notify their members and the commits per event do not grow with the members")
            {
                CHECK(count_of(runtime, "@u1:example.org") == 2U);
                CHECK(count_of(runtime, "@u5:example.org") == 1U);
                CHECK(large_cost == small_cost);
            }
        }
    }
}
