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

using merovingian::database::PersistentAccountData;
using merovingian::database::PersistentNotification;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto notification_for(std::string user, std::string event, std::uint64_t order) -> PersistentNotification
{
    return PersistentNotification{
        std::move(user), "!room:example.org", std::move(event), order, 1U, "[\"notify\"]", std::string{}, false};
}

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

SCENARIO("a notification batch commits once and prunes each user's history in the same transaction",
         "[database][notifications][push-fanout][p1]")
{
    GIVEN("a store where alice already holds two notifications and the cap is two")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(10U, 10U, 10U));
        REQUIRE(started.started);
        auto& store = started.runtime.homeserver.database.persistent_store;
        REQUIRE(
            merovingian::database::store_notification(store, notification_for("@alice:example.org", "$a1", 1U), 2U));
        REQUIRE(
            merovingian::database::store_notification(store, notification_for("@alice:example.org", "$a2", 2U), 2U));

        WHEN("one batch adds a row for alice and rows for three other users")
        {
            auto const commits_before = merovingian::database::committed_transaction_count(store);
            auto batch = std::vector<PersistentNotification>{};
            batch.push_back(notification_for("@alice:example.org", "$a3", 3U));
            batch.push_back(notification_for("@bob:example.org", "$a3", 3U));
            batch.push_back(notification_for("@carol:example.org", "$a3", 3U));
            batch.push_back(notification_for("@dave:example.org", "$a3", 3U));
            REQUIRE(merovingian::database::store_notifications(store, std::move(batch), 2U));

            THEN("the whole batch, prune included, is one committed transaction")
            {
                CHECK(merovingian::database::committed_transaction_count(store) - commits_before == 1U);
            }
            THEN("alice keeps her newest two rows and every other user has theirs")
            {
                auto const alice = merovingian::database::list_notifications_for_user(store, "@alice:example.org");
                REQUIRE(alice.size() == 2U);
                CHECK(alice.front().event_id == "$a2");
                CHECK(alice.back().event_id == "$a3");
                CHECK(count_of(started.runtime, "@bob:example.org") == 1U);
                CHECK(count_of(started.runtime, "@carol:example.org") == 1U);
                CHECK(count_of(started.runtime, "@dave:example.org") == 1U);
            }
        }

        WHEN("the commit of a batch fails")
        {
            auto const alice_before = merovingian::database::list_notifications_for_user(store, "@alice:example.org");
            merovingian::database::force_next_persist_failures(store, 1U);
            auto batch = std::vector<PersistentNotification>{};
            batch.push_back(notification_for("@alice:example.org", "$a3", 3U));
            batch.push_back(notification_for("@bob:example.org", "$a3", 3U));
            auto const stored = merovingian::database::store_notifications(store, std::move(batch), 2U);

            THEN("nothing is half written: memory still equals the database")
            {
                CHECK_FALSE(stored);
                auto const alice_after =
                    merovingian::database::list_notifications_for_user(store, "@alice:example.org");
                REQUIRE(alice_after.size() == alice_before.size());
                CHECK(alice_after.front().event_id == alice_before.front().event_id);
                CHECK(alice_after.back().event_id == alice_before.back().event_id);
                CHECK(count_of(started.runtime, "@bob:example.org") == 0U);
            }
        }

        WHEN("a batch holds a row with no event ID")
        {
            auto batch = std::vector<PersistentNotification>{};
            batch.push_back(notification_for("@bob:example.org", "$ok", 5U));
            batch.push_back(notification_for("@carol:example.org", "", 6U));

            THEN("it is refused whole")
            {
                CHECK_FALSE(merovingian::database::store_notifications(store, std::move(batch), 2U));
                CHECK(count_of(started.runtime, "@bob:example.org") == 0U);
            }
        }
    }
}

SCENARIO("looking up one user's account data does not examine other users' rows",
         "[database][account-data][push-fanout][p1]")
{
    GIVEN("a store holding three account-data rows for each of two hundred users")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(10U, 10U, 10U));
        REQUIRE(started.started);
        auto& store = started.runtime.homeserver.database.persistent_store;
        for (auto user = 0; user < 200; ++user)
        {
            auto const user_id = "@user" + std::to_string(user) + ":example.org";
            for (auto const* type : {"org.example.a", "org.example.b", "m.ignored_user_list"})
            {
                REQUIRE(merovingian::database::store_account_data(
                    store, PersistentAccountData{user_id, std::string{}, type, R"({"ignored_users":{}})", 1U}));
            }
        }

        WHEN("one user's ignore list and one user's row are resolved")
        {
            auto const before = store.account_data_rows_examined.value();
            auto const ignored = merovingian::trust_safety::resolve_ignored_users(store, "@user7:example.org");
            auto const content =
                merovingian::database::find_account_data_content(store, "@user9:example.org", "", "org.example.b");
            auto const examined = store.account_data_rows_examined.value() - before;

            THEN("only those users' rows were examined, and the answers are right")
            {
                CHECK(ignored.empty());
                CHECK(content.has_value());
                CHECK(examined <= 6U);
            }
        }

        WHEN("a row is replaced and a user with no rows is looked up")
        {
            REQUIRE(merovingian::database::store_account_data(
                store, PersistentAccountData{"@user7:example.org", std::string{}, "m.ignored_user_list",
                                             R"({"ignored_users":{"@spam:example.org":{}}})", 2U}));
            auto const ignored = merovingian::trust_safety::resolve_ignored_users(store, "@user7:example.org");
            auto const none = merovingian::database::find_account_data_content(store, "@nobody:example.org", "",
                                                                               "m.ignored_user_list");

            THEN("the new content is read, the table did not grow, and the stranger has nothing")
            {
                CHECK(ignored.contains("@spam:example.org"));
                CHECK(store.account_data.size() == 600U);
                CHECK_FALSE(none.has_value());
            }
        }
    }
}

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
