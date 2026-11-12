// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run 3, finding C08: a sliding sync room timeline is built from the newest row and stops after
// max_timeline_rows_skipped rows not taken (ADR-0616, ADR-0664), however long the room's hidden history is.
//
// Spec: MSC4186 `limited` ("more events ... than were included in the timeline") and `prev_batch` ("a /messages
// `from` that pages back"); the Ignoring Users section withholds an ignored sender's events from the timeline.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/sync/TimelineWindow.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>

namespace
{

namespace hs = merovingian::homeserver;
namespace json = merovingian::canonicaljson;
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

// A config whose rate limits admit the thousand-odd sends the scenario makes from one address.
[[nodiscard]] auto many_sends_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto limits = merovingian::config::ClientRateLimitsConfig{};
    limits.default_per_ip = merovingian::http::RateLimitPolicy{100'000U, 60U};
    limits.tier["generic"] = merovingian::http::RateLimitPolicy{100'000U, 60U};
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        limits,
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto send(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
                        std::string const& target, std::string const& body) -> hs::DispatchResult
{
    return hs::handle_client_server_request(rt, {method, target, token, body}, /*can_wait=*/false);
}

auto send_messages(hs::ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::size_t count,
                   std::string const& prefix) -> void
{
    for (auto number = std::size_t{0U}; number < count; ++number)
    {
        auto const label = prefix + std::to_string(number);
        auto const sent =
            send(rt, token, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + label,
                 R"({"msgtype":"m.text","body":")" + label + R"("})");
        REQUIRE(sent.response.status == 200U);
    }
}

// Sliding sync with a fresh connection that subscribes to the room with a timeline_limit of 2.
[[nodiscard]] auto subscribe(hs::ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                             std::string const& conn_id) -> json::Object
{
    auto const answered =
        send(rt, token, "POST", "/_matrix/client/unstable/org.matrix.msc4186/sync",
             R"({"conn_id":")" + conn_id + R"(","room_subscriptions":{")" + room_id + R"(":{"timeline_limit":2}}})");
    REQUIRE(answered.response.status == 200U);
    auto const body = parse_object(answered.response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* room = object_member_as_object(*rooms, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

[[nodiscard]] auto timeline_size(json::Object const& room) -> std::size_t
{
    auto const* timeline = object_member(room, "timeline");
    return timeline == nullptr ? std::size_t{0U} : std::get<json::Array>(timeline->storage()).size();
}

[[nodiscard]] auto flag(json::Object const& room, std::string_view name) -> bool
{
    auto const* value = object_member(room, name);
    return value != nullptr && std::get<bool>(value->storage());
}

} // namespace

SCENARIO("A sliding sync timeline does not walk a room's hidden history", "[sync][sliding-sync][integration][c08]")
{
    GIVEN("a room whose newest 1,100 events were sent by a user the caller ignores")
    {
        auto started = hs::start_client_server(many_sends_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = merovingian::tests::register_and_login_alice(rt);
        auto const registered_bob = send(rt, {}, "POST", "/_matrix/client/v3/register",
                                         merovingian::tests::registration_json("bob", "CorrectHorse7!"));
        REQUIRE(registered_bob.response.status == 200U);
        auto const bob = merovingian::tests::access_token_from(registered_bob.response.body);

        auto const created = send(rt, bob, "POST", "/_matrix/client/v3/createRoom", R"({"preset":"public_chat"})");
        REQUIRE(created.response.status == 200U);
        auto const room_id = merovingian::tests::string_field(created.response.body, "room_id");
        REQUIRE(send(rt, alice, "POST", "/_matrix/client/v3/join/" + room_id, "{}").response.status == 200U);
        send_messages(rt, alice, room_id, 1U, "own");
        REQUIRE(send(rt, alice, "PUT", "/_matrix/client/v3/user/@alice:example.org/account_data/m.ignored_user_list",
                     R"({"ignored_users":{"@bob:example.org":{}}})")
                    .response.status == 200U);
        send_messages(rt, bob, room_id, 1100U, "hidden");
        auto& store = rt.homeserver.database.persistent_store;

        WHEN("the caller's fresh connection subscribes to the room")
        {
            auto const before = store.sync_timeline_rows_examined.value();
            auto const room = subscribe(rt, alice, room_id, "c1");
            auto const examined = store.sync_timeline_rows_examined.value() - before;

            THEN("the walk stops at the skip budget, takes nothing and says it may have left events out")
            {
                REQUIRE(examined == merovingian::sync::max_timeline_rows_skipped);
                REQUIRE(timeline_size(room) == 0U);
                REQUIRE(flag(room, "limited"));
                REQUIRE(object_member(room, "prev_batch") != nullptr);
            }
        }
        WHEN("the same room has far more hidden events and a second fresh connection subscribes")
        {
            send_messages(rt, bob, room_id, 200U, "more");
            auto const before = store.sync_timeline_rows_examined.value();
            std::ignore = subscribe(rt, alice, room_id, "c2");
            auto const examined = store.sync_timeline_rows_examined.value() - before;

            THEN("the rows examined are the same budget, not more")
            {
                REQUIRE(examined == merovingian::sync::max_timeline_rows_skipped);
            }
        }
    }

    GIVEN("a room where the caller can see the newest events")
    {
        auto started = hs::start_client_server(many_sends_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = merovingian::tests::register_and_login_alice(rt);
        auto const created = send(rt, alice, "POST", "/_matrix/client/v3/createRoom", R"({"preset":"private_chat"})");
        REQUIRE(created.response.status == 200U);
        auto const room_id = merovingian::tests::string_field(created.response.body, "room_id");
        send_messages(rt, alice, room_id, 5U, "visible");

        WHEN("a fresh connection subscribes with a timeline_limit of 2")
        {
            auto const room = subscribe(rt, alice, room_id, "c1");

            THEN("the newest 2 events are returned and the room is limited")
            {
                REQUIRE(timeline_size(room) == 2U);
                REQUIRE(flag(room, "limited"));
            }
        }
    }
}
