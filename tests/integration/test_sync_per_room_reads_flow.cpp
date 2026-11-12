// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Run-3 finding C34 (ADR-0654): classic /sync reads the state, membership and receipt rows of the rooms it serves
// through the per-room indexes, never a server-wide table, and processes at most max_sync_rooms joined rooms. Cost is
// shown with the store's rows-examined counters, never time.
//
// Spec: client-server-api.md, GET /sync: the JoinedRoom `summary` carries `m.invited_member_count`.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
namespace json = merovingian::canonicaljson;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;

[[nodiscard]] auto create_room(hs::ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const created =
        hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

[[nodiscard]] auto sync_body(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& query)
    -> json::Object
{
    auto const synced =
        hs::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync" + query, token, {}}, false);
    REQUIRE(synced.response.status == 200U);
    return parse_object(synced.response.body);
}

// Rows of rooms nobody syncs: they make a scan of a server-wide table expensive and an index lookup free.
auto add_filler(hs::ClientServerRuntime& runtime, std::size_t rooms) -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    for (auto index = std::size_t{0U}; index < rooms; ++index)
    {
        auto const room = "!filler" + std::to_string(index) + ":other.example";
        store.memberships.push_back({room, "@filler:other.example", "join", 1U});
        store.state.push_back(db::PersistentStateEvent{room, "m.room.member", "@filler:other.example", "$filler"});
        store.state.push_back(db::PersistentStateEvent{room, "m.room.name", "", "$filler-name"});
        auto receipt = db::PersistentReceipt{};
        receipt.room_id = room;
        receipt.user_id = "@filler:other.example";
        receipt.event_id = "$filler";
        store.receipts.push_back(receipt);
    }
    db::rebuild_state_index(store);
    db::rebuild_membership_index(store);
    db::rebuild_key_indexes(store);
}

[[nodiscard]] auto joined_rooms(json::Object const& body) -> json::Object const*
{
    auto const* rooms = object_member_as_object(body, "rooms");
    return rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
}

} // namespace

SCENARIO("a /sync reads the rows of its own rooms, not the server-wide tables", "[sync][c34][security]")
{
    GIVEN("a user in two rooms and three thousand rows of other rooms in each of state, memberships and receipts")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const first = create_room(runtime, token);
        auto const second = create_room(runtime, token);
        add_filler(runtime, 1500U);
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("an initial sync is made")
        {
            auto const state_before = store.state_rows_examined.value();
            auto const members_before = store.membership_rows_examined.value();
            auto const receipts_before = store.receipt_rows_examined.value();
            auto const body = sync_body(runtime, token, "");

            THEN("both rooms are served from their own rows")
            {
                REQUIRE(joined_rooms(body) != nullptr);
                REQUIRE(object_member_as_object(*joined_rooms(body), first) != nullptr);
                REQUIRE(object_member_as_object(*joined_rooms(body), second) != nullptr);
                auto const state_rows = store.state_rows_examined.value() - state_before;
                REQUIRE(state_rows > 0U);
                REQUIRE(state_rows <= 400U);
                REQUIRE(store.membership_rows_examined.value() - members_before <= 400U);
                REQUIRE(store.receipt_rows_examined.value() - receipts_before <= 400U);
            }
        }

        WHEN("an idle incremental sync is made")
        {
            auto const initial = sync_body(runtime, token, "?timeout=0");
            auto const* next = merovingian::tests::string_member(initial, "next_batch");
            REQUIRE(next != nullptr);
            auto const state_before = store.state_rows_examined.value();
            auto const members_before = store.membership_rows_examined.value();
            auto const body = sync_body(runtime, token, "?timeout=0&since=" + *next);

            THEN("a room that cannot have news costs no state read, and certainly not a scan of the state table")
            {
                REQUIRE((joined_rooms(body) == nullptr || joined_rooms(body)->empty()));
                auto const state_rows = store.state_rows_examined.value() - state_before;
                REQUIRE(state_rows <= 20U);
                REQUIRE(store.membership_rows_examined.value() - members_before <= 400U);
            }
        }
    }
}

SCENARIO("a /sync counts the invited members of a room from the room's own membership rows", "[sync][c34]")
{
    GIVEN("a room with one invited user, and filler memberships elsewhere")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room = create_room(runtime, token);
        auto& store = runtime.homeserver.database.persistent_store;
        store.memberships.push_back({room, "@bob:example.org", "invite", 2U});
        db::rebuild_membership_index(store);
        add_filler(runtime, 500U);

        WHEN("an initial sync is made")
        {
            auto const body = sync_body(runtime, token, "");

            THEN("the summary reports exactly one invited member")
            {
                REQUIRE(joined_rooms(body) != nullptr);
                auto const* joined = object_member_as_object(*joined_rooms(body), room);
                REQUIRE(joined != nullptr);
                auto const* summary = object_member_as_object(*joined, "summary");
                REQUIRE(summary != nullptr);
                auto const* invited = merovingian::tests::int_member(*summary, "m.invited_member_count");
                REQUIRE(invited != nullptr);
                REQUIRE(*invited == 1);
            }
        }
    }
}

SCENARIO("a /sync does per-room work for at most max_sync_rooms joined rooms", "[sync][c34]")
{
    GIVEN("a user joined to five rooms and a limit of three")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        for (auto index = 0; index < 5; ++index)
        {
            std::ignore = create_room(runtime, token);
        }
        runtime.limits.max_sync_rooms = 3U;
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("an initial sync is made")
        {
            auto const state_before = store.state_rows_examined.value();
            auto const body = sync_body(runtime, token, "");

            THEN("three rooms are returned and only three rooms were read")
            {
                REQUIRE(joined_rooms(body) != nullptr);
                REQUIRE(joined_rooms(body)->size() == 3U);
                auto const three_rooms = store.state_rows_examined.value() - state_before;
                runtime.limits.max_sync_rooms = 5U;
                auto const five_before = store.state_rows_examined.value();
                auto const full = sync_body(runtime, token, "");
                REQUIRE(joined_rooms(full)->size() == 5U);
                REQUIRE(three_rooms < store.state_rows_examined.value() - five_before);
            }
        }
    }
}

SCENARIO("an idle incremental /sync does not count the unread events of a room it does not send", "[sync][c05]")
{
    GIVEN("a room holding events above the user's join, and a user who has synced")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room = create_room(runtime, token);
        for (auto number = 0; number < 5; ++number)
        {
            auto const sent = hs::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/n" + std::to_string(number),
                          token, R"({"msgtype":"m.text","body":"x"})"});
            REQUIRE(sent.response.status == 200U);
        }
        auto& store = runtime.homeserver.database.persistent_store;
        auto const initial_before = store.sync_unread_rows_examined.value();
        auto const initial = sync_body(runtime, token, "?timeout=0");
        auto const* next = merovingian::tests::string_member(initial, "next_batch");
        REQUIRE(next != nullptr);

        THEN("the initial sync counted the room")
        {
            REQUIRE(store.sync_unread_rows_examined.value() > initial_before);
        }

        WHEN("an incremental sync finds nothing new")
        {
            auto const before = store.sync_unread_rows_examined.value();
            auto const body = sync_body(runtime, token, "?timeout=0&since=" + *next);

            THEN("no unread row was examined")
            {
                REQUIRE((joined_rooms(body) == nullptr || joined_rooms(body)->empty()));
                REQUIRE(store.sync_unread_rows_examined.value() == before);
            }
        }
    }
}

namespace
{

// A runtime in which alice is in `rooms` rooms, with the cap set to `cap`; returns the rooms, oldest first.
struct Fixture final
{
    hs::ClientServerStartResult started{};
    std::string token{};
    std::vector<std::string> rooms{};
};

[[nodiscard]] auto make_fixture(std::size_t rooms, std::uint32_t cap) -> Fixture
{
    auto fixture = Fixture{hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U)), {}, {}};
    REQUIRE(fixture.started.started);
    fixture.token = merovingian::tests::register_and_login_alice(fixture.started.runtime);
    for (auto index = std::size_t{0U}; index < rooms; ++index)
    {
        fixture.rooms.push_back(create_room(fixture.started.runtime, fixture.token));
    }
    fixture.started.runtime.limits.max_sync_rooms = cap;
    return fixture;
}

auto send_text(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& room,
               std::string const& txn) -> void
{
    auto const sent = hs::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/" + txn, token,
                  R"({"msgtype":"m.text","body":"news"})"});
    REQUIRE(sent.response.status == 200U);
}

} // namespace

SCENARIO("a room past the room cap still gets its news on an incremental sync", "[sync][c34][security]")
{
    GIVEN("a user in eight rooms and a cap of three")
    {
        auto fixture = make_fixture(8U, 3U);
        auto& runtime = fixture.started.runtime;

        WHEN("an initial sync is made")
        {
            auto const body = sync_body(runtime, fixture.token, "");

            THEN("the three most recently active rooms are served")
            {
                auto const* joined = joined_rooms(body);
                REQUIRE(joined != nullptr);
                REQUIRE(joined->size() == 3U);
                for (auto index = std::size_t{5U}; index < 8U; ++index)
                {
                    REQUIRE(object_member_as_object(*joined, fixture.rooms[index]) != nullptr);
                }
            }
        }

        WHEN("a room that is not among the first three gets a message after the user has synced")
        {
            auto const first = sync_body(runtime, fixture.token, "");
            auto const* next = merovingian::tests::string_member(first, "next_batch");
            REQUIRE(next != nullptr);
            send_text(runtime, fixture.token, fixture.rooms[4], "late");
            auto const body = sync_body(runtime, fixture.token, "?timeout=0&since=" + *next);

            THEN("the incremental sync delivers it")
            {
                auto const* joined = joined_rooms(body);
                REQUIRE(joined != nullptr);
                REQUIRE(joined->size() == 1U);
                REQUIRE(object_member_as_object(*joined, fixture.rooms[4]) != nullptr);
            }
        }
    }
}

SCENARIO("an incremental sync's per-room work does not grow with the user's idle rooms", "[sync][c34][security]")
{
    GIVEN("one user in a single room and another in eight rooms with a cap of three, each with news in one room")
    {
        auto const work_of = [](std::size_t rooms, std::uint32_t cap) {
            auto fixture = make_fixture(rooms, cap);
            auto& runtime = fixture.started.runtime;
            auto const first = sync_body(runtime, fixture.token, "");
            auto const* next = merovingian::tests::string_member(first, "next_batch");
            REQUIRE(next != nullptr);
            send_text(runtime, fixture.token, fixture.rooms[rooms == 1U ? 0U : 4U], "late");
            auto& store = runtime.homeserver.database.persistent_store;
            auto const state_before = store.state_rows_examined.value();
            auto const receipts_before = store.receipt_rows_examined.value();
            auto const body = sync_body(runtime, fixture.token, "?timeout=0&since=" + *next);
            REQUIRE(joined_rooms(body) != nullptr);
            REQUIRE(joined_rooms(body)->size() == 1U);
            return std::pair{store.state_rows_examined.value() - state_before,
                             store.receipt_rows_examined.value() - receipts_before};
        };

        WHEN("each makes an incremental sync")
        {
            auto const single = work_of(1U, 1000U);
            auto const many = work_of(8U, 3U);

            THEN("the state rows read are the same, the idle rooms having cost nothing")
            {
                REQUIRE(single.first > 0U);
                REQUIRE(many.first == single.first);
            }
        }
    }
}
