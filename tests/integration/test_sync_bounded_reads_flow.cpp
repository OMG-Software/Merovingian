// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, classic /sync: the work of one request is its own user's rows and its timeline window, not
// the room's history or other users' rows (ADR-0616, ADR-0618).
//
// Spec: client-server-api.md, GET /sync: `limited` is "True if the number of events returned was limited by the
// limit on the filter", and `prev_batch` is "A token that can be supplied to the from parameter of the
// /rooms/<room_id>/messages endpoint in order to retrieve earlier events".

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentAccountData.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
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

constexpr auto alice = std::string_view{"@alice:example.org"};

[[nodiscard]] auto make_runtime() -> hs::ClientServerStartResult
{
    auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
    REQUIRE(started.started);
    return started;
}

[[nodiscard]] auto create_room(hs::ClientServerRuntime& runtime, std::string const& token) -> std::string
{
    auto const created =
        hs::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

auto send_messages(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
                   std::size_t first, std::size_t count) -> void
{
    for (auto number = first; number < first + count; ++number)
    {
        auto const label = std::to_string(number);
        auto const sent = hs::handle_client_server_request(
            runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t" + label, token,
                      R"({"msgtype":"m.text","body":"m)" + label + R"("})"});
        REQUIRE(sent.response.status == 200U);
    }
}

[[nodiscard]] auto sync_with(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& query)
    -> json::Object
{
    auto const synced =
        hs::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync" + query, token, {}}, false);
    REQUIRE(synced.response.status == 200U);
    return parse_object(synced.response.body);
}

[[nodiscard]] auto joined_room(json::Object const& body, std::string const& room_id) -> json::Object const&
{
    auto const* rooms = object_member_as_object(body, "rooms");
    REQUIRE(rooms != nullptr);
    auto const* join = object_member_as_object(*rooms, "join");
    REQUIRE(join != nullptr);
    auto const* room = object_member_as_object(*join, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

// Bodies of the messages in a room's timeline, oldest first.
[[nodiscard]] auto timeline_bodies(json::Object const& timeline) -> std::vector<std::string>
{
    auto bodies = std::vector<std::string>{};
    auto const* events = object_member(timeline, "events");
    REQUIRE(events != nullptr);
    for (auto const& entry : std::get<json::Array>(events->storage()))
    {
        auto const& event = std::get<json::Object>(entry.storage());
        auto const* content = object_member_as_object(event, "content");
        auto const* body = content == nullptr ? nullptr : string_member(*content, "body");
        if (body != nullptr)
        {
            bodies.push_back(*body);
        }
    }
    return bodies;
}

[[nodiscard]] auto is_limited(json::Object const& timeline) -> bool
{
    auto const* limited = object_member(timeline, "limited");
    REQUIRE(limited != nullptr);
    return std::get<bool>(limited->storage());
}

constexpr auto limit_three = std::string_view{R"(?filter={"room":{"timeline":{"limit":3}}})"};

} // namespace

SCENARIO("a /sync timeline reads the newest rows of the room, and stops at the limit",
         "[sync][timeline][security][gate-m-sync]")
{
    GIVEN("a room with sixty messages")
    {
        auto started = make_runtime();
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto const room_id = create_room(runtime, token);
        send_messages(runtime, token, room_id, 0U, 60U);
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("an initial sync asks for three events")
        {
            auto const before = store.sync_timeline_rows_examined.value();
            auto const body = sync_with(runtime, token, std::string{limit_three});
            auto const examined = store.sync_timeline_rows_examined.value() - before;
            auto const& room = joined_room(body, room_id);
            auto const* timeline = object_member_as_object(room, "timeline");
            REQUIRE(timeline != nullptr);

            THEN("it read one row past the window, whatever the room's history")
            {
                REQUIRE(examined == 4U);
            }

            THEN("the window is the newest three, limited, anchored at the oldest of them")
            {
                REQUIRE(timeline_bodies(*timeline) == std::vector<std::string>{"m57", "m58", "m59"});
                REQUIRE(is_limited(*timeline));
                auto const* prev_batch = string_member(*timeline, "prev_batch");
                REQUIRE(prev_batch != nullptr);
                auto const rows = store.events.room_in_stream_order(room_id);
                auto const& oldest = *std::ranges::prev(rows.end(), 3);
                REQUIRE(*prev_batch == std::to_string(oldest.stream_ordering));
            }

            THEN("the state is the room's current state, as a limited timeline needs")
            {
                auto const* state = object_member_as_object(room, "state");
                REQUIRE(state != nullptr);
                auto const* events = object_member(*state, "events");
                REQUIRE(events != nullptr);
                REQUIRE_FALSE(std::get<json::Array>(events->storage()).empty());
            }

            AND_WHEN("an incremental sync finds nothing new")
            {
                auto const* next_batch = string_member(body, "next_batch");
                REQUIRE(next_batch != nullptr);
                auto const quiet_before = store.sync_timeline_rows_examined.value();
                auto const quiet = sync_with(runtime, token, "?timeout=0&since=" + *next_batch);
                auto const quiet_examined = store.sync_timeline_rows_examined.value() - quiet_before;

                THEN("no row of the room was read")
                {
                    REQUIRE(quiet_examined == 0U);
                    std::ignore = quiet;
                }
            }

            AND_WHEN("two messages arrive and an incremental sync asks for three")
            {
                auto const* next_batch = string_member(body, "next_batch");
                REQUIRE(next_batch != nullptr);
                auto const since = *next_batch;
                send_messages(runtime, token, room_id, 60U, 2U);
                auto const inc_before = store.sync_timeline_rows_examined.value();
                auto const later = sync_with(runtime, token, std::string{limit_three} + "&timeout=0&since=" + since);
                auto const inc_examined = store.sync_timeline_rows_examined.value() - inc_before;
                auto const* later_timeline = object_member_as_object(joined_room(later, room_id), "timeline");
                REQUIRE(later_timeline != nullptr);

                THEN("the window is exactly those two, not limited, for the cost of those two")
                {
                    REQUIRE(timeline_bodies(*later_timeline) == std::vector<std::string>{"m60", "m61"});
                    REQUIRE_FALSE(is_limited(*later_timeline));
                    REQUIRE(inc_examined == 2U);
                }
            }
        }
    }
}

SCENARIO("a /sync reads the user's account data once, not once per room", "[sync][account-data][security][gate-m-sync]")
{
    GIVEN("a user with room account data in three rooms, and five thousand rows of other users")
    {
        auto started = make_runtime();
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto room_ids = std::vector<std::string>{};
        for (auto room = 0; room < 3; ++room)
        {
            room_ids.push_back(create_room(runtime, token));
            auto const put = hs::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/user/@alice:example.org/rooms/" + room_ids.back() + "/account_data/m.mine",
                 token, R"({"room":)" + std::to_string(room) + "}"});
            REQUIRE(put.response.status == 200U);
        }
        auto& store = runtime.homeserver.database.persistent_store;
        for (auto row = 0; row < 5000; ++row)
        {
            store.account_data.push_back({"@other" + std::to_string(row) + ":example.org", room_ids.front(), "m.theirs",
                                          R"({"secret":1})", db::allocate_sync_stream_id(store)});
        }
        db::rebuild_account_data_index(store);

        WHEN("the user syncs")
        {
            auto const before = store.account_data_rows_examined.value();
            auto const body = sync_with(runtime, token, "");
            auto const examined = store.account_data_rows_examined.value() - before;

            THEN("no other user's rows were read")
            {
                REQUIRE(examined < 200U);
            }

            THEN("each room carries exactly its own row")
            {
                for (auto room = std::size_t{0U}; room < room_ids.size(); ++room)
                {
                    auto const* account_data =
                        object_member_as_object(joined_room(body, room_ids[room]), "account_data");
                    REQUIRE(account_data != nullptr);
                    auto const& events = std::get<json::Array>(object_member(*account_data, "events")->storage());
                    REQUIRE(events.size() == 1U);
                    auto const& event = std::get<json::Object>(events.front().storage());
                    REQUIRE(*string_member(event, "type") == "m.mine");
                    auto const* content = object_member_as_object(event, "content");
                    REQUIRE(content != nullptr);
                    REQUIRE(std::get<std::int64_t>(object_member(*content, "room")->storage()) ==
                            static_cast<std::int64_t>(room));
                }
            }
        }
    }
}

SCENARIO("a /sync and a sendToDevice read only the recipient's queue and the device's keys",
         "[sync][to-device][keys][security][gate-m-sync]")
{
    GIVEN("a user with one queued message and two one-time keys, among thousands of other users' rows")
    {
        auto started = make_runtime();
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        auto& store = runtime.homeserver.database.persistent_store;
        for (auto row = 0; row < 3000; ++row)
        {
            auto const other = "@other" + std::to_string(row) + ":example.org";
            store.to_device_messages.push_back(
                {db::allocate_sync_stream_id(store), "@sender:example.org", other, "DEV", "m.test", R"({"n":1})"});
            store.one_time_keys.push_back({other, "DEV", "signed_curve25519:a", "{}"});
            store.fallback_keys.push_back({other, "DEV", "signed_curve25519:a", "{}"});
        }
        store.one_time_keys.push_back({std::string{alice}, "DEVICE1", "signed_curve25519:a", "{}"});
        store.one_time_keys.push_back({std::string{alice}, "DEVICE1", "signed_curve25519:b", "{}"});
        db::rebuild_key_indexes(store);
        auto const sent =
            hs::handle_client_server_request(runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.test/first", token,
                                                       R"({"messages":{"@alice:example.org":{"DEVICE1":{"k":1}}}})"});
        REQUIRE(sent.response.status == 200U);

        WHEN("the user sends one more to themselves")
        {
            auto const before = store.to_device_rows_examined.value();
            auto const again = hs::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.test/second", token,
                          R"({"messages":{"@alice:example.org":{"DEVICE1":{"k":2}}}})"});

            THEN("only the recipient's rows were read")
            {
                REQUIRE(again.response.status == 200U);
                REQUIRE(store.to_device_rows_examined.value() - before <= 4U);
            }
        }

        WHEN("the user syncs")
        {
            auto const queue_before = store.to_device_rows_examined.value();
            auto const keys_before = store.key_rows_examined.value();
            auto const body = sync_with(runtime, token, "");

            THEN("their message and key counts are exact, for the cost of their own rows")
            {
                auto const* to_device = object_member_as_object(body, "to_device");
                REQUIRE(to_device != nullptr);
                REQUIRE(std::get<json::Array>(object_member(*to_device, "events")->storage()).size() == 1U);
                auto const* counts = object_member_as_object(body, "device_one_time_keys_count");
                REQUIRE(counts != nullptr);
                REQUIRE(std::get<std::int64_t>(object_member(*counts, "signed_curve25519")->storage()) == 2);
                REQUIRE(store.to_device_rows_examined.value() - queue_before <= 2U);
                REQUIRE(store.key_rows_examined.value() - keys_before <= 2U);
            }
        }
    }
}
