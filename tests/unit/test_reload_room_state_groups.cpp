// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// reload_room and the state groups (ADR-0064). The federation worker's PersistentStore is a
// snapshot taken at worker start; reload_room refreshes one room of it. Federation reads that
// return history judge each event on the state group recorded for it and fail closed when there
// is none (federation::ServerEventFilter), so a reload that left the groups behind made every
// event created after the worker started look invisible: timestamp_to_event answered 404 and
// backfill sent the event redacted.
//
// Spec: Matrix Server-Server API v1.19, GET /timestamp_to_event/{roomId} ("404 - No event was
// found") and GET /backfill/{roomId}; docs/matrix-v1.19-spec/server-server-api.md.

#include "../support/temp_directory.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/event_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;

constexpr auto room_id = std::string_view{"!room:local.example"};
constexpr auto other_room_id = std::string_view{"!other:local.example"};
constexpr auto alice = std::string_view{"@alice:local.example"};
constexpr auto bob = std::string_view{"@bob:remote.example"};
constexpr auto remote_server = std::string_view{"remote.example"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-reload-state-groups-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto make_event(std::string event_id, std::string_view room, std::string_view sender,
                              std::string_view type, std::string_view state_key_json, std::string_view content_json,
                              std::uint64_t position) -> db::PersistentEvent
{
    auto event = db::PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::string{room};
    event.sender_user_id = std::string{sender};
    event.depth = position;
    event.stream_ordering = position;
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","room_id":")" + std::string{room} +
                 R"(","sender":")" + std::string{sender} + R"(",)" + std::string{state_key_json} +
                 R"("origin_server_ts":)" + std::to_string(1000U + position) + R"(,"content":)" +
                 std::string{content_json} + "}";
    return event;
}

// Writes `event` and records its state group, as main's event pipeline does.
auto store_with_group(db::PersistentStore& store, db::PersistentEvent event, std::string const& group_id,
                      std::optional<std::string> const& parent_group,
                      std::vector<db::PersistentStateGroupStateEntry> const& full_state) -> void
{
    auto const event_id = event.event_id;
    REQUIRE(db::store_event(store, std::move(event)));
    auto const group = db::create_or_reuse_state_group(store, room_id, group_id, parent_group, full_state);
    REQUIRE(group.has_value());
    REQUIRE(db::set_event_state_group(store, event_id, *group));
}

[[nodiscard]] auto groups_of_room(db::PersistentStore const& store, std::string_view room) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(store.state_groups, [room](db::PersistentStateGroup const& group) {
            return group.room_id == room;
        }));
}

[[nodiscard]] auto mappings_of(db::PersistentStore const& store, std::string_view event_id) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(store.event_state_groups, [event_id](db::PersistentEventStateGroup const& mapping) {
            return mapping.event_id == event_id;
        }));
}

// Main's store (handle B) holds the room's first state group; the worker's store (handle A) is
// opened afterwards and so hydrates it. Then main creates the member join, a second group (a delta
// from the first) and a message, none of which handle A has seen.
struct WorkerAndMain final
{
    std::filesystem::path path{unique_sqlite_path()};
    db::PersistentStoreOpenResult main_open{};
    db::PersistentStoreOpenResult worker_open{};

    WorkerAndMain()
    {
        std::filesystem::remove(path);
        main_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(main_open.ok);
        auto& main_store = main_open.store;
        REQUIRE(db::store_room(main_store, {std::string{room_id}, std::string{alice}}));
        REQUIRE(db::store_room(main_store, {std::string{other_room_id}, std::string{alice}}));
        store_with_group(main_store,
                         make_event("$create", room_id, alice, "m.room.create", R"("state_key":"",)",
                                    R"({"room_version":"10","creator":"@alice:local.example"})", 1U),
                         "sg:create", std::nullopt, {{"sg:create", "m.room.create", "", "$create"}});
        REQUIRE(db::create_or_reuse_state_group(main_store, other_room_id, "sg:other", std::nullopt, {}).has_value());

        worker_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(worker_open.ok);
    }

    // What main does after the worker started: Bob (a user of remote.example) joins, then a message.
    auto main_writes_join_and_message() -> void
    {
        auto& main_store = main_open.store;
        REQUIRE(db::store_membership(main_store, {std::string{room_id}, std::string{bob}}) ==
                db::MembershipStoreResult::stored);
        store_with_group(main_store,
                         make_event("$bob_join", room_id, bob, "m.room.member",
                                    R"("state_key":"@bob:remote.example",)", R"({"membership":"join"})", 2U),
                         "sg:join", "sg:create",
                         {{"sg:join", "m.room.create", "", "$create"},
                          {"sg:join", "m.room.member", std::string{bob}, "$bob_join"}});
        auto message = make_event("$message", room_id, alice, "m.room.message", "",
                                  R"({"msgtype":"m.text","body":"visible-body"})", 3U);
        message.prev_event_ids = {"$bob_join"};
        REQUIRE(db::store_event(main_store, std::move(message)));
        REQUIRE(db::set_event_state_group(main_store, "$message", "sg:join"));
    }

    [[nodiscard]] auto worker() -> db::PersistentStore&
    {
        return worker_open.store;
    }
};

} // namespace

SCENARIO("reload_room brings the room's state groups, their entries and the event mappings with it",
         "[database][sqlite][reload][state-groups][regression]")
{
    GIVEN("a worker store opened before main created a member join, a second state group and a message")
    {
        auto fixture = WorkerAndMain{};
        fixture.main_writes_join_and_message();

        THEN("the worker store knows nothing of the new group or the new events' mappings yet")
        {
            REQUIRE_FALSE(db::find_state_group(fixture.worker(), "sg:join").has_value());
            REQUIRE_FALSE(db::find_event_state_group(fixture.worker(), "$message").has_value());
        }

        WHEN("reload_room is called on the worker store for that room")
        {
            REQUIRE(db::reload_room(fixture.worker(), room_id));

            THEN("the worker store holds the new group, its entries and the mapping of each new event")
            {
                auto const group = db::find_state_group(fixture.worker(), "sg:join");
                REQUIRE(group.has_value());
                REQUIRE(group->room_id == room_id);
                REQUIRE(group->parent_state_group_id == std::optional<std::string>{"sg:create"});
                REQUIRE(db::find_event_state_group(fixture.worker(), "$message") ==
                        std::optional<std::string>{"sg:join"});
                REQUIRE(db::find_event_state_group(fixture.worker(), "$bob_join") ==
                        std::optional<std::string>{"sg:join"});

                auto const full_state = db::read_state_group_full_state(fixture.worker(), "sg:join");
                REQUIRE(full_state.has_value());
                REQUIRE(full_state->size() == 2U);
            }

            THEN("the worker store's groups and mappings for the room equal main's")
            {
                REQUIRE(groups_of_room(fixture.worker(), room_id) == groups_of_room(fixture.main_open.store, room_id));
                REQUIRE(fixture.worker().state_group_state.size() == fixture.main_open.store.state_group_state.size());
                REQUIRE(fixture.worker().event_state_groups.size() ==
                        fixture.main_open.store.event_state_groups.size());
            }

            THEN("another room's group is left as it was")
            {
                REQUIRE(groups_of_room(fixture.worker(), other_room_id) == 1U);
            }
        }

        WHEN("reload_room is called on the worker store three times")
        {
            REQUIRE(db::reload_room(fixture.worker(), room_id));
            auto const groups = fixture.worker().state_groups.size();
            auto const entries = fixture.worker().state_group_state.size();
            auto const mappings = fixture.worker().event_state_groups.size();
            REQUIRE(db::reload_room(fixture.worker(), room_id));
            REQUIRE(db::reload_room(fixture.worker(), room_id));

            THEN("no group, entry or mapping is duplicated")
            {
                REQUIRE(fixture.worker().state_groups.size() == groups);
                REQUIRE(fixture.worker().state_group_state.size() == entries);
                REQUIRE(fixture.worker().event_state_groups.size() == mappings);
                REQUIRE(mappings_of(fixture.worker(), "$message") == 1U);
            }
        }
    }
}

SCENARIO("A reloaded worker store lets a joined server see an event created after the worker started",
         "[database][sqlite][reload][state-groups][federation][timestamp-to-event][regression]")
{
    GIVEN("a worker store opened before main created Bob's join and a message, and then reloaded for the room")
    {
        auto fixture = WorkerAndMain{};
        fixture.main_writes_join_and_message();
        REQUIRE(db::reload_room(fixture.worker(), room_id));

        WHEN("the server of a joined user is judged for the new message")
        {
            THEN("the message is visible to it, on the state group the reload brought")
            {
                REQUIRE(fed::event_visible_to_server(fixture.worker(), "$message", remote_server));
            }
        }

        WHEN("the server asks for the event nearest the message's timestamp")
        {
            auto const result =
                fed::build_timestamp_to_event_response(fixture.worker(), room_id, 1003, db::TimeDirection::forwards,
                                                       remote_server);

            THEN("the answer names the message instead of 404")
            {
                REQUIRE(result.status == fed::RoomReadStatus::ok);
                REQUIRE(result.body.find("$message") != std::string::npos);
            }
        }

        WHEN("the server backfills from the message")
        {
            auto const pdus = fed::build_backfill_pdus(fixture.worker(), room_id, {"$message"}, 10U, remote_server);

            THEN("the message comes back whole, not redacted")
            {
                REQUIRE_FALSE(pdus.empty());
                REQUIRE(pdus.front().find("visible-body") != std::string::npos);
            }
        }
    }
}
