// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C44, ADR-0733: the federation worker opens no database. Main reads each room's snapshot and
// sends it; the worker builds its store from those snapshots before its runtime starts, and a
// reload swaps one room's slice. These are the database halves of that: a snapshot carries the
// room's forward extremities (the worker's make_leave and make_knock templates build on them), a
// fill builds a whole store from snapshots with every index a hydrated store has, main lists the
// room IDs a worker may ask for, and main answers a key lookup from memory with public columns.

#include "../support/TempDirectory.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/federation/EventQuery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
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
           ("merovingian-worker-snapshot-fill-" + std::to_string(now) + ".sqlite3");
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

// Writes `event` with its state group and moves the room's tips onto it, as main's event pipeline does.
auto store_event_as_main(db::PersistentStore& store, db::PersistentEvent event, std::string const& group_id,
                         std::optional<std::string> const& parent_group,
                         std::vector<db::PersistentStateGroupStateEntry> const& full_state) -> void
{
    auto const event_id = event.event_id;
    auto const room = event.room_id;
    auto const prev_event_ids = event.prev_event_ids;
    REQUIRE(db::store_event(store, std::move(event)));
    // No state of its own: the event is placed in a group that already exists.
    auto const group = full_state.empty()
                           ? std::optional<std::string>{group_id}
                           : db::create_or_reuse_state_group(store, room, group_id, parent_group, full_state);
    REQUIRE(group.has_value());
    REQUIRE(db::set_event_state_group(store, event_id, *group));
    REQUIRE(db::update_forward_extremities(store, room, event_id, prev_event_ids, true));
}

// Main's database: two rooms, the first with a create event; the worker's store (a second handle)
// is opened after that and hydrates it.
struct MainDatabase final
{
    std::filesystem::path path{unique_sqlite_path()};
    db::PersistentStoreOpenResult main_open{};

    MainDatabase()
    {
        std::filesystem::remove(path);
        main_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(main_open.ok);
        auto& main_store = main_open.store;
        REQUIRE(db::store_room(main_store, {std::string{room_id}, std::string{alice}}));
        REQUIRE(db::store_room(main_store, {std::string{other_room_id}, std::string{alice}}));
        store_event_as_main(main_store,
                            make_event("$create", room_id, alice, "m.room.create", R"("state_key":"",)",
                                       R"({"room_version":"10","creator":"@alice:local.example"})", 1U),
                            "sg:create", std::nullopt,
                            {
                                {"sg:create", "m.room.create", "", "$create"}
        });
        REQUIRE(db::store_state(main_store, {std::string{room_id}, "m.room.create", "", "$create"}));
    }

    // Bob (a user of remote.example) joins, then Alice sends a message: the room's one tip moves to the message.
    auto main_writes_join_and_message() -> void
    {
        auto& main_store = main_open.store;
        REQUIRE(db::store_membership(main_store, {std::string{room_id}, std::string{bob}}) ==
                db::MembershipStoreResult::stored);
        auto join = make_event("$bob_join", room_id, bob, "m.room.member", R"("state_key":"@bob:remote.example",)",
                               R"({"membership":"join"})", 2U);
        join.prev_event_ids = {"$create"};
        store_event_as_main(main_store, std::move(join), "sg:join", "sg:create",
                            {
                                {"sg:join", "m.room.create", "",               "$create"  },
                                {"sg:join", "m.room.member", std::string{bob}, "$bob_join"}
        });
        REQUIRE(db::store_state(main_store, {std::string{room_id}, "m.room.member", std::string{bob}, "$bob_join"}));
        auto message = make_event("$message", room_id, alice, "m.room.message", "",
                                  R"({"msgtype":"m.text","body":"visible-body"})", 3U);
        message.prev_event_ids = {"$bob_join"};
        store_event_as_main(main_store, std::move(message), "sg:join", std::nullopt, {});
    }

    [[nodiscard]] auto store() -> db::PersistentStore&
    {
        return main_open.store;
    }
};

[[nodiscard]] auto snapshots_of_every_room(db::PersistentStore const& source) -> std::vector<db::RoomReloadSnapshot>
{
    auto const room_ids = db::load_room_ids(source);
    REQUIRE(room_ids.has_value());
    auto snapshots = std::vector<db::RoomReloadSnapshot>{};
    for (auto const& id : *room_ids)
    {
        auto snapshot = db::load_room_snapshot(source, id);
        REQUIRE(snapshot.has_value());
        snapshots.push_back(std::move(*snapshot));
    }
    return snapshots;
}

[[nodiscard]] auto count_room_memberships(db::PersistentStore const& store, std::string_view room) -> std::size_t
{
    auto rows = std::size_t{0U};
    db::for_each_room_membership_row(store, room, [&rows](db::PersistentMembership const&) {
        ++rows;
    });
    return rows;
}

} // namespace

SCENARIO("A room snapshot carries the room's forward extremities and a reload replaces the worker's",
         "[database][sqlite][reload][c44][snapshot-tips][regression]")
{
    GIVEN("a worker store hydrated while the room's only tip was its create event")
    {
        auto main = MainDatabase{};
        auto worker_open = db::open_sqlite_persistent_store(main.path.string());
        REQUIRE(worker_open.ok);
        auto& worker = worker_open.store;
        REQUIRE(worker.forward_extremities.tips_of_room(room_id) == std::vector<std::string>{"$create"});

        WHEN("main adds a join and a message and the worker reloads the room")
        {
            main.main_writes_join_and_message();
            auto const snapshot = db::load_room_snapshot(main.store(), room_id);
            REQUIRE(db::reload_room(worker, room_id));

            THEN("the snapshot names the message as the room's one tip")
            {
                REQUIRE(snapshot.has_value());
                REQUIRE(snapshot->forward_extremities.size() == 1U);
                REQUIRE(snapshot->forward_extremities.front().event_id == "$message");
            }

            THEN("the worker's tips are main's, charged to the server of the tip's sender")
            {
                REQUIRE(worker.forward_extremities.tips_of_room(room_id) == std::vector<std::string>{"$message"});
                REQUIRE(worker.forward_extremities.count_for_sender_server(room_id, alice) == 1U);
                REQUIRE(worker.forward_extremities.count_for_sender_server(room_id, bob) == 0U);
            }

            THEN("reloading twice more leaves exactly the same tip")
            {
                REQUIRE(db::reload_room(worker, room_id));
                REQUIRE(db::reload_room(worker, room_id));
                REQUIRE(worker.forward_extremities.tips_of_room(room_id) == std::vector<std::string>{"$message"});
                REQUIRE(worker.forward_extremities.size() == 1U);
            }
        }
    }
}

SCENARIO("A store filled from room snapshots holds what a hydrated store holds, with working indexes",
         "[database][sqlite][c44][snapshot-fill]")
{
    GIVEN("main's database with two rooms, one holding a create event, a remote join and a message")
    {
        auto main = MainDatabase{};
        main.main_writes_join_and_message();

        WHEN("a memory store is filled from a snapshot of every room main lists")
        {
            auto filled = db::PersistentStore{};
            auto const added = db::fill_store_from_room_snapshots(filled, snapshots_of_every_room(main.store()));

            THEN("it holds both rooms and exactly main's rows of each room table")
            {
                REQUIRE(added == 2U);
                REQUIRE(filled.backend == db::PersistentStoreBackend::memory);
                REQUIRE(filled.rooms.size() == 2U);
                REQUIRE(filled.events.size() == main.store().events.size());
                REQUIRE(filled.event_edges.size() == main.store().event_edges.size());
                REQUIRE(filled.memberships.size() == main.store().memberships.size());
                REQUIRE(filled.state.size() == main.store().state.size());
                REQUIRE(filled.state_groups.size() == main.store().state_groups.size());
                REQUIRE(filled.state_group_state.size() == main.store().state_group_state.size());
                REQUIRE(filled.event_state_groups.size() == main.store().event_state_groups.size());
            }

            THEN("the state, membership and tip indexes answer without a rebuild")
            {
                REQUIRE(db::find_current_state_event_id(filled, room_id, "m.room.member", bob) ==
                        std::optional<std::string>{"$bob_join"});
                REQUIRE(count_room_memberships(filled, room_id) == 1U);
                REQUIRE(count_room_memberships(filled, other_room_id) == 0U);
                REQUIRE(filled.forward_extremities.tips_of_room(room_id) == std::vector<std::string>{"$message"});
                REQUIRE(filled.forward_extremities.count_for_sender_server(room_id, alice) == 1U);
                REQUIRE(db::find_event_state_group(filled, "$message") == std::optional<std::string>{"sg:join"});
            }

            THEN("a joined server sees the message on its recorded state group")
            {
                REQUIRE(fed::event_visible_to_server(filled, "$message", remote_server));
            }
        }

        WHEN("a memory store is filled from no snapshots")
        {
            auto filled = db::PersistentStore{};
            auto const added = db::fill_store_from_room_snapshots(filled, {});

            THEN("nothing is added")
            {
                REQUIRE(added == 0U);
                REQUIRE(filled.rooms.empty());
                REQUIRE(filled.events.empty());
            }
        }
    }
}

SCENARIO("Main lists every room ID once, sorted, and a store with no database lists none",
         "[database][sqlite][c44][room-ids]")
{
    GIVEN("main's database with two rooms")
    {
        auto main = MainDatabase{};

        WHEN("main lists its room IDs")
        {
            auto const room_ids = db::load_room_ids(main.store());

            THEN("the list is exactly both rooms in byte order")
            {
                REQUIRE(room_ids == std::optional<std::vector<std::string>>{
                                        std::vector<std::string>{std::string{other_room_id}, std::string{room_id}}
                });
            }
        }

        WHEN("a memory store lists its room IDs")
        {
            auto const memory = db::PersistentStore{};

            THEN("there is no list")
            {
                REQUIRE_FALSE(db::load_room_ids(memory).has_value());
            }
        }
    }
}

SCENARIO("Main answers a worker's key lookup with public columns, never its own key, up to the cap",
         "[database][c44][server-keys]")
{
    GIVEN("a store holding this server's own key with its secret and two keys of a remote server")
    {
        auto store = db::PersistentStore{};
        store.server_signing_keys.emplace_back("local.example", "ed25519:own", "own-public", 9000U,
                                               "secretbox:v1:c2VjcmV0");
        store.server_signing_keys.emplace_back("remote.example", "ed25519:a", "public-a", 5000U);
        auto retired = db::PersistentServerSigningKey{"remote.example", "ed25519:b", "public-b", 4000U};
        retired.expired_ts = 4000U;
        store.server_signing_keys.push_back(std::move(retired));
        store.server_signing_keys.emplace_back("third.example", "ed25519:c", "public-c", 7000U);

        WHEN("the remote server's keys are asked for with room for all of them")
        {
            auto const keys = db::public_signing_keys_of_server(store, remote_server, 16U);

            THEN("both remote rows come back with their public columns and no secret")
            {
                REQUIRE(keys.size() == 2U);
                REQUIRE(keys[0].key_id == "ed25519:a");
                REQUIRE(keys[0].public_key == "public-a");
                REQUIRE(keys[0].valid_until_ts == 5000U);
                REQUIRE(keys[1].key_id == "ed25519:b");
                REQUIRE(keys[1].expired_ts == 4000U);
                for (auto const& key : keys)
                {
                    REQUIRE(key.server_name == remote_server);
                    REQUIRE(key.secret_key.empty());
                }
            }
        }

        WHEN("the cap is one row, and then zero")
        {
            THEN("exactly one row, and then none, comes back")
            {
                REQUIRE(db::public_signing_keys_of_server(store, remote_server, 1U).size() == 1U);
                REQUIRE(db::public_signing_keys_of_server(store, remote_server, 0U).empty());
            }
        }

        WHEN("this server's own name is asked for")
        {
            THEN("the row that holds a secret is not copied at all")
            {
                REQUIRE(db::public_signing_keys_of_server(store, "local.example", 16U).empty());
            }
        }
    }
}

SCENARIO("A worker's key mirror refreshes from main's answer, taking only the asked server's public rows",
         "[database][c44][server-keys][key-source]")
{
    GIVEN("an in-memory worker store whose key source answers as main would, plus rows it should never take")
    {
        auto store = db::PersistentStore{};
        auto asked = std::vector<std::string>{};
        store.remote_signing_key_source =
            [&asked](std::string_view server_name) -> std::optional<std::vector<db::PersistentServerSigningKey>> {
            asked.emplace_back(server_name);
            auto rows = std::vector<db::PersistentServerSigningKey>{};
            rows.emplace_back(std::string{remote_server}, "ed25519:a", "public-a", 5000U);
            rows.emplace_back("third.example", "ed25519:c", "public-c", 7000U);
            rows.emplace_back(std::string{remote_server}, "ed25519:s", "public-s", 9000U, "secretbox:v1:c2VjcmV0");
            return rows;
        };

        WHEN("the remote server's keys are refreshed")
        {
            auto const refreshed = db::refresh_remote_signing_keys(store, remote_server);

            THEN("the source is asked once for that server, and only its row without a secret is taken")
            {
                REQUIRE(refreshed);
                REQUIRE(asked == std::vector<std::string>{std::string{remote_server}});
                auto const held = db::snapshot_server_signing_keys(store);
                REQUIRE(held.size() == 1U);
                REQUIRE(held[0].server_name == remote_server);
                REQUIRE(held[0].key_id == "ed25519:a");
                REQUIRE(held[0].public_key == "public-a");
                REQUIRE(held[0].secret_key.empty());
            }
        }
    }

    GIVEN("an in-memory worker store holding one key, whose key source fails")
    {
        auto store = db::PersistentStore{};
        store.server_signing_keys.emplace_back(std::string{remote_server}, "ed25519:a", "public-a", 5000U);
        auto calls = std::size_t{0U};
        store.remote_signing_key_source =
            [&calls](std::string_view) -> std::optional<std::vector<db::PersistentServerSigningKey>> {
            ++calls;
            return std::nullopt;
        };

        WHEN("the remote server's keys are refreshed")
        {
            auto const refreshed = db::refresh_remote_signing_keys(store, remote_server);

            THEN("the refresh fails and the mirror is unchanged")
            {
                REQUIRE_FALSE(refreshed);
                REQUIRE(calls == 1U);
                auto const held = db::snapshot_server_signing_keys(store);
                REQUIRE(held.size() == 1U);
                REQUIRE(held[0].key_id == "ed25519:a");
            }
        }
    }

    GIVEN("an in-memory store with no key source")
    {
        auto store = db::PersistentStore{};

        WHEN("a server's keys are refreshed")
        {
            auto const refreshed = db::refresh_remote_signing_keys(store, remote_server);

            THEN("it is the no-op it always was")
            {
                REQUIRE(refreshed);
                REQUIRE(db::snapshot_server_signing_keys(store).empty());
            }
        }
    }
}
