// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// F-27 (ADR-0360): the federation worker reads its PersistentStore on many request threads while a room_sync
// rewrites one room of it on another. reload_room removes a room's rows and puts them back table by table, so a
// reader that lands between sees a room with no ACL, and the spec's server ACL (a PDU from a denied server "MUST
// be ignored") would fail open. StoreReadGuard gives the worker one reader-writer lock: store readers share it
// for their own call, a reload takes it exclusively only for the in-memory swap, after the database read.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Server Access Control Lists (ACLs)".
//
// The concurrency scenario is written for ThreadSanitizer as much as for its own assertions: assertions run on
// the main thread only (Catch2 is not thread-safe) and the reader thread is joined by an RAII guard.
// Tags: [store_read_guard][f27].

#include "../support/joining_threads.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/federation_worker/store_read_guard.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;
namespace worker = merovingian::federation_worker;

constexpr auto room_id = std::string_view{"!room:local.example"};
constexpr auto alice = std::string_view{"@alice:local.example"};
constexpr auto denied_server = std::string_view{"denied.example"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-store-read-guard-" + std::to_string(now) + ".sqlite3");
}

auto store_state_event(db::PersistentStore& store, std::string event_id, std::string_view type,
                       std::string_view state_key, std::string_view content_json, std::uint64_t position) -> void
{
    auto event = db::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = std::string{room_id};
    event.sender_user_id = std::string{alice};
    event.depth = position;
    event.stream_ordering = position;
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","room_id":")" + std::string{room_id} +
                 R"(","sender":")" + std::string{alice} + R"(","state_key":")" + std::string{state_key} +
                 R"(","origin_server_ts":)" + std::to_string(1000U + position) + R"(,"content":)" +
                 std::string{content_json} + "}";
    REQUIRE(db::store_event(store, std::move(event)));
    REQUIRE(db::store_state(store, {std::string{room_id}, std::string{type}, std::string{state_key}, event_id}));
}

// Main's store writes a room; a second handle on the same database is the worker's snapshot.
struct MainAndWorker final
{
    std::filesystem::path path{unique_sqlite_path()};
    db::PersistentStoreOpenResult main_open{};
    db::PersistentStoreOpenResult worker_open{};

    MainAndWorker()
    {
        std::filesystem::remove(path);
        main_open = db::open_sqlite_persistent_store(path.string());
        REQUIRE(main_open.ok);
        REQUIRE(db::store_room(main_open.store, {std::string{room_id}, std::string{alice}}));
        store_state_event(main_open.store, "$create", "m.room.create", "", R"({"room_version":"10"})", 1U);
    }

    ~MainAndWorker()
    {
        std::filesystem::remove(path);
    }

    MainAndWorker(MainAndWorker const&) = delete;
    auto operator=(MainAndWorker const&) -> MainAndWorker& = delete;
    MainAndWorker(MainAndWorker&&) = delete;
    auto operator=(MainAndWorker&&) -> MainAndWorker& = delete;

    auto main_denies_the_server() -> void
    {
        store_state_event(main_open.store, "$acl", "m.room.server_acl", "",
                          R"({"allow":["*"],"deny":["denied.example"]})", 2U);
    }

    auto open_worker() -> void
    {
        worker_open = db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::federation_worker);
        REQUIRE(worker_open.ok);
    }

    [[nodiscard]] auto worker() -> db::PersistentStore&
    {
        return worker_open.store;
    }
};

} // namespace

SCENARIO("a room reload reads the database without touching the store and swaps in memory afterwards",
         "[database][sqlite][reload][store_read_guard][f27]")
{
    GIVEN("a worker store opened before main added an ACL denying a server")
    {
        auto fixture = MainAndWorker{};
        fixture.open_worker();
        fixture.main_denies_the_server();
        REQUIRE(fed::room_server_acl_allows(fixture.worker(), room_id, denied_server));

        WHEN("the room's snapshot is loaded")
        {
            auto const snapshot = db::load_room_snapshot(fixture.worker(), room_id);

            THEN("the snapshot holds the ACL and the worker store has not changed yet")
            {
                REQUIRE(snapshot.has_value());
                REQUIRE(std::ranges::any_of(snapshot->state, [](db::PersistentStateEvent const& row) {
                    return row.event_type == "m.room.server_acl";
                }));
                REQUIRE(fed::room_server_acl_allows(fixture.worker(), room_id, denied_server));
            }
        }

        WHEN("the snapshot is loaded and then applied")
        {
            auto snapshot = db::load_room_snapshot(fixture.worker(), room_id);
            REQUIRE(snapshot.has_value());
            db::apply_room_snapshot(fixture.worker(), std::move(*snapshot));

            THEN("the worker store now enforces the ACL")
            {
                REQUIRE_FALSE(fed::room_server_acl_allows(fixture.worker(), room_id, denied_server));
            }
        }
    }
}

SCENARIO("providers the guard wraps keep their answers and an unset provider stays unset",
         "[federation_worker][store_read_guard][f27]")
{
    GIVEN("a federation runtime with an ACL provider and a room version resolver only")
    {
        auto state = fed::FederationRuntimeState{};
        state.room_server_acl_provider = [](std::string_view, std::string_view server) {
            return server != denied_server;
        };
        state.room_version_resolver = [](std::string_view) {
            return std::string{"10"};
        };
        auto guard = worker::StoreReadGuard{};

        WHEN("the guard wraps the store readers")
        {
            guard.wrap_store_readers(state);

            THEN("the wrapped providers answer as before")
            {
                REQUIRE(state.room_server_acl_provider(room_id, "allowed.example"));
                REQUIRE_FALSE(state.room_server_acl_provider(room_id, denied_server));
                REQUIRE(state.room_version_resolver(room_id) == "10");
            }

            THEN("a provider that was not set is still not set")
            {
                REQUIRE_FALSE(static_cast<bool>(state.backfill_provider));
                REQUIRE_FALSE(static_cast<bool>(state.state_query_provider));
                REQUIRE_FALSE(static_cast<bool>(state.space_hierarchy_provider));
            }
        }
    }
}

SCENARIO("a reader never sees a room half way through a reload, so a denied server is never allowed",
         "[federation_worker][store_read_guard][f27][concurrency][security]")
{
    GIVEN("a worker store whose room has an ACL denying a server, and the guard's wrapped providers reading it")
    {
        auto fixture = MainAndWorker{};
        fixture.main_denies_the_server();
        fixture.open_worker();
        REQUIRE_FALSE(fed::room_server_acl_allows(fixture.worker(), room_id, denied_server));

        auto state = fed::FederationRuntimeState{};
        auto& store = fixture.worker();
        state.room_server_acl_provider = [&store](std::string_view room, std::string_view server) {
            return fed::room_server_acl_allows(store, room, server);
        };
        // Reads the room's state twice with a yield between: inside one provider call the store must not change.
        state.room_version_resolver = [&store](std::string_view) {
            auto const before = store.state.size();
            std::this_thread::yield();
            return std::string{before == store.state.size() ? "steady" : "torn"};
        };
        auto guard = worker::StoreReadGuard{};
        guard.wrap_store_readers(state);

        WHEN("one thread keeps asking the ACL while another reloads the room again and again")
        {
            auto stop = std::atomic<bool>{false};
            auto asked = std::atomic<std::size_t>{0U};
            auto allowed_wrongly = std::atomic<std::size_t>{0U};
            auto torn = std::atomic<std::size_t>{0U};
            auto reload_failures = std::size_t{0U};
            {
                auto readers = merovingian::tests::JoiningThreads{};
                readers.emplace_back([&] {
                    while (!stop.load())
                    {
                        if (state.room_server_acl_provider(room_id, denied_server))
                        {
                            allowed_wrongly.fetch_add(1U);
                        }
                        if (state.room_version_resolver(room_id) != "steady")
                        {
                            torn.fetch_add(1U);
                        }
                        asked.fetch_add(1U);
                    }
                });
                for (auto round = std::size_t{0U}; round < 150U; ++round)
                {
                    if (!guard.reload_room(store, room_id))
                    {
                        ++reload_failures;
                    }
                }
                stop.store(true);
            }

            THEN("every answer was a deny, no provider call saw the store change, and every reload succeeded")
            {
                REQUIRE(reload_failures == 0U);
                REQUIRE(asked.load() > 0U);
                REQUIRE(allowed_wrongly.load() == 0U);
                REQUIRE(torn.load() == 0U);
                REQUIRE_FALSE(fed::room_server_acl_allows(store, room_id, denied_server));
            }
        }
    }
}
