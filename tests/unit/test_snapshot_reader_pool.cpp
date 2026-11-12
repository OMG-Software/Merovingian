// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0739: main reads a federation worker's store (ADR-0733) through database readers it opened before entering a
// sandbox that forbids opening files (FreeBSD Capsicum). Moving the database file away from its path stands in for
// that sandbox here: every open by the path fails afterwards, exactly as ECAPMODE makes it fail, while a descriptor
// opened before keeps reading the same file.
#include "../support/TempDirectory.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/SnapshotReaderPool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto room_id = std::string_view{"!room:local.example"};
constexpr auto event_count = std::size_t{3U};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-snapshot-readers-" + std::to_string(now) + ".sqlite3");
}

// Main's SQLite database with one room of `event_count` events. The returned store keeps its own connections open,
// as main's does.
[[nodiscard]] auto database_with_a_room(std::filesystem::path const& path) -> db::PersistentStoreOpenResult
{
    std::filesystem::remove(path);
    auto opened = db::open_sqlite_persistent_store(path.string());
    REQUIRE(opened.ok);
    REQUIRE(db::store_room(opened.store, {std::string{room_id}, "@alice:local.example"}));
    for (auto index = std::uint64_t{1U}; index <= event_count; ++index)
    {
        auto event = db::PersistentEvent{};
        event.event_id = "$event" + std::to_string(index);
        event.room_id = std::string{room_id};
        event.sender_user_id = "@alice:local.example";
        event.json = R"({"type":"m.room.message","content":{"body":"hello"}})";
        event.depth = index;
        event.stream_ordering = index;
        REQUIRE(db::store_event(opened.store, std::move(event)));
    }
    return opened;
}

// Moves the database away from its path for as long as it lives, then back.
class PathMovedAway final
{
public:
    explicit PathMovedAway(std::filesystem::path path)
        : path_{std::move(path)}
        , aside_{path_.string() + ".aside"}
    {
        std::filesystem::rename(path_, aside_);
    }
    PathMovedAway(PathMovedAway const&) = delete;
    auto operator=(PathMovedAway const&) -> PathMovedAway& = delete;
    PathMovedAway(PathMovedAway&&) = delete;
    auto operator=(PathMovedAway&&) -> PathMovedAway& = delete;
    ~PathMovedAway()
    {
        auto error = std::error_code{};
        std::filesystem::rename(aside_, path_, error);
    }

private:
    std::filesystem::path path_;
    std::filesystem::path aside_;
};

} // namespace

SCENARIO("Main reads a worker's store through readers opened at start, never by opening the database again",
         "[database][c44][snapshot-readers][sqlite]")
{
    GIVEN("main's SQLite database with a room, and a pool of two readers built on it")
    {
        auto const path = unique_sqlite_path();
        auto main_database = database_with_a_room(path);
        auto readers = db::SnapshotReaderPool{main_database.store, 2U};
        REQUIRE(readers.readers_opened_at_start() == 2U);
        REQUIRE(readers.connections_opened() == 2U);

        WHEN("the database can no longer be opened by its path, and the room list and the room are read three times")
        {
            auto const moved = PathMovedAway{path};
            auto lists = std::vector<std::optional<std::vector<std::string>>>{};
            auto rooms = std::vector<std::optional<db::RoomReloadSnapshot>>{};
            for (auto round = 0; round < 3; ++round)
            {
                lists.push_back(readers.room_ids());
                rooms.push_back(readers.room_snapshot(room_id));
            }
            auto const opened_by_path = db::detail::load_room_ids_from_sqlite(path.string());

            THEN("every read gives the room's rows through a reader opened at start, and none opened a connection")
            {
                REQUIRE_FALSE(opened_by_path.has_value());
                for (auto const& list : lists)
                {
                    REQUIRE(list.has_value());
                    REQUIRE(*list == std::vector<std::string>{std::string{room_id}});
                }
                for (auto const& room : rooms)
                {
                    REQUIRE(room.has_value());
                    REQUIRE(room->room_id == room_id);
                    REQUIRE(room->room.has_value());
                    REQUIRE(room->events.size() == event_count);
                }
                REQUIRE(readers.connections_opened() == 2U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("The readers serve reads from several threads at once without opening more",
         "[database][c44][snapshot-readers][sqlite]")
{
    GIVEN("a pool of two readers on main's SQLite database, and four threads released together")
    {
        auto const path = unique_sqlite_path();
        auto main_database = database_with_a_room(path);
        auto readers = db::SnapshotReaderPool{main_database.store, 2U};
        constexpr auto thread_count = std::size_t{4U};
        constexpr auto reads_per_thread = std::size_t{20U};

        WHEN("each thread reads the room list and the room repeatedly")
        {
            // Results are recorded per thread and asserted on this thread: Catch2 assertions are not thread-safe.
            auto good_reads = std::vector<std::size_t>(thread_count, 0U);
            auto release = std::atomic<bool>{false};
            {
                auto threads = std::vector<std::jthread>{};
                threads.reserve(thread_count);
                for (auto index = std::size_t{0U}; index < thread_count; ++index)
                {
                    threads.emplace_back([&, index]() {
                        while (!release.load(std::memory_order_acquire))
                        {
                            std::this_thread::yield();
                        }
                        for (auto read = std::size_t{0U}; read < reads_per_thread; ++read)
                        {
                            auto const list = readers.room_ids();
                            auto const room = readers.room_snapshot(room_id);
                            if (list.has_value() && list->size() == 1U && room.has_value() &&
                                room->events.size() == event_count)
                            {
                                ++good_reads[index];
                            }
                        }
                    });
                }
                release.store(true, std::memory_order_release);
            }

            THEN("every read succeeds, and the pool still holds only the two readers it opened at start")
            {
                for (auto const count : good_reads)
                {
                    REQUIRE(count == reads_per_thread);
                }
                REQUIRE(readers.connections_opened() == 2U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A pool on a database that cannot be opened reads nothing, and an in-memory server has nothing to read",
         "[database][c44][snapshot-readers]")
{
    GIVEN("a SQLite path with no database behind it")
    {
        auto store = db::PersistentStore{};
        store.backend = db::PersistentStoreBackend::sqlite;
        store.sqlite_path =
            (merovingian::tests::temporary_directory() / "merovingian-no-such-dir" / "absent.sqlite3").string();

        WHEN("a pool is built on it and asked for the room list and a room")
        {
            auto readers = db::SnapshotReaderPool{store, 2U};
            auto const list = readers.room_ids();
            auto const room = readers.room_snapshot(room_id);

            THEN("no reader opened and both reads fail rather than answer empty")
            {
                REQUIRE(readers.readers_opened_at_start() == 0U);
                REQUIRE_FALSE(list.has_value());
                REQUIRE_FALSE(room.has_value());
            }
        }
    }

    GIVEN("an in-memory store")
    {
        auto store = db::PersistentStore{};
        store.backend = db::PersistentStoreBackend::memory;

        WHEN("a pool is built on it and asked for the room list and a room")
        {
            auto readers = db::SnapshotReaderPool{store, 2U};
            auto const list = readers.room_ids();
            auto const room = readers.room_snapshot(room_id);

            THEN("it opens nothing, lists no room, and has nothing to apply")
            {
                REQUIRE(readers.connections_opened() == 0U);
                REQUIRE(list.has_value());
                REQUIRE(list->empty());
                REQUIRE(room.has_value());
                REQUIRE(room->nothing_to_apply);
            }
        }
    }
}
