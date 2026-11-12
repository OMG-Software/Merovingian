// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C44, ADR-0733 and ADR-0735, against a real SQLite file: main reads a room for a federation
// worker in one read transaction, and that transaction has ended by the time page 0 is handed
// back to be sent. A worker that stops reading its channel therefore holds no lock on main's
// database. The probe is a write with busy_timeout 0 from another connection: it is refused
// while the read holds its lock (shown from inside the read, so the probe can see a lock) and
// succeeds the moment page 0 is ready.

#include "../support/TempDirectory.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/WorkerSnapshotService.hpp"
#include "merovingian/homeserver/WorkerSnapshotSources.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
namespace ipc = merovingian::ipc;

constexpr auto room_id = std::string_view{"!room:local.example"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-worker-snapshot-lock-" + std::to_string(now) + ".sqlite3");
}

// One write from a connection of its own that does not wait for a lock: SQLITE_OK, or SQLITE_BUSY while another
// connection holds a lock that a write must wait for.
[[nodiscard]] auto write_without_waiting(std::filesystem::path const& path) -> int
{
    sqlite3* raw = nullptr;
    if (sqlite3_open(path.string().c_str(), &raw) != SQLITE_OK)
    {
        sqlite3_close(raw);
        return SQLITE_CANTOPEN;
    }
    sqlite3_busy_timeout(raw, 0);
    auto const result = sqlite3_exec(raw, "INSERT INTO c44_probe (x) VALUES (1)", nullptr, nullptr, nullptr);
    sqlite3_close(raw);
    return result;
}

} // namespace

SCENARIO("Main's read for a worker has ended, and holds no lock, when page 0 is ready to send",
         "[integration][c44][worker-snapshot-lock][sqlite]")
{
    GIVEN("main's SQLite database with a room of events, and a service reading it the way WorkerPool does")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        REQUIRE(db::store_room(opened.store, {std::string{room_id}, "@alice:local.example"}));
        for (auto index = 1U; index <= 20U; ++index)
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
        {
            sqlite3* raw = nullptr;
            REQUIRE(sqlite3_open(path.string().c_str(), &raw) == SQLITE_OK);
            REQUIRE(sqlite3_exec(raw, "CREATE TABLE c44_probe (x INTEGER)", nullptr, nullptr, nullptr) == SQLITE_OK);
            sqlite3_close(raw);
        }

        // Written by the read on the calling thread and read after answer() returned on it.
        auto probes_during_read = std::vector<int>{};
        auto sources = hs::WorkerSnapshotSources{};
        sources.list_rooms = []() -> std::optional<std::vector<std::string>> {
            return std::vector<std::string>{std::string{room_id}};
        };
        sources.read_room = [&path, &probes_during_read](std::string_view room) {
            return db::detail::load_room_snapshot_from_sqlite(path.string(), room, [&](std::string_view table) {
                if (table == "events")
                {
                    probes_during_read.push_back(write_without_waiting(path));
                }
            });
        };
        sources.server_keys = [](std::string_view, std::size_t) {
            return std::vector<db::PersistentServerSigningKey>{};
        };
        sources.now = []() {
            return std::chrono::steady_clock::now();
        };
        auto service = hs::WorkerSnapshotService{std::move(sources), ipc::worker_store_page_budget(24U << 20U)};
        auto const channel = std::make_shared<int const>(0); // SHARED_PTR: reviewed - stand-in channel identity.
        service.permit_reload(channel, room_id, 1U);

        WHEN("the worker asks for the room and main has page 0 in hand")
        {
            auto const body = service.answer(channel, "room_snapshot_request",
                                             ipc::serialize_room_snapshot_request({std::string{room_id}, 1U, 0U}));
            auto const probe_at_send = write_without_waiting(path);

            THEN("during the read a write could not get its lock, and at the send it could")
            {
                REQUIRE(probes_during_read == std::vector<int>{SQLITE_BUSY});
                REQUIRE(probe_at_send == SQLITE_OK);
                auto const page = ipc::deserialize_room_snapshot_page(body);
                REQUIRE(page.has_value());
                REQUIRE(page->rows.events.size() == 20U);
            }
        }
    }
}
