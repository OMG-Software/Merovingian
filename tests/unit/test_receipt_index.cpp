// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Run-3 finding C23 (ADR-0651): the receipts table is read by room and by (room, user) through two standing indexes,
// kept right by every writer and rebuilt on load, and one user's threaded receipts in one room are capped.
//
// Spec: Matrix Client-Server API v1.19, "Receipts": each user_id, receipt_type and thread tuple is associated with
// only a single event_id.
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#receipts

#include "../support/TempDirectory.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto make_receipt(std::string room, std::string user, std::string event, std::string thread = {},
                                std::string type = "m.read") -> db::PersistentReceipt
{
    auto result = db::PersistentReceipt{};
    result.room_id = std::move(room);
    result.user_id = std::move(user);
    result.event_id = std::move(event);
    result.thread_id = std::move(thread);
    result.receipt_type = std::move(type);
    return result;
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-receipt-index-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto user_name(std::size_t index) -> std::string
{
    return "@user" + std::to_string(index) + ":example.org";
}

[[nodiscard]] auto thread_rows(db::PersistentStore const& store, std::string const& room, std::string const& user)
    -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const* row : db::receipts_of_user_in_room(store, room, user))
    {
        if (!row->thread_id.empty() && row->thread_id != "main")
        {
            ++count;
        }
    }
    return count;
}

} // namespace

SCENARIO("receipt readers examine the rows of the room or user they ask about, not the table", "[receipts][c23][index]")
{
    GIVEN("a store with 40 rooms of 10 users, each holding one receipt, plus a victim room")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto room = std::size_t{0U}; room < 40U; ++room)
        {
            for (auto user = std::size_t{0U}; user < 10U; ++user)
            {
                REQUIRE(db::store_receipt(store, make_receipt("!r" + std::to_string(room) + ":example.org",
                                                              user_name(user), "$e" + std::to_string(user))));
            }
        }
        REQUIRE(store.receipts.size() == 400U);

        WHEN("one room's receipts are read")
        {
            auto const before = store.receipt_rows_examined.value();
            auto const rows = db::receipts_in_room(store, "!r7:example.org");

            THEN("exactly that room's ten rows are returned and examined")
            {
                REQUIRE(rows.size() == 10U);
                REQUIRE(store.receipt_rows_examined.value() - before == 10U);
                REQUIRE(std::ranges::all_of(rows, [](db::PersistentReceipt const* row) {
                    return row->room_id == "!r7:example.org";
                }));
            }
        }

        WHEN("one user's receipts in one room are read")
        {
            auto const before = store.receipt_rows_examined.value();
            auto const rows = db::receipts_of_user_in_room(store, "!r7:example.org", user_name(3U));

            THEN("exactly that user's one row is returned and examined")
            {
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front()->event_id == "$e3");
                REQUIRE(store.receipt_rows_examined.value() - before == 1U);
            }
        }

        WHEN("a room nobody holds a receipt in is read")
        {
            auto const before = store.receipt_rows_examined.value();

            THEN("nothing is returned and nothing is examined")
            {
                REQUIRE(db::receipts_in_room(store, "!none:example.org").empty());
                REQUIRE(store.receipt_rows_examined.value() == before);
            }
        }

        WHEN("receipts are removed, replaced and added")
        {
            REQUIRE(db::remove_receipt(store, make_receipt("!r7:example.org", user_name(3U), "$e3")));
            REQUIRE(db::store_receipt(store, make_receipt("!r7:example.org", user_name(4U), "$newer")));
            REQUIRE(db::store_receipt(store, make_receipt("!r7:example.org", user_name(20U), "$fresh")));

            THEN("the indexes follow every write")
            {
                REQUIRE(store.receipt_room_index.in_step(store.receipts.size()));
                REQUIRE(store.receipt_user_room_index.in_step(store.receipts.size()));
                REQUIRE(db::receipts_of_user_in_room(store, "!r7:example.org", user_name(3U)).empty());
                auto const replaced = db::receipts_of_user_in_room(store, "!r7:example.org", user_name(4U));
                REQUIRE(replaced.size() == 1U);
                REQUIRE(replaced.front()->event_id == "$newer");
                REQUIRE(db::receipts_in_room(store, "!r7:example.org").size() == 10U);
                REQUIRE(db::receipts_in_room(store, "!r8:example.org").size() == 10U);
                REQUIRE(store.receipts.size() == 400U);
            }
        }
    }
}

SCENARIO("receipt indexes are rebuilt when the store is loaded again", "[receipts][c23][index]")
{
    GIVEN("a database holding receipts, some of them deleted afterwards")
    {
        auto const path = unique_sqlite_path();
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            for (auto user = std::size_t{0U}; user < 6U; ++user)
            {
                REQUIRE(db::store_receipt(opened.store, make_receipt("!a:example.org", user_name(user), "$a")));
                REQUIRE(
                    db::store_receipt(opened.store, make_receipt("!b:example.org", user_name(user), "$b", "$root")));
            }
            REQUIRE(db::remove_receipt(opened.store, make_receipt("!a:example.org", user_name(0U), "$a")));
            REQUIRE(db::remove_receipt(opened.store, make_receipt("!b:example.org", user_name(5U), "$b", "$root")));
        }

        WHEN("the database is opened again")
        {
            auto reloaded = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reloaded.ok);
            auto& store = reloaded.store;

            THEN("both indexes are in step and answer exactly the surviving rows")
            {
                REQUIRE(store.receipts.size() == 10U);
                REQUIRE(store.receipt_room_index.in_step(store.receipts.size()));
                REQUIRE(store.receipt_user_room_index.in_step(store.receipts.size()));
                auto const before = store.receipt_rows_examined.value();
                REQUIRE(db::receipts_in_room(store, "!a:example.org").size() == 5U);
                REQUIRE(db::receipts_in_room(store, "!b:example.org").size() == 5U);
                REQUIRE(db::receipts_of_user_in_room(store, "!a:example.org", user_name(0U)).empty());
                REQUIRE(db::receipts_of_user_in_room(store, "!b:example.org", user_name(5U)).empty());
                REQUIRE(db::receipts_of_user_in_room(store, "!b:example.org", user_name(2U)).size() == 1U);
                REQUIRE(store.receipt_rows_examined.value() - before == 11U);
            }

            THEN("a write after the reload keeps them in step")
            {
                REQUIRE(db::store_receipt(store, make_receipt("!a:example.org", user_name(0U), "$back")));
                REQUIRE(store.receipt_user_room_index.in_step(store.receipts.size()));
                REQUIRE(db::receipts_in_room(store, "!a:example.org").size() == 6U);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("one user's threaded receipts in one room are capped, oldest first", "[receipts][c23][cap]")
{
    GIVEN("a user holding unthreaded, main and a full set of threaded receipts, and another user")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const room = std::string{"!room:example.org"};
        auto const alice = std::string{"@alice:example.org"};
        auto const bob = std::string{"@bob:example.org"};
        REQUIRE(db::store_receipt(store, make_receipt(room, alice, "$plain")));
        REQUIRE(db::store_receipt(store, make_receipt(room, alice, "$main", "main")));
        REQUIRE(db::store_receipt(store, make_receipt(room, bob, "$bob", "$bobroot")));
        auto const cap = db::max_threaded_receipt_rows_per_user_room;
        for (auto thread = std::size_t{0U}; thread < cap; ++thread)
        {
            REQUIRE(db::store_receipt(
                store, make_receipt(room, alice, "$t" + std::to_string(thread), "$root" + std::to_string(thread))));
        }

        THEN("the cap's worth of threaded rows is served")
        {
            REQUIRE(thread_rows(store, room, alice) == cap);
        }

        WHEN("an existing thread's receipt is moved")
        {
            REQUIRE(db::store_receipt(store, make_receipt(room, alice, "$moved", "$root0")));

            THEN("it replaces its row and evicts nothing")
            {
                REQUIRE(thread_rows(store, room, alice) == cap);
                auto const first_thread = std::ranges::count_if(db::receipts_of_user_in_room(store, room, alice),
                                                                [](db::PersistentReceipt const* row) {
                                                                    return row->thread_id == "$root0";
                                                                });
                REQUIRE(first_thread == 1);
            }
        }

        WHEN("a receipt for one more thread is stored")
        {
            REQUIRE(db::store_receipt(store, make_receipt(room, alice, "$over", "$rootover")));

            THEN("the user's oldest threaded row is gone and the count stays at the cap")
            {
                REQUIRE(thread_rows(store, room, alice) == cap);
                auto const rows = db::receipts_of_user_in_room(store, room, alice);
                REQUIRE(std::ranges::none_of(rows, [](db::PersistentReceipt const* row) {
                    return row->thread_id == "$root0";
                }));
                REQUIRE(std::ranges::any_of(rows, [](db::PersistentReceipt const* row) {
                    return row->thread_id == "$rootover";
                }));
            }

            THEN("the unthreaded and main rows of the user, and the other user's rows, are kept")
            {
                auto const rows = db::receipts_of_user_in_room(store, room, alice);
                REQUIRE(std::ranges::any_of(rows, [](db::PersistentReceipt const* row) {
                    return row->thread_id.empty() && row->event_id == "$plain";
                }));
                REQUIRE(std::ranges::any_of(rows, [](db::PersistentReceipt const* row) {
                    return row->thread_id == "main";
                }));
                REQUIRE(db::receipts_of_user_in_room(store, room, bob).size() == 1U);
            }

            THEN("the indexes are in step and the eviction is durable in the mirror")
            {
                REQUIRE(store.receipt_room_index.in_step(store.receipts.size()));
                REQUIRE(store.receipt_user_room_index.in_step(store.receipts.size()));
                REQUIRE(store.receipts.size() == cap + 3U);
            }
        }

        WHEN("the same number of threaded receipts is stored in another room")
        {
            for (auto thread = std::size_t{0U}; thread < cap; ++thread)
            {
                REQUIRE(
                    db::store_receipt(store, make_receipt("!other:example.org", alice, "$o" + std::to_string(thread),
                                                          "$root" + std::to_string(thread))));
            }

            THEN("the cap is per room: both rooms hold a full set")
            {
                REQUIRE(thread_rows(store, room, alice) == cap);
                REQUIRE(thread_rows(store, "!other:example.org", alice) == cap);
            }
        }
    }
}
