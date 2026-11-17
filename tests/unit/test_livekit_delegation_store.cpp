// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The LiveKit delegation store functions (migration 004, ADR-0832): what each refuses, that a write is one
// transaction with bound parameters only, that memory changes only after a commit, replacement by key and by delay ID,
// the delete at deactivation, and a round trip through a SQLite file with strict hydration.
#include "../support/TempDirectory.hpp"
#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/LiveKitDelegationRowText.hpp"
#include "merovingian/database/LiveKitDelegationStore.hpp"
#include "merovingian/database/LiveKitDelegationTable.hpp"
#include "merovingian/database/PersistentLiveKitDelegation.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/TableLoadProfile.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sqlite3.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace db = merovingian::database;
using db::PersistentLiveKitDelegation;

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

[[nodiscard]] auto delegation(std::string delay_id, std::string_view user = alice, std::string_view member = "member-1")
    -> PersistentLiveKitDelegation
{
    return {std::move(delay_id), std::string{user}, "!room:example.org", "slot-1", std::string{member}, 1'000U};
}

[[nodiscard]] auto opened_store() -> db::PersistentStoreOpenResult
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    return opened;
}

struct SqliteClose final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

// Runs one query on its own connection to the file and returns the text of its first column of its first row.
[[nodiscard]] auto sqlite_first_text(std::filesystem::path const& path, char const* sql) -> std::string
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    auto text = std::string{};
    if (opened != SQLITE_OK)
    {
        return text;
    }
    auto* statement = static_cast<sqlite3_stmt*>(nullptr);
    if (sqlite3_prepare_v2(connection.get(), sql, -1, &statement, nullptr) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW)
    {
        auto const* value = sqlite3_column_text(statement, 0);
        if (value != nullptr)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            text = reinterpret_cast<char const*>(value);
        }
    }
    sqlite3_finalize(statement);
    return text;
}

using RawRow = std::array<std::string, db::livekit_delegation_row_columns>;

// The six columns of a valid row, as the text the store writes, for a test to change one of.
[[nodiscard]] auto raw_row(std::string delay_id) -> RawRow
{
    return {std::move(delay_id), std::string{alice}, "!room:example.org", "slot-9", "member-9", "1000"};
}

// Writes `values` to the store's database as one row of `livekit_delegations`, without touching memory (a
// bound-parameter insert, so any text goes in), the way a damaged or foreign file would hold it.
[[nodiscard]] auto insert_raw_row(db::PersistentStore& store, RawRow const& values) -> bool
{
    auto statement = db::PreparedStatement{
        "insert_raw_livekit_delegation",
        "INSERT INTO livekit_delegations (delay_id, user_id, room_id, slot_id, member_id, created_ms) VALUES ($1, $2, "
        "$3, $4, $5, $6)",
        {}};
    for (auto const& value : values)
    {
        statement.parameters.push_back(db::BoundValue{value, false});
    }
    return db::commit_persistent_transaction(store, {statement});
}

[[nodiscard]] auto temporary_database(std::string_view stem) -> std::filesystem::path
{
    return merovingian::tests::temporary_directory() /
           (std::string{stem} + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            ".sqlite3");
}

struct RawRowCase final
{
    std::string_view name{};
    std::size_t column{0U};
    std::string_view value{};
};

} // namespace

SCENARIO("A LiveKit delegation is stored, and a field outside its rules is refused",
         "[database][livekit-delegations][delegation-store]")
{
    GIVEN("an in-memory store")
    {
        auto opened = opened_store();
        auto& store = opened.store;

        WHEN("a valid row is stored")
        {
            auto const stored = db::store_livekit_delegation(store, delegation("d-1"));

            THEN("memory holds it under both lookups")
            {
                REQUIRE(stored);
                REQUIRE(store.livekit_delegations.size() == 1U);
                REQUIRE(store.livekit_delegations.find("d-1") != nullptr);
                REQUIRE(store.livekit_delegations.find("d-1")->created_ms == 1'000U);
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-1") ==
                        store.livekit_delegations.find("d-1"));
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 1U);
            }
        }

        WHEN("a row breaking one rule is stored")
        {
            auto const broken = GENERATE(
                std::pair<std::string_view, PersistentLiveKitDelegation>{"an empty delay ID", delegation("")},
                std::pair<std::string_view, PersistentLiveKitDelegation>{
                    "a 65-byte delay ID", delegation(std::string(db::max_livekit_delegation_delay_id_bytes + 1U, 'd'))},
                std::pair<std::string_view, PersistentLiveKitDelegation>{"an empty user", delegation("d-1", "")},
                std::pair<std::string_view, PersistentLiveKitDelegation>{
                    "a 256-byte user",
                    delegation("d-1", std::string(db::max_livekit_delegation_field_bytes + 1U, 'u'))},
                std::pair<std::string_view, PersistentLiveKitDelegation>{"an empty room",
                                                                         [] {
                                                                             auto made = delegation("d-1");
                                                                             made.room_id.clear();
                                                                             return made;
                                                                         }()},
                std::pair<std::string_view, PersistentLiveKitDelegation>{
                    "a 256-byte room",
                    [] {
                        auto made = delegation("d-1");
                        made.room_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 'r');
                        return made;
                    }()},
                std::pair<std::string_view, PersistentLiveKitDelegation>{"an empty slot",
                                                                         [] {
                                                                             auto made = delegation("d-1");
                                                                             made.slot_id.clear();
                                                                             return made;
                                                                         }()},
                std::pair<std::string_view, PersistentLiveKitDelegation>{
                    "a 256-byte slot",
                    [] {
                        auto made = delegation("d-1");
                        made.slot_id = std::string(db::max_livekit_delegation_field_bytes + 1U, 's');
                        return made;
                    }()},
                std::pair<std::string_view, PersistentLiveKitDelegation>{"an empty member",
                                                                         delegation("d-1", alice, "")},
                std::pair<std::string_view, PersistentLiveKitDelegation>{
                    "a 256-byte member",
                    delegation("d-1", alice, std::string(db::max_livekit_delegation_field_bytes + 1U, 'm'))},
                std::pair<std::string_view, PersistentLiveKitDelegation>{"a NUL byte in the delay ID",
                                                                         delegation(std::string{"d\0x", 3U})});
            INFO(broken.first);
            db::enable_statement_capture(store, 16U);
            auto const before = db::committed_transaction_count(store);
            auto const stored = db::store_livekit_delegation(store, broken.second);

            THEN("it is refused, nothing is written and memory is unchanged")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(db::committed_transaction_count(store) == before);
                REQUIRE(store.captured_statements.empty());
                REQUIRE(store.livekit_delegations.size() == 0U);
            }
        }

        WHEN("rows exactly at the caps are stored")
        {
            auto at_cap = delegation(std::string(db::max_livekit_delegation_delay_id_bytes, 'd'));
            at_cap.user_id = std::string(db::max_livekit_delegation_field_bytes, 'u');
            at_cap.room_id = std::string(db::max_livekit_delegation_field_bytes, 'r');
            at_cap.slot_id = std::string(db::max_livekit_delegation_field_bytes, 's');
            at_cap.member_id = std::string(db::max_livekit_delegation_field_bytes, 'm');

            THEN("the row is stored")
            {
                REQUIRE(db::store_livekit_delegation(store, at_cap));
                REQUIRE(store.livekit_delegations.size() == 1U);
            }
        }
    }
}

SCENARIO("A new delegation replaces the one holding its key or its delay ID in one transaction",
         "[database][livekit-delegations][delegation-store]")
{
    GIVEN("a store holding two delegations of one user")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_livekit_delegation(store, delegation("d-1", alice, "member-1")));
        REQUIRE(db::store_livekit_delegation(store, delegation("d-2", alice, "member-2")));
        REQUIRE(db::store_livekit_delegation(store, delegation("d-3", bob, "member-1")));

        WHEN("a delegation for the same key but a new delay ID is stored")
        {
            auto replacement = delegation("d-new", alice, "member-1");
            replacement.created_ms = 5'000U;
            auto const before = db::committed_transaction_count(store);
            auto const stored = db::store_livekit_delegation(store, replacement);

            THEN("the old delay ID is gone, the key answers the new row, and it was one transaction")
            {
                REQUIRE(stored);
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.livekit_delegations.size() == 3U);
                REQUIRE(store.livekit_delegations.find("d-1") == nullptr);
                REQUIRE(store.livekit_delegations.find("d-new") != nullptr);
                REQUIRE(store.livekit_delegations.find("d-new")->created_ms == 5'000U);
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-1") ==
                        store.livekit_delegations.find("d-new"));
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 2U);
            }
        }

        WHEN("a delegation for a new key but a delay ID already held is stored")
        {
            auto const before = db::committed_transaction_count(store);
            auto const stored = db::store_livekit_delegation(store, delegation("d-2", alice, "member-3"));

            THEN("the old row under that delay ID is gone, the new key answers it, and it was one transaction")
            {
                REQUIRE(stored);
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.livekit_delegations.size() == 3U);
                REQUIRE(store.livekit_delegations.find("d-2")->member_id == "member-3");
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-2") ==
                        nullptr);
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-3") ==
                        store.livekit_delegations.find("d-2"));
            }
        }

        WHEN("a delegation holding the key of one row and the delay ID of another is stored")
        {
            auto const stored = db::store_livekit_delegation(store, delegation("d-2", alice, "member-1"));

            THEN("both old rows are replaced by the one new row")
            {
                REQUIRE(stored);
                REQUIRE(store.livekit_delegations.size() == 2U);
                REQUIRE(store.livekit_delegations.find("d-1") == nullptr);
                REQUIRE(store.livekit_delegations.find("d-2")->member_id == "member-1");
                REQUIRE(store.livekit_delegations.find("d-3") != nullptr);
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 1U);
            }
        }

        WHEN("the same delegation is stored again")
        {
            auto const stored = db::store_livekit_delegation(store, delegation("d-1", alice, "member-1"));

            THEN("it is accepted and there is still one row for it")
            {
                REQUIRE(stored);
                REQUIRE(store.livekit_delegations.size() == 3U);
                REQUIRE(store.livekit_delegations.find("d-1") != nullptr);
            }
        }

        WHEN("the commit of a replacement fails")
        {
            db::force_next_persist_failures(store, 1U);
            auto const stored = db::store_livekit_delegation(store, delegation("d-new", alice, "member-1"));

            THEN("it reports the failure and memory still holds the old row")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.livekit_delegations.size() == 3U);
                REQUIRE(store.livekit_delegations.find("d-1") != nullptr);
                REQUIRE(store.livekit_delegations.find("d-new") == nullptr);
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-1") ==
                        store.livekit_delegations.find("d-1"));
            }
        }
    }
}

SCENARIO("A LiveKit delegation is written with bound parameters only",
         "[database][livekit-delegations][delegation-store]")
{
    GIVEN("a memory store capturing statements")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        db::enable_statement_capture(store, 16U);

        WHEN("a delegation is stored, replaced and deleted, and a user's rows are deleted")
        {
            REQUIRE(db::store_livekit_delegation(store, delegation("d-1")));
            REQUIRE(db::delete_livekit_delegation(store, "d-1"));
            REQUIRE(db::delete_livekit_delegations_of_user(store, alice));
            auto const& captured = store.captured_statements;

            THEN("every statement uses $n placeholders and none carries a value")
            {
                REQUIRE(captured.size() == 5U);
                for (auto const& statement : captured)
                {
                    INFO("statement " << statement.name);
                    REQUIRE(statement.sql.find('$') != std::string::npos);
                    REQUIRE(statement.sql.find("d-1") == std::string::npos);
                    REQUIRE(statement.sql.find(std::string{alice}) == std::string::npos);
                    REQUIRE(statement.sql.find("member-1") == std::string::npos);
                }
                REQUIRE(captured[0].name == "delete_livekit_delegation_by_key");
                REQUIRE(captured[0].parameters.size() == 4U);
                REQUIRE(captured[1].name == "delete_livekit_delegation_by_delay_id");
                REQUIRE(captured[2].name == "insert_livekit_delegation");
                REQUIRE(captured[2].parameters.size() == 6U);
                REQUIRE(captured[2].sql.find("$6") != std::string::npos);
                REQUIRE(captured[2].parameters[0].value == "d-1");
                REQUIRE(captured[2].parameters[5].value == "1000");
                REQUIRE(captured[3].sql == "DELETE FROM livekit_delegations WHERE delay_id = $1");
                REQUIRE(captured[4].sql == "DELETE FROM livekit_delegations WHERE user_id = $1");
                REQUIRE(captured[4].parameters[0].value == std::string{alice});
            }
        }
    }
}

SCENARIO("A delegation is deleted by delay ID, and a failed commit leaves it in memory",
         "[database][livekit-delegations][delegation-store]")
{
    GIVEN("a store holding two delegations")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_livekit_delegation(store, delegation("d-1", alice, "member-1")));
        REQUIRE(db::store_livekit_delegation(store, delegation("d-2", alice, "member-2")));

        WHEN("one is deleted, and then a delay ID that is not held")
        {
            auto const deleted = db::delete_livekit_delegation(store, "d-1");
            auto const absent = db::delete_livekit_delegation(store, "d-none");

            THEN("both report success and only the first row is gone")
            {
                REQUIRE(deleted);
                REQUIRE(absent);
                REQUIRE(store.livekit_delegations.size() == 1U);
                REQUIRE(store.livekit_delegations.find("d-1") == nullptr);
                REQUIRE(store.livekit_delegations.find_by_key(alice, "!room:example.org", "slot-1", "member-1") ==
                        nullptr);
                REQUIRE(store.livekit_delegations.find("d-2") != nullptr);
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 1U);
            }
        }

        WHEN("the commit of a delete fails")
        {
            db::force_next_persist_failures(store, 1U);
            auto const deleted = db::delete_livekit_delegation(store, "d-1");

            THEN("it reports the failure and memory is exactly as it was")
            {
                REQUIRE_FALSE(deleted);
                REQUIRE(store.livekit_delegations.size() == 2U);
                REQUIRE(store.livekit_delegations.find("d-1") != nullptr);
            }
        }
    }
}

SCENARIO("All of a user's LiveKit delegations are deleted in one statement",
         "[database][livekit-delegations][delegation-store]")
{
    GIVEN("a store holding delegations of two users")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_livekit_delegation(store, delegation("d-1", alice, "member-1")));
        REQUIRE(db::store_livekit_delegation(store, delegation("d-2", alice, "member-2")));
        REQUIRE(db::store_livekit_delegation(store, delegation("d-3", bob, "member-1")));

        WHEN("one user's delegations are deleted")
        {
            auto const before = db::committed_transaction_count(store);
            auto const deleted = db::delete_livekit_delegations_of_user(store, alice);

            THEN("they go in one transaction and the other user's stay")
            {
                REQUIRE(deleted);
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.livekit_delegations.size() == 1U);
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 0U);
                REQUIRE(store.livekit_delegations.find("d-3") != nullptr);
            }
        }

        WHEN("the commit of that delete fails")
        {
            db::force_next_persist_failures(store, 1U);
            auto const deleted = db::delete_livekit_delegations_of_user(store, alice);

            THEN("it reports the failure and memory is exactly as it was")
            {
                REQUIRE_FALSE(deleted);
                REQUIRE(store.livekit_delegations.size() == 3U);
                REQUIRE(store.livekit_delegations.count_of_user(alice) == 2U);
            }
        }

        WHEN("a user with no delegations is deleted")
        {
            auto const before = db::committed_transaction_count(store);
            auto const deleted = db::delete_livekit_delegations_of_user(store, "@nobody:example.org");

            THEN("the DELETE still runs, so a row hydration skipped does not outlive the account")
            {
                REQUIRE(deleted);
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.livekit_delegations.size() == 3U);
            }
        }
    }
}

SCENARIO("Deactivation deletes a LiveKit delegation that exists only in the database",
         "[database][livekit-delegations][delegation-store][sqlite]")
{
    GIVEN("a SQLite file holding a delegation memory never loaded")
    {
        auto const path = temporary_database("merovingian-livekit-delegations-skipped-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(insert_raw_row(opened.store, raw_row("z-hidden")));
            REQUIRE(opened.store.livekit_delegations.size() == 0U);

            WHEN("the user's delegations are deleted")
            {
                REQUIRE(db::delete_livekit_delegations_of_user(opened.store, alice));

                THEN("the row is gone from the file")
                {
                    REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM livekit_delegations") == "0");
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("LiveKit delegations survive a reopen of a SQLite store with every column and index",
         "[database][livekit-delegations][delegation-store][sqlite]")
{
    GIVEN("a SQLite store holding three delegations of two users, one replaced and one deleted")
    {
        auto const path = temporary_database("merovingian-livekit-delegations-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            auto first = delegation("d-1", alice, "member-1");
            first.created_ms = 123'456'789U;
            REQUIRE(db::store_livekit_delegation(opened.store, first));
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-2", alice, "member-2")));
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-3", bob, "member-1")));
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-4", bob, "member-1")));
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-5", bob, "member-9")));
            REQUIRE(db::delete_livekit_delegation(opened.store, "d-5"));
        }

        WHEN("the store is opened again")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const& table = reopened.store.livekit_delegations;

            THEN("exactly the surviving rows are back with every column, and the lookups answer")
            {
                REQUIRE(table.size() == 3U);
                REQUIRE(table.find("d-1") != nullptr);
                REQUIRE(table.find("d-1")->user_id == std::string{alice});
                REQUIRE(table.find("d-1")->room_id == "!room:example.org");
                REQUIRE(table.find("d-1")->slot_id == "slot-1");
                REQUIRE(table.find("d-1")->member_id == "member-1");
                REQUIRE(table.find("d-1")->created_ms == 123'456'789U);
                REQUIRE(table.find("d-3") == nullptr);
                REQUIRE(table.find("d-4") != nullptr);
                REQUIRE(table.find("d-5") == nullptr);
                REQUIRE(table.find_by_key(bob, "!room:example.org", "slot-1", "member-1") == table.find("d-4"));
                REQUIRE(table.count_of_user(alice) == 2U);
                REQUIRE(table.count_of_user(bob) == 1U);
                REQUIRE(reopened.store.livekit_delegation_rows_skipped_at_load == 0U);
            }
        }

        WHEN("a user's delegations are deleted and the store is opened again")
        {
            {
                auto opened = db::open_sqlite_persistent_store(path.string());
                REQUIRE(opened.ok);
                REQUIRE(db::delete_livekit_delegations_of_user(opened.store, alice));
            }
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the file agrees with memory")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.livekit_delegations.size() == 1U);
                REQUIRE(reopened.store.livekit_delegations.find("d-4") != nullptr);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM livekit_delegations") == "1");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Hydration reads a LiveKit delegation row strictly and counts the rows it skips",
         "[database][livekit-delegations][delegation-store][sqlite]")
{
    GIVEN("a SQLite file holding a valid row and one row that is not read exactly")
    {
        auto const bad =
            GENERATE(RawRowCase{"a created_ms that is not a number", 5U, "abc"},
                     RawRowCase{"an empty created_ms", 5U, ""}, RawRowCase{"a negative created_ms", 5U, "-5"},
                     RawRowCase{"a created_ms of 21 digits", 5U, "123456789012345678901"},
                     RawRowCase{"an empty user", 1U, ""}, RawRowCase{"an empty room", 2U, ""},
                     RawRowCase{"an empty slot", 3U, ""}, RawRowCase{"an empty member", 4U, ""});
        INFO(bad.name);
        auto const path = temporary_database("merovingian-livekit-delegations-strict-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("m-good")));
            auto damaged = raw_row("z-bad");
            damaged[bad.column] = std::string{bad.value};
            REQUIRE(insert_raw_row(opened.store, damaged));
        }

        WHEN("the store is opened")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the row is not loaded, stays in the file and is counted, and the valid row loads")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.livekit_delegations.size() == 1U);
                REQUIRE(reopened.store.livekit_delegations.find("z-bad") == nullptr);
                REQUIRE(reopened.store.livekit_delegations.find("m-good") != nullptr);
                REQUIRE(reopened.store.livekit_delegation_rows_skipped_at_load == 1U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM livekit_delegations WHERE delay_id = 'z-bad'") ==
                        "1");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Hydration skips a row that duplicates a key or an over-long field and counts it",
         "[database][livekit-delegations][delegation-store][sqlite]")
{
    GIVEN("a SQLite file holding a row, a second row with its key, and a row with an over-long delay ID")
    {
        auto const path = temporary_database("merovingian-livekit-delegations-dup-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("a-first", alice, "member-1")));
            auto same_key = raw_row("z-second");
            same_key[3] = "slot-1";
            same_key[4] = "member-1";
            REQUIRE(insert_raw_row(opened.store, same_key));
            REQUIRE(insert_raw_row(opened.store,
                                   raw_row(std::string(db::max_livekit_delegation_delay_id_bytes + 1U, 'x'))));
        }

        WHEN("the store is opened")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the first row keeps the key, the other two are skipped and counted, and all stay in the file")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.livekit_delegations.size() == 1U);
                REQUIRE(reopened.store.livekit_delegations.find("a-first") != nullptr);
                REQUIRE(reopened.store.livekit_delegations.find("z-second") == nullptr);
                REQUIRE(reopened.store.livekit_delegation_rows_skipped_at_load == 2U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM livekit_delegations") == "3");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A store opened with the federation worker profile does not load LiveKit delegations and leaves them in the "
         "file",
         "[database][livekit-delegations][delegation-store][sqlite]")
{
    GIVEN("a SQLite store holding two delegations")
    {
        auto const path = temporary_database("merovingian-livekit-delegations-profile-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-one")));
            REQUIRE(db::store_livekit_delegation(opened.store, delegation("d-two", bob)));
        }

        WHEN("it is opened with the full profile and with the federation worker profile")
        {
            auto const full = db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::full);
            auto const worker =
                db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::federation_worker);

            THEN("the full profile loads both, the worker profile loads none and counts no skipped row")
            {
                REQUIRE(full.ok);
                REQUIRE(full.store.livekit_delegations.size() == 2U);
                REQUIRE(worker.ok);
                REQUIRE(worker.store.livekit_delegations.size() == 0U);
                REQUIRE(worker.store.livekit_delegation_rows_skipped_at_load == 0U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM livekit_delegations") == "2");
            }
        }
        std::filesystem::remove(path);
    }
}
