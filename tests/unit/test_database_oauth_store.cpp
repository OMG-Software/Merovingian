// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The OAuth 2.0 client and session tables (migration 002, ADR-0776, ADR-0777): the store functions on the memory
// and SQLite backends, the caps, the 24-hour touch rule counted in transactions, the idle-client order retention
// reads, and the session row that goes with its device in one transaction.
#include "../support/TempDirectory.hpp"
#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/OAuthClientStoreResult.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::OAuthClientStoreResult;
using merovingian::database::PersistentOAuthClient;
using merovingian::database::PersistentOAuthSession;
using merovingian::database::PersistentStore;

constexpr auto day_ms = std::uint64_t{24U} * 60U * 60U * 1000U;
constexpr auto all_times = std::numeric_limits<std::uint64_t>::max();

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-oauth-store-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto client(std::string id, std::uint64_t at_ms) -> PersistentOAuthClient
{
    return {std::move(id), R"({"client_name":"Example"})", at_ms, at_ms};
}

[[nodiscard]] auto session(std::string user, std::string device, std::string client_id) -> PersistentOAuthSession
{
    return {std::move(user), std::move(device), std::move(client_id), "urn:matrix:client:api:*", 1000U};
}

struct SqliteClose final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

// Runs one statement on its own connection to the file, outside the store.
[[nodiscard]] auto sqlite_run(std::filesystem::path const& path, char const* sql) -> bool
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    return opened == SQLITE_OK && sqlite3_exec(connection.get(), sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

} // namespace

SCENARIO("An OAuth client row is stored once, kept as first written, and refused over its caps",
         "[database][oauth][oauth-store]")
{
    GIVEN("a memory store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("a client is stored, stored again with other metadata, and oversized rows are offered")
        {
            auto const first = merovingian::database::store_oauth_client(store, client("client-a", 5000U));
            auto again = client("client-a", 9000U);
            again.metadata_json = R"({"client_name":"Other"})";
            auto const second = merovingian::database::store_oauth_client(store, again);

            auto at_cap = client(std::string(merovingian::database::max_oauth_client_id_bytes, 'c'), 1U);
            auto over_id = client(std::string(merovingian::database::max_oauth_client_id_bytes + 1U, 'c'), 1U);
            auto at_metadata = client("client-big", 1U);
            at_metadata.metadata_json = std::string(merovingian::database::max_oauth_client_metadata_bytes, 'm');
            auto over_metadata = client("client-bigger", 1U);
            over_metadata.metadata_json = std::string(merovingian::database::max_oauth_client_metadata_bytes + 1U, 'm');
            auto const transactions_before = merovingian::database::committed_transaction_count(store);
            auto const over_id_result = merovingian::database::store_oauth_client(store, over_id);
            auto const over_metadata_result = merovingian::database::store_oauth_client(store, over_metadata);
            auto const empty_id_result = merovingian::database::store_oauth_client(store, client("", 1U));
            auto const refused_transactions =
                merovingian::database::committed_transaction_count(store) - transactions_before;
            auto const at_cap_result = merovingian::database::store_oauth_client(store, at_cap);
            auto const at_metadata_result = merovingian::database::store_oauth_client(store, at_metadata);

            THEN("the first write inserts, the second keeps the first row, and only rows within the caps are stored")
            {
                REQUIRE(first == OAuthClientStoreResult::inserted);
                REQUIRE(second == OAuthClientStoreResult::existing);
                auto const* held = merovingian::database::find_oauth_client(store, "client-a");
                REQUIRE(held != nullptr);
                REQUIRE(held->metadata_json == R"({"client_name":"Example"})");
                REQUIRE(held->created_at_ms == 5000U);
                REQUIRE(over_id_result == OAuthClientStoreResult::refused);
                REQUIRE(over_metadata_result == OAuthClientStoreResult::refused);
                REQUIRE(empty_id_result == OAuthClientStoreResult::refused);
                REQUIRE(refused_transactions == 0U);
                REQUIRE(at_cap_result == OAuthClientStoreResult::inserted);
                REQUIRE(at_metadata_result == OAuthClientStoreResult::inserted);
                REQUIRE(merovingian::database::oauth_client_count(store) == 3U);
            }
        }
    }
}

SCENARIO("Using an OAuth client writes its last use at most once a day", "[database][oauth][oauth-store][touch]")
{
    GIVEN("a memory store holding a client last used at day 10")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const day_ten = 10U * day_ms;
        REQUIRE(merovingian::database::store_oauth_client(store, client("client-a", day_ten)) ==
                OAuthClientStoreResult::inserted);

        WHEN("it is used a thousand times within the day, then once just after the day, then from the past")
        {
            auto const before = merovingian::database::committed_transaction_count(store);
            auto all_ok = true;
            for (auto use = std::uint64_t{0U}; use < 1000U; ++use)
            {
                all_ok =
                    merovingian::database::touch_oauth_client(store, "client-a", day_ten + (use * 86'000U)) && all_ok;
            }
            all_ok = merovingian::database::touch_oauth_client(store, "client-a", day_ten + day_ms) && all_ok;
            auto const within_day = merovingian::database::committed_transaction_count(store) - before;
            auto const after_day = day_ten + day_ms + 1U;
            auto const touched = merovingian::database::touch_oauth_client(store, "client-a", after_day);
            auto const after_touch = merovingian::database::committed_transaction_count(store) - before;
            auto const from_past = merovingian::database::touch_oauth_client(store, "client-a", day_ten);
            auto const unknown = merovingian::database::touch_oauth_client(store, "client-unknown", after_day);

            THEN("nothing is written inside the day, exactly one write follows it, and the clock never goes back")
            {
                REQUIRE(all_ok);
                REQUIRE(within_day == 0U);
                REQUIRE(touched);
                REQUIRE(after_touch == 1U);
                REQUIRE(from_past);
                REQUIRE(merovingian::database::committed_transaction_count(store) - before == 1U);
                REQUIRE(merovingian::database::find_oauth_client(store, "client-a")->last_used_at_ms == after_day);
                REQUIRE_FALSE(unknown);
            }
        }
    }
}

SCENARIO("Sessionless OAuth clients are listed least recently used first without reading the sessions",
         "[database][oauth][oauth-store][retention]")
{
    GIVEN("a memory store with five clients, one of them holding a session")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        for (auto const& [id, at] : std::vector<std::pair<std::string, std::uint64_t>>{
                 {"client-e", 50U},
                 {"client-b", 20U},
                 {"client-a", 10U},
                 {"client-d", 40U},
                 {"client-c", 30U}
        })
        {
            REQUIRE(merovingian::database::store_oauth_client(store, client(id, at)) ==
                    OAuthClientStoreResult::inserted);
        }
        REQUIRE(merovingian::database::store_device(store, {"@alice:example.org", "DEVA", ""}));
        REQUIRE(merovingian::database::store_oauth_session(store, session("@alice:example.org", "DEVA", "client-b")));
        // Sessions that name no held client cost nothing either: the order is kept on the clients alone.
        for (auto index = 0; index < 50; ++index)
        {
            REQUIRE(merovingian::database::remember_oauth_session(
                store, session("@bob:example.org", "DEV" + std::to_string(index), "client-gone")));
        }

        WHEN("the sessionless clients are listed, capped, cut by time, and with one excluded")
        {
            auto const examined_before = store.oauth.rows_examined();
            auto const all = merovingian::database::oauth_clients_without_sessions(store, 10U, all_times);
            auto const examined = store.oauth.rows_examined() - examined_before;
            auto const capped = merovingian::database::oauth_clients_without_sessions(store, 2U, all_times);
            auto const before_forty = merovingian::database::oauth_clients_without_sessions(store, 10U, 40U);
            auto const without_a =
                merovingian::database::oauth_clients_without_sessions(store, 2U, all_times, [](std::string_view id) {
                    return id == "client-a";
                });

            THEN("they come oldest first, never the client with a session, and only the clients are walked")
            {
                REQUIRE(all == std::vector<std::string>{"client-a", "client-c", "client-d", "client-e"});
                REQUIRE(examined == 4U);
                REQUIRE(capped == std::vector<std::string>{"client-a", "client-c"});
                REQUIRE(before_forty == std::vector<std::string>{"client-a", "client-c"});
                REQUIRE(without_a == std::vector<std::string>{"client-c", "client-d"});
                REQUIRE(merovingian::database::oauth_client_has_session(store, "client-b"));
            }
        }

        WHEN("a client is touched, and the session is deleted")
        {
            REQUIRE(merovingian::database::touch_oauth_client(store, "client-a", 10U + (2U * day_ms)));
            REQUIRE(merovingian::database::delete_oauth_session(store, "@alice:example.org", "DEVA"));
            auto const order = merovingian::database::oauth_clients_without_sessions(store, 10U, all_times);

            THEN("the touched client moves to the back and the freed client takes its place by its last use")
            {
                REQUIRE(order == std::vector<std::string>{"client-b", "client-c", "client-d", "client-e", "client-a"});
                REQUIRE_FALSE(merovingian::database::oauth_client_has_session(store, "client-b"));
            }
        }
    }
}

SCENARIO("Deleting OAuth clients is all or nothing and never takes a client with a session",
         "[database][oauth][oauth-store][retention]")
{
    GIVEN("a memory store with 300 sessionless clients and one with a session")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto ids = std::vector<std::string>{};
        for (auto index = 0; index < 300; ++index)
        {
            ids.push_back("client-" + std::to_string(index));
            REQUIRE(merovingian::database::store_oauth_client(store, client(ids.back(), 1U)) ==
                    OAuthClientStoreResult::inserted);
        }
        REQUIRE(merovingian::database::store_oauth_client(store, client("client-held", 1U)) ==
                OAuthClientStoreResult::inserted);
        REQUIRE(merovingian::database::store_device(store, {"@alice:example.org", "DEVA", ""}));
        REQUIRE(
            merovingian::database::store_oauth_session(store, session("@alice:example.org", "DEVA", "client-held")));

        WHEN("sets naming the held client, an unknown client, or one client twice are offered")
        {
            auto const before = merovingian::database::committed_transaction_count(store);
            auto const with_held = std::vector<std::string>{"client-1", "client-held"};
            auto const with_unknown = std::vector<std::string>{"client-1", "client-unknown"};
            auto const with_repeat = std::vector<std::string>{"client-1", "client-1"};

            THEN("each is refused whole and nothing is written")
            {
                REQUIRE_FALSE(merovingian::database::delete_oauth_clients(store, with_held));
                REQUIRE_FALSE(merovingian::database::delete_oauth_clients(store, with_unknown));
                REQUIRE_FALSE(merovingian::database::delete_oauth_clients(store, with_repeat));
                REQUIRE(merovingian::database::committed_transaction_count(store) == before);
                REQUIRE(merovingian::database::oauth_client_count(store) == 301U);
            }
        }

        WHEN("the 300 sessionless clients are deleted, with the write forced to fail once first")
        {
            merovingian::database::force_next_persist_failures(store, 1U);
            auto const failed = merovingian::database::delete_oauth_clients(store, ids);
            auto const count_after_failure = merovingian::database::oauth_client_count(store);
            auto const before = merovingian::database::committed_transaction_count(store);
            auto const deleted = merovingian::database::delete_oauth_clients(store, ids);

            THEN("the failure changes nothing, and the delete is one transaction leaving only the held client")
            {
                REQUIRE_FALSE(failed);
                REQUIRE(count_after_failure == 301U);
                REQUIRE(deleted);
                REQUIRE(merovingian::database::committed_transaction_count(store) - before == 1U);
                REQUIRE(merovingian::database::oauth_client_count(store) == 1U);
                REQUIRE(merovingian::database::find_oauth_client(store, "client-held") != nullptr);
                REQUIRE(merovingian::database::oauth_clients_without_sessions(store, 10U, all_times).empty());
            }
        }
    }
}

SCENARIO("An OAuth session is keyed by user and device, read through the user's index, and capped",
         "[database][oauth][oauth-store]")
{
    GIVEN("a memory store holding one client")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_oauth_client(store, client("client-a", 1U)) ==
                OAuthClientStoreResult::inserted);
        for (auto index = 0; index < 3; ++index)
        {
            REQUIRE(merovingian::database::store_oauth_session(
                store, session("@alice:example.org", "DEV" + std::to_string(index), "client-a")));
        }
        for (auto index = 0; index < 40; ++index)
        {
            REQUIRE(merovingian::database::store_oauth_session(
                store, session("@bob:example.org", "DEV" + std::to_string(index), "client-a")));
        }

        WHEN("sessions are read and bad ones are prepared")
        {
            auto const examined_before = store.oauth.rows_examined();
            auto const alice = merovingian::database::oauth_sessions_of_user(store, "@alice:example.org");
            auto const examined = store.oauth.rows_examined() - examined_before;
            auto over_scope = session("@alice:example.org", "DEVX", "client-a");
            over_scope.scope = std::string(merovingian::database::max_oauth_scope_bytes + 1U, 's');
            auto at_scope = session("@alice:example.org", "DEVY", "client-a");
            at_scope.scope = std::string(merovingian::database::max_oauth_scope_bytes, 's');

            THEN("a user's sessions cost that user's rows, and every malformed or duplicate row is refused")
            {
                REQUIRE(alice.size() == 3U);
                REQUIRE(examined == 3U);
                auto const* found = merovingian::database::find_oauth_session(store, "@alice:example.org", "DEV1");
                REQUIRE(found != nullptr);
                REQUIRE(found->client_id == "client-a");
                REQUIRE(merovingian::database::find_oauth_session(store, "@alice:example.org", "DEV9") == nullptr);
                REQUIRE_FALSE(merovingian::database::prepare_oauth_session_insert(store, over_scope).has_value());
                REQUIRE(merovingian::database::prepare_oauth_session_insert(store, at_scope).has_value());
                REQUIRE_FALSE(merovingian::database::prepare_oauth_session_insert(
                                  store, session("@alice:example.org", "DEV1", "client-a"))
                                  .has_value());
                REQUIRE_FALSE(merovingian::database::prepare_oauth_session_insert(
                                  store, session("@alice:example.org", "DEVZ", "client-unknown"))
                                  .has_value());
                REQUIRE_FALSE(
                    merovingian::database::prepare_oauth_session_insert(store, session("", "DEVZ", "client-a"))
                        .has_value());
                REQUIRE_FALSE(merovingian::database::prepare_oauth_session_insert(
                                  store, session("@alice:example.org", "", "client-a"))
                                  .has_value());
            }
        }
    }
}

SCENARIO("A session row is written in the caller's own transaction with its device and tokens",
         "[database][oauth][oauth-store][composable]")
{
    GIVEN("a memory store holding a client and no device")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_oauth_client(store, client("client-a", 1U)) ==
                OAuthClientStoreResult::inserted);
        auto const row = session("@alice:example.org", "DEVA", "client-a");

        WHEN("the session statement joins a device insert in one transaction that fails, then one that commits")
        {
            auto const prepared = merovingian::database::prepare_oauth_session_insert(store, row);
            REQUIRE(prepared.has_value());
            auto const device_insert = merovingian::database::PreparedStatement{
                "insert_device",
                "INSERT INTO devices VALUES ($1, $2, $3)",
                {{"@alice:example.org", false}, {"DEVA", false}, {"", false}}
            };
            merovingian::database::force_persist_failure_for_statement(store, prepared->name);
            auto const failed = merovingian::database::commit_persistent_transaction(store, {device_insert, *prepared});
            auto const absent_after_failure =
                merovingian::database::find_oauth_session(store, "@alice:example.org", "DEVA") == nullptr;
            auto const before = merovingian::database::committed_transaction_count(store);
            auto const committed =
                merovingian::database::commit_persistent_transaction(store, {device_insert, *prepared});
            auto const remembered = committed && merovingian::database::remember_oauth_session(store, row);

            THEN("memory takes the session only after the one commit")
            {
                REQUIRE_FALSE(failed);
                REQUIRE(absent_after_failure);
                REQUIRE(committed);
                REQUIRE(merovingian::database::committed_transaction_count(store) - before == 1U);
                REQUIRE(remembered);
                REQUIRE(merovingian::database::oauth_client_has_session(store, "client-a"));
            }
        }
    }
}

SCENARIO("Deleting a device deletes its OAuth session in the same transaction",
         "[database][oauth][oauth-store][device]")
{
    GIVEN("a memory store with alice's OAuth device and a second device of hers")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_oauth_client(store, client("client-a", 1U)) ==
                OAuthClientStoreResult::inserted);
        REQUIRE(merovingian::database::store_device(store, {"@alice:example.org", "DEVA", ""}));
        REQUIRE(merovingian::database::store_device(store, {"@alice:example.org", "DEVB", ""}));
        REQUIRE(merovingian::database::store_oauth_session(store, session("@alice:example.org", "DEVA", "client-a")));
        REQUIRE(merovingian::database::store_oauth_session(store, session("@alice:example.org", "DEVB", "client-a")));

        WHEN("the session delete in the device's transaction fails")
        {
            merovingian::database::force_persist_failure_for_statement(store, "delete_oauth_session_of_device");
            auto const deleted = merovingian::database::delete_device(store, "@alice:example.org", "DEVA");

            THEN("the device and its session both stay")
            {
                REQUIRE_FALSE(deleted);
                REQUIRE(merovingian::database::has_user_device(store, "@alice:example.org", "DEVA"));
                REQUIRE(merovingian::database::find_oauth_session(store, "@alice:example.org", "DEVA") != nullptr);
            }
        }

        WHEN("the device is deleted")
        {
            auto const before = merovingian::database::committed_transaction_count(store);
            auto const deleted = merovingian::database::delete_device(store, "@alice:example.org", "DEVA");

            THEN("its session goes in the same one transaction and the other device keeps its session")
            {
                REQUIRE(deleted);
                REQUIRE(merovingian::database::committed_transaction_count(store) - before == 1U);
                REQUIRE_FALSE(merovingian::database::has_user_device(store, "@alice:example.org", "DEVA"));
                REQUIRE(merovingian::database::find_oauth_session(store, "@alice:example.org", "DEVA") == nullptr);
                REQUIRE(merovingian::database::find_oauth_session(store, "@alice:example.org", "DEVB") != nullptr);
                REQUIRE(merovingian::database::oauth_client_has_session(store, "client-a"));
            }
        }
    }
}

SCENARIO("OAuth clients and sessions survive a SQLite reopen, and a device delete takes both rows or neither",
         "[database][oauth][oauth-store][sqlite]")
{
    GIVEN("a SQLite store with a client, a touched last use, alice's OAuth device and a sessionless client")
    {
        auto const path = unique_sqlite_path("reopen");
        std::filesystem::remove(path);
        {
            auto opened = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            auto& store = opened.store;
            REQUIRE(merovingian::database::store_oauth_client(store, client("client-a", 1U)) ==
                    OAuthClientStoreResult::inserted);
            REQUIRE(merovingian::database::store_oauth_client(store, client("client-idle", 2U)) ==
                    OAuthClientStoreResult::inserted);
            REQUIRE(merovingian::database::touch_oauth_client(store, "client-a", 3U * day_ms));
            REQUIRE(merovingian::database::store_device(store, {"@alice:example.org", "DEVA", ""}));
            REQUIRE(
                merovingian::database::store_oauth_session(store, session("@alice:example.org", "DEVA", "client-a")));
        }

        WHEN("it is reopened")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const& store = reopened.store;

            THEN("both tables are hydrated with their values and the idle order")
            {
                auto const* held = merovingian::database::find_oauth_client(store, "client-a");
                REQUIRE(held != nullptr);
                REQUIRE(held->last_used_at_ms == 3U * day_ms);
                REQUIRE(held->created_at_ms == 1U);
                REQUIRE(held->metadata_json == R"({"client_name":"Example"})");
                auto const* row = merovingian::database::find_oauth_session(store, "@alice:example.org", "DEVA");
                REQUIRE(row != nullptr);
                REQUIRE(row->scope == "urn:matrix:client:api:*");
                REQUIRE(merovingian::database::oauth_clients_without_sessions(store, 10U, all_times) ==
                        std::vector<std::string>{"client-idle"});
            }
        }

        WHEN("the database refuses the session delete inside the device's transaction")
        {
            REQUIRE(sqlite_run(path, "CREATE TRIGGER refuse_oauth_session_delete BEFORE DELETE ON oauth_sessions "
                                     "BEGIN SELECT RAISE(ABORT, 'refused'); END"));
            auto reopened = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const deleted = merovingian::database::delete_device(reopened.store, "@alice:example.org", "DEVA");
            REQUIRE(sqlite_run(path, "DROP TRIGGER refuse_oauth_session_delete"));
            auto again = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(again.ok);

            THEN("the device row stays with the session row, in memory and on disk")
            {
                REQUIRE_FALSE(deleted);
                REQUIRE(merovingian::database::has_user_device(reopened.store, "@alice:example.org", "DEVA"));
                REQUIRE(merovingian::database::find_oauth_session(reopened.store, "@alice:example.org", "DEVA") !=
                        nullptr);
                REQUIRE(merovingian::database::has_user_device(again.store, "@alice:example.org", "DEVA"));
                REQUIRE(merovingian::database::find_oauth_session(again.store, "@alice:example.org", "DEVA") !=
                        nullptr);
            }
        }

        WHEN("the device is deleted")
        {
            {
                auto reopened = merovingian::database::open_sqlite_persistent_store(path.string());
                REQUIRE(reopened.ok);
                REQUIRE(merovingian::database::delete_device(reopened.store, "@alice:example.org", "DEVA"));
            }
            auto again = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(again.ok);

            THEN("the session row is gone from the file and its client is sessionless")
            {
                REQUIRE(merovingian::database::find_oauth_session(again.store, "@alice:example.org", "DEVA") ==
                        nullptr);
                REQUIRE_FALSE(merovingian::database::oauth_client_has_session(again.store, "client-a"));
            }
        }
        std::filesystem::remove(path);
    }
}
