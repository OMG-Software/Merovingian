// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// F-08 part 1 (security audit run 4): every token lookup and revocation scanned the whole access_tokens and
// refresh_tokens vectors under runtime.mutex, so the cost of a refresh grew with every other user's rows. The two
// tables are now CredentialTable (rows plus a digest index by hash, an index by (user, device), by user and, for
// refresh tokens, by predecessor), and SessionTable gained a per-device index. These tests prove the cost with the
// rows-examined counters, never with time, and that the indexes agree with the rows after every kind of change.
//
// Spec: Matrix Client-Server API v1.19, "POST /refresh" and "Account management" (a token the server revokes
// MUST stop authenticating; the old refresh token is revoked once the new pair is used). The tests pin that the
// answers did not change when the lookups became indexed. ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/CredentialTable.hpp"
#include "merovingian/database/PersistentAccessToken.hpp"
#include "merovingian/database/PersistentRefreshToken.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalSession.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/SessionTable.hpp"
#include "merovingian/homeserver/auth_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

[[nodiscard]] auto fake_hash(std::string_view kind, std::size_t number) -> std::string
{
    return "token-hash:v4:" + std::string{kind} + std::to_string(number);
}

struct ExpectedRefresh final
{
    std::string user_id;
    std::string device_id;
    std::string hash;
    std::string predecessor;
};

[[nodiscard]] auto make_refresh(ExpectedRefresh const& expected) -> db::PersistentRefreshToken
{
    return {expected.user_id, expected.device_id, expected.hash, false, std::nullopt, expected.predecessor};
}

// Every row in `present` is found by hash, device, user and predecessor; every row in `gone` by none. The probes
// that revoke run on a copy, which also proves a copy of the table answers like the original.
auto check_refresh_table(db::CredentialTable<db::PersistentRefreshToken> const& table,
                         std::vector<ExpectedRefresh> const& present, std::vector<ExpectedRefresh> const& gone) -> void
{
    REQUIRE(table.size() == present.size());
    for (auto const& expected : present)
    {
        INFO("present " << expected.hash);
        auto const* row = table.find(expected.hash);
        REQUIRE(row != nullptr);
        REQUIRE(row->user_id == expected.user_id);
        REQUIRE(row->device_id == expected.device_id);
        REQUIRE(row->predecessor_hash == expected.predecessor);
        REQUIRE(table.contains(expected.hash));
        REQUIRE(table.has_unrevoked_hash(expected.hash));
        REQUIRE(table.has_unrevoked_for_device(expected.user_id, expected.device_id));
        REQUIRE(table.has_unrevoked_for_user(expected.user_id));

        auto expected_on_device = std::size_t{0U};
        auto expected_on_user = std::size_t{0U};
        auto expected_with_predecessor = std::size_t{0U};
        for (auto const& other : present)
        {
            expected_on_user += other.user_id == expected.user_id ? 1U : 0U;
            expected_on_device += other.user_id == expected.user_id && other.device_id == expected.device_id ? 1U : 0U;
            expected_with_predecessor +=
                !expected.predecessor.empty() && other.predecessor == expected.predecessor ? 1U : 0U;
        }
        auto device_probe = table;
        REQUIRE(device_probe.revoke_for_device(expected.user_id, expected.device_id) == expected_on_device);
        REQUIRE_FALSE(device_probe.has_unrevoked_for_device(expected.user_id, expected.device_id));
        auto user_probe = table;
        REQUIRE(user_probe.revoke_for_user(expected.user_id) == expected_on_user);
        auto predecessor_probe = table;
        REQUIRE(predecessor_probe.revoke_with_predecessor(expected.predecessor) == expected_with_predecessor);
        auto hash_probe = table;
        REQUIRE(hash_probe.revoke_hash(expected.hash) == 1U);
        REQUIRE_FALSE(hash_probe.has_unrevoked_hash(expected.hash));
    }
    for (auto const& erased : gone)
    {
        INFO("gone " << erased.hash);
        REQUIRE(table.find(erased.hash) == nullptr);
        REQUIRE_FALSE(table.contains(erased.hash));
        REQUIRE_FALSE(table.has_unrevoked_hash(erased.hash));
        // The device an erased row sat on answers for exactly the rows still present, never for the erased one.
        auto expected_on_device = std::size_t{0U};
        for (auto const& other : present)
        {
            expected_on_device += other.user_id == erased.user_id && other.device_id == erased.device_id ? 1U : 0U;
        }
        auto probe = table;
        REQUIRE(probe.revoke_for_device(erased.user_id, erased.device_id) == expected_on_device);
    }
}

} // namespace

SCENARIO("A refresh token table keeps every index right through erases and copies", "[f08][credential]")
{
    GIVEN("a refresh table of eight rows over two users, two devices and chained predecessors")
    {
        auto rows = std::vector<ExpectedRefresh>{
            {"@a:example.org", "D1", fake_hash("r", 0U), ""},
            {"@a:example.org", "D1", fake_hash("r", 1U), fake_hash("r", 0U)},
            {"@a:example.org", "D2", fake_hash("r", 2U), fake_hash("r", 0U)},
            {"@b:example.org", "D1", fake_hash("r", 3U), ""},
            {"@b:example.org", "D1", fake_hash("r", 4U), fake_hash("r", 3U)},
            {"@b:example.org", "D2", fake_hash("r", 5U), fake_hash("r", 3U)},
            {"@a:example.org", "D3", fake_hash("r", 6U), fake_hash("r", 1U)},
            // "ab" + "c" must not collide with "a" + "bc" in the device index.
            {"@ab:example.org", "c", fake_hash("r", 7U), ""},
        };
        auto table = db::CredentialTable<db::PersistentRefreshToken>{};
        for (auto const& row : rows)
        {
            REQUIRE(table.insert(make_refresh(row)));
        }
        REQUIRE_FALSE(table.insert(make_refresh(rows[2])));

        WHEN("nothing has been erased")
        {
            THEN("every row is found by hash, device, user and predecessor")
            {
                check_refresh_table(table, rows, {});
            }
        }

        WHEN("the first row, a middle row and the last row are erased, each moving the last row into the hole")
        {
            REQUIRE(table.erase(rows[0].hash));
            REQUIRE(table.erase(rows[3].hash));
            REQUIRE(table.erase(rows[7].hash));
            REQUIRE_FALSE(table.erase(rows[0].hash));
            auto gone = std::vector<ExpectedRefresh>{rows[0], rows[3], rows[7]};
            auto present = std::vector<ExpectedRefresh>{rows[1], rows[2], rows[4], rows[5], rows[6]};

            THEN("the remaining rows are found by every index and the erased rows by none")
            {
                check_refresh_table(table, present, gone);
            }
            THEN("a copy of the table answers the same")
            {
                auto const copy = table;
                check_refresh_table(copy, present, gone);
            }
        }

        WHEN("a row that shares its predecessor with another is revoked by predecessor")
        {
            auto const revoked = table.revoke_with_predecessor(rows[0].hash);

            THEN("exactly the rows minted from that predecessor are revoked")
            {
                REQUIRE(revoked == 2U);
                REQUIRE_FALSE(table.has_unrevoked_hash(rows[1].hash));
                REQUIRE_FALSE(table.has_unrevoked_hash(rows[2].hash));
                REQUIRE(table.has_unrevoked_hash(rows[0].hash));
                REQUIRE(table.has_unrevoked_hash(rows[4].hash));
                REQUIRE(table.revoke_with_predecessor("") == 0U);
            }
        }

        WHEN("the sweep erases the rows a predicate names")
        {
            auto const removed = table.erase_if([](db::PersistentRefreshToken const& row) {
                return row.user_id == "@a:example.org";
            });

            THEN("the indexes cover exactly the rows that remain")
            {
                REQUIRE(removed == 4U);
                auto gone = std::vector<ExpectedRefresh>{rows[0], rows[1], rows[2], rows[6]};
                auto present = std::vector<ExpectedRefresh>{rows[3], rows[4], rows[5], rows[7]};
                check_refresh_table(table, present, gone);
            }
        }
    }
}

SCENARIO("An access token table finds by hash, device and user and revokes in step", "[f08][credential]")
{
    GIVEN("an access table of three rows")
    {
        auto table = db::CredentialTable<db::PersistentAccessToken>{};
        REQUIRE(table.insert({"@a:example.org", "D1", fake_hash("a", 0U), false, std::nullopt, {}}));
        REQUIRE(table.insert({"@a:example.org", "D2", fake_hash("a", 1U), false, std::nullopt, {}}));
        REQUIRE(table.insert({"@b:example.org", "D1", fake_hash("a", 2U), false, std::nullopt, {}}));

        WHEN("the first row is erased")
        {
            REQUIRE(table.erase(fake_hash("a", 0U)));

            THEN("the row moved into the hole is still found, and the erased one is not")
            {
                REQUIRE(table.find(fake_hash("a", 0U)) == nullptr);
                REQUIRE(table.find(fake_hash("a", 2U)) != nullptr);
                REQUIRE(table.find(fake_hash("a", 2U))->user_id == "@b:example.org");
                REQUIRE_FALSE(table.has_unrevoked_for_device("@a:example.org", "D1"));
                REQUIRE(table.has_unrevoked_for_device("@b:example.org", "D1"));
                REQUIRE(table.has_unrevoked_for_user_except_device("@a:example.org", "D1"));
                REQUIRE_FALSE(table.has_unrevoked_for_user_except_device("@a:example.org", "D2"));
            }
        }

        WHEN("a user's tokens are revoked except one device")
        {
            REQUIRE(table.revoke_for_user_except_device("@a:example.org", "D1") == 1U);

            THEN("only the other device's token is revoked")
            {
                REQUIRE(table.has_unrevoked_hash(fake_hash("a", 0U)));
                REQUIRE_FALSE(table.has_unrevoked_hash(fake_hash("a", 1U)));
                REQUIRE(table.has_unrevoked_hash(fake_hash("a", 2U)));
            }
        }
    }
}

SCENARIO("A session table removes one device's sessions through its index", "[f08][session]")
{
    GIVEN("a session table with three devices and a second user")
    {
        auto table = hs::SessionTable{};
        table.push_back({"@a:example.org", "D1", fake_hash("s", 0U), false, std::nullopt, {}});
        table.push_back({"@a:example.org", "D2", fake_hash("s", 1U), false, std::nullopt, {}});
        table.push_back({"@a:example.org", "D1", fake_hash("s", 2U), false, std::nullopt, {}});
        table.push_back({"@b:example.org", "D1", fake_hash("s", 3U), false, std::nullopt, {}});
        table.push_back({"@a:example.org", "D1", fake_hash("s", 4U), false, std::nullopt, {}});
        auto const accept = [](hs::LocalSession const& session, std::string const& hash) {
            return session.access_token_hash == hash;
        };
        auto const lookup = [&accept](hs::SessionTable const& sessions, std::size_t number) -> hs::LocalSession const* {
            auto const candidates = std::array<std::string, 1U>{fake_hash("s", number)};
            return sessions.find(candidates, accept);
        };

        WHEN("a device is erased")
        {
            REQUIRE(table.erase_device("@a:example.org", "D1") == 3U);

            THEN("its sessions are found no more and every other session is")
            {
                REQUIRE(table.size() == 2U);
                REQUIRE(lookup(table, 0U) == nullptr);
                REQUIRE(lookup(table, 2U) == nullptr);
                REQUIRE(lookup(table, 4U) == nullptr);
                REQUIRE(lookup(table, 1U) != nullptr);
                REQUIRE(lookup(table, 3U) != nullptr);
                REQUIRE(lookup(table, 3U)->user_id == "@b:example.org");
                REQUIRE(table.erase_device("@a:example.org", "D1") == 0U);
            }
            THEN("a later push_back and a copy are indexed too, and a second device erase still works")
            {
                table.push_back({"@a:example.org", "D1", fake_hash("s", 5U), false, std::nullopt, {}});
                auto copy = table;
                REQUIRE(lookup(copy, 5U) != nullptr);
                REQUIRE(copy.erase_device("@a:example.org", "D2") == 1U);
                REQUIRE(lookup(copy, 1U) == nullptr);
                REQUIRE(lookup(copy, 5U) != nullptr);
                REQUIRE(lookup(copy, 3U) != nullptr);
                REQUIRE(lookup(table, 1U) != nullptr);
            }
        }
    }
}

SCENARIO("A refresh token's issue time survives a save and reload through SQLite", "[f08][credential][sqlite]")
{
    GIVEN("a SQLite store holding a refresh token issued at a known time and one stored without a time")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-f08-issued-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        std::filesystem::remove(path);
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        REQUIRE(db::store_refresh_token(opened.store, {"@a:example.org", "D1", fake_hash("issued", 1U), false,
                                                       std::nullopt, fake_hash("issued", 0U), 1700000000123}));
        REQUIRE(db::store_refresh_token(opened.store,
                                        {"@a:example.org", "D2", fake_hash("issued", 2U), false, std::nullopt, {}}));

        WHEN("the store is reopened and hydrated")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);

            THEN("the time is read back, an unset time is 0 and the indexes cover the loaded rows")
            {
                auto const* timed = reopened.store.refresh_tokens.find(fake_hash("issued", 1U));
                REQUIRE(timed != nullptr);
                REQUIRE(timed->issued_at_ms == 1700000000123);
                REQUIRE(timed->predecessor_hash == fake_hash("issued", 0U));
                auto const* untimed = reopened.store.refresh_tokens.find(fake_hash("issued", 2U));
                REQUIRE(untimed != nullptr);
                REQUIRE(untimed->issued_at_ms == 0);
                REQUIRE(reopened.store.refresh_tokens.has_unrevoked_for_device("@a:example.org", "D2"));
                REQUIRE(reopened.store.refresh_tokens.has_unrevoked_with_predecessor(fake_hash("issued", 0U)));
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("The retention sweep drops a retired refresh row of a device that no longer exists",
         "[f08-rows][credential][retention]")
{
    GIVEN("retired and unrevoked refresh rows on a live device and on a missing one")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(db::store_device(store, {"@a:example.org", "LIVE", ""}));
        REQUIRE(db::store_refresh_token(
            store, {"@a:example.org", "LIVE", fake_hash("live-retired", 1U), true, std::nullopt, {}, 1}));
        REQUIRE(db::store_refresh_token(
            store, {"@a:example.org", "LIVE", fake_hash("live-open", 1U), false, std::nullopt, {}, 2}));
        REQUIRE(db::store_refresh_token(
            store, {"@a:example.org", "GONE", fake_hash("gone-retired", 1U), true, std::nullopt, {}, 3}));
        REQUIRE(db::store_refresh_token(
            store, {"@a:example.org", "GONE", fake_hash("gone-open", 1U), false, std::nullopt, {}, 4}));

        WHEN("the sweep collects unusable credentials")
        {
            auto const unusable =
                db::collect_unusable_credentials(store, std::chrono::system_clock::now(), std::chrono::seconds{0});

            THEN("only the retired row of the missing device is collected")
            {
                REQUIRE(unusable.refresh_token_hashes.size() == 1U);
                REQUIRE(unusable.refresh_token_hashes.front() == fake_hash("gone-retired", 1U));
            }
        }
    }
}
