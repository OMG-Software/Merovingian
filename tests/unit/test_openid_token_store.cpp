// SPDX-License-Identifier: GPL-3.0-or-later
//
// PersistentStore-level coverage for OpenID tokens (Matrix v1.19 CS API
// §OpenID / SS API §OpenID). See tests/integration/test_homeserver_auth_service_flow.cpp
// for the higher-level mint/redeem and access-token-separation coverage;
// this file exercises store_openid_token itself in isolation.

#include "../support/TempDirectory.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>

SCENARIO("Persistent store inserts and retains OpenID tokens", "[database][persistence][openid]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const future = std::chrono::system_clock::now() + std::chrono::hours{1};

        WHEN("a valid OpenID token row is stored")
        {
            auto const stored = merovingian::database::store_openid_token(
                store, {"@alice:example.org", "token-hash:v2:abc123", future});

            THEN("it is persisted into the in-memory vector")
            {
                REQUIRE(stored);
                REQUIRE(store.openid_tokens.size() == 1U);
                REQUIRE(store.openid_tokens.front().user_id == "@alice:example.org");
                REQUIRE(store.openid_tokens.front().token_hash == "token-hash:v2:abc123");
            }
        }

        WHEN("a row with an empty user_id is stored")
        {
            auto const stored = merovingian::database::store_openid_token(store, {"", "token-hash:v2:abc123", future});

            THEN("the write is rejected and nothing is persisted")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.openid_tokens.empty());
            }
        }

        WHEN("a row with a malformed (non-hash-prefixed) token_hash is stored")
        {
            auto const stored =
                merovingian::database::store_openid_token(store, {"@alice:example.org", "not-a-hash", future});

            THEN("the write is rejected and nothing is persisted")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.openid_tokens.empty());
            }
        }
    }
}

SCENARIO("Persistent store prunes an already-expired OpenID token on the next insert without touching another "
         "user's unexpired token",
         "[database][persistence][openid][retention]")
{
    GIVEN("a store holding one token that has since expired and one still-valid token for a different user")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const future = std::chrono::system_clock::now() + std::chrono::hours{1};
        // Both rows are inserted while still valid. store_openid_token sweeps
        // every already-expired row on EVERY insert, including the row just
        // inserted -- so seeding an "already expired" row directly here would
        // be swept by its own insert call and never survive to be pruned by
        // a later one. Backdating alice's row after insertion instead
        // simulates real elapsed time between mint and a later insert, which
        // is the only way this situation arises in production (request_
        // openid_token always mints with a future expires_at).
        REQUIRE(merovingian::database::store_openid_token(store,
                                                          {"@alice:example.org", "token-hash:v2:will_expire", future}));
        REQUIRE(merovingian::database::store_openid_token(store,
                                                          {"@bob:example.org", "token-hash:v2:still_valid", future}));
        REQUIRE(store.openid_tokens.size() == 2U);
        for (auto& row : store.openid_tokens)
        {
            if (row.user_id == "@alice:example.org")
            {
                row.expires_at = std::chrono::system_clock::now() - std::chrono::hours{1};
            }
        }

        WHEN("a third, unrelated user's token is minted")
        {
            auto const stored = merovingian::database::store_openid_token(
                store, {"@carol:example.org", "token-hash:v2:carol_token", future});

            THEN("alice's expired row is swept, and bob's unexpired token survives untouched")
            {
                REQUIRE(stored);
                REQUIRE(store.openid_tokens.size() == 2U);
                for (auto const& row : store.openid_tokens)
                {
                    // The hazard this proves: a prune triggered by one user's
                    // (carol's) insert must never remove a DIFFERENT user's
                    // still-unexpired token. Only alice's now-expired row may
                    // be gone.
                    REQUIRE(row.user_id != "@alice:example.org");
                }
                auto const bob = std::ranges::find_if(store.openid_tokens, [](auto const& row) {
                    return row.user_id == "@bob:example.org";
                });
                REQUIRE(bob != store.openid_tokens.end());
                REQUIRE(bob->token_hash == "token-hash:v2:still_valid");
                auto const carol = std::ranges::find_if(store.openid_tokens, [](auto const& row) {
                    return row.user_id == "@carol:example.org";
                });
                REQUIRE(carol != store.openid_tokens.end());
            }
        }
    }
}

SCENARIO("Persistent store revokes every OpenID token of one user", "[database][persistence][openid][f77]")
{
    GIVEN("a store holding two tokens of one user and one of another")
    {
        auto store = merovingian::database::PersistentStore{};
        auto const future = std::chrono::system_clock::now() + std::chrono::hours{1};
        REQUIRE(merovingian::database::store_openid_token(store, {"@alice:example.org", "token-hash:v2:a1", future}));
        REQUIRE(merovingian::database::store_openid_token(store, {"@alice:example.org", "token-hash:v2:a2", future}));
        REQUIRE(merovingian::database::store_openid_token(store, {"@bob:example.org", "token-hash:v2:b1", future}));

        WHEN("the first user's tokens are revoked")
        {
            auto const revoked = merovingian::database::revoke_openid_tokens_for_user(store, "@alice:example.org");

            THEN("only the other user's token remains")
            {
                REQUIRE(revoked);
                REQUIRE(store.openid_tokens.size() == 1U);
                REQUIRE(store.openid_tokens.front().user_id == "@bob:example.org");
            }
        }

        WHEN("the deletion is forced to fail")
        {
            merovingian::database::force_persist_failure_for_statement(store, "revoke_openid_tokens_for_user");
            auto const revoked = merovingian::database::revoke_openid_tokens_for_user(store, "@alice:example.org");

            THEN("the failure is reported and every in-memory row stays, so the call can be repeated")
            {
                REQUIRE_FALSE(revoked);
                REQUIRE(store.openid_tokens.size() == 3U);
                REQUIRE(merovingian::database::revoke_openid_tokens_for_user(store, "@alice:example.org"));
                REQUIRE(store.openid_tokens.size() == 1U);
            }
        }

        WHEN("a user with no tokens is revoked")
        {
            auto const revoked = merovingian::database::revoke_openid_tokens_for_user(store, "@carol:example.org");

            THEN("it succeeds and nothing changes")
            {
                REQUIRE(revoked);
                REQUIRE(store.openid_tokens.size() == 3U);
            }
        }
    }
}

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto openid_hash(std::string const& user, std::size_t number) -> std::string
{
    return "token-hash:v4:" + user + "-" + std::to_string(number);
}

} // namespace

SCENARIO("A user holds a bounded number of live OpenID tokens", "[database][persistence][openid][c37]")
{
    GIVEN("a store and a user who mints more tokens than the cap")
    {
        auto store = db::PersistentStore{};
        auto const base = std::chrono::system_clock::now() + std::chrono::hours{1};
        auto const alice = std::string{"@alice:example.org"};
        auto const extra = std::size_t{5U};
        REQUIRE(db::store_openid_token(store, {"@bob:example.org", openid_hash("bob", 0U), base}));
        for (auto number = std::size_t{0U}; number < db::max_openid_tokens_per_user + extra; ++number)
        {
            REQUIRE(db::store_openid_token(
                store, {alice, openid_hash("alice", number), base + std::chrono::seconds{static_cast<long>(number)}}));
        }

        WHEN("the rows are counted")
        {
            auto const held = std::ranges::count_if(store.openid_tokens, [&alice](auto const& row) {
                return row.user_id == alice;
            });

            THEN("the user holds exactly the cap, the oldest were evicted and another user is untouched")
            {
                REQUIRE(static_cast<std::size_t>(held) == db::max_openid_tokens_per_user);
                REQUIRE(db::find_openid_token(store, openid_hash("alice", 0U)) == nullptr);
                REQUIRE(db::find_openid_token(store, openid_hash("alice", extra - 1U)) == nullptr);
                REQUIRE(db::find_openid_token(store, openid_hash("alice", extra)) != nullptr);
                REQUIRE(db::find_openid_token(
                            store, openid_hash("alice", db::max_openid_tokens_per_user + extra - 1U)) != nullptr);
                REQUIRE(db::find_openid_token(store, openid_hash("bob", 0U)) != nullptr);
                REQUIRE(store.openid_tokens.size() == db::max_openid_tokens_per_user + 1U);
            }
        }
    }
}

SCENARIO("Looking an OpenID token up costs one row however many tokens are held",
         "[database][persistence][openid][c37]")
{
    GIVEN("a store holding a thousand users' tokens")
    {
        auto store = db::PersistentStore{};
        auto const later = std::chrono::system_clock::now() + std::chrono::hours{1};
        for (auto number = std::size_t{0U}; number < 1000U; ++number)
        {
            auto const user = "@u" + std::to_string(number) + ":example.org";
            REQUIRE(db::store_openid_token(store, {user, openid_hash(user, 0U), later}));
        }

        WHEN("an unknown hash and a held hash are looked up")
        {
            auto const before = store.openid_rows_examined.value();
            auto const unknown = db::find_openid_token(store, "token-hash:v4:unknown");
            auto const unknown_cost = store.openid_rows_examined.value() - before;
            auto const held = db::find_openid_token(store, openid_hash("@u731:example.org", 0U));
            auto const held_cost = store.openid_rows_examined.value() - before - unknown_cost;

            THEN("each examines at most one row, and only the held one is found")
            {
                REQUIRE(unknown == nullptr);
                REQUIRE(unknown_cost <= 1U);
                REQUIRE(held != nullptr);
                REQUIRE(held->user_id == "@u731:example.org");
                REQUIRE(held_cost <= 1U);
            }
        }
    }
}

SCENARIO("Expired OpenID rows are swept in one commit", "[database][persistence][openid][c37]")
{
    GIVEN("a store with two hundred rows of many users that have all expired")
    {
        auto store = db::PersistentStore{};
        auto const later = std::chrono::system_clock::now() + std::chrono::hours{1};
        for (auto number = std::size_t{0U}; number < 200U; ++number)
        {
            auto const user = "@u" + std::to_string(number) + ":example.org";
            REQUIRE(db::store_openid_token(store, {user, openid_hash(user, 0U), later}));
        }
        for (auto& row : store.openid_tokens)
        {
            row.expires_at = std::chrono::system_clock::now() - std::chrono::minutes{1};
        }
        auto const commits_before = db::committed_transaction_count(store);

        WHEN("one more token is minted")
        {
            REQUIRE(db::store_openid_token(store, {"@fresh:example.org", openid_hash("fresh", 0U), later}));

            THEN("the mint and the sweep were one commit, and only the fresh row and a working index remain")
            {
                REQUIRE(db::committed_transaction_count(store) - commits_before == 1U);
                REQUIRE(store.openid_tokens.size() == 1U);
                REQUIRE(db::find_openid_token(store, openid_hash("fresh", 0U)) != nullptr);
                REQUIRE(db::find_openid_token(store, openid_hash("@u7:example.org", 0U)) == nullptr);
            }
        }
    }
}

SCENARIO("The OpenID indexes survive a delete and a reload", "[database][persistence][openid][sqlite][c37]")
{
    GIVEN("a SQLite store holding tokens of two users")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-c37-openid-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        std::filesystem::remove(path);
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto const later = std::chrono::system_clock::now() + std::chrono::hours{1};
        REQUIRE(db::store_openid_token(opened.store, {"@a:example.org", openid_hash("a", 1U), later}));
        REQUIRE(db::store_openid_token(opened.store, {"@a:example.org", openid_hash("a", 2U), later}));
        REQUIRE(db::store_openid_token(opened.store, {"@b:example.org", openid_hash("b", 1U), later}));

        WHEN("one user's tokens are revoked and the store is reopened")
        {
            REQUIRE(db::revoke_openid_tokens_for_user(opened.store, "@a:example.org"));
            REQUIRE(db::find_openid_token(opened.store, openid_hash("a", 1U)) == nullptr);
            REQUIRE(db::find_openid_token(opened.store, openid_hash("b", 1U)) != nullptr);
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);

            THEN("the loaded rows are indexed and the deleted ones are gone")
            {
                REQUIRE(reopened.store.openid_tokens.size() == 1U);
                REQUIRE(reopened.store.openid_hash_index.in_step(1U));
                auto const before = reopened.store.openid_rows_examined.value();
                REQUIRE(db::find_openid_token(reopened.store, openid_hash("b", 1U)) != nullptr);
                REQUIRE(db::find_openid_token(reopened.store, openid_hash("a", 2U)) == nullptr);
                REQUIRE(reopened.store.openid_rows_examined.value() - before <= 2U);
            }
        }
        std::filesystem::remove(path);
    }
}
