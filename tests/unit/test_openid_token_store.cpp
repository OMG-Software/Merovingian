// SPDX-License-Identifier: GPL-3.0-or-later
//
// PersistentStore-level coverage for OpenID tokens (Matrix v1.19 CS API
// §OpenID / SS API §OpenID). See tests/unit/test_homeserver_auth_service.cpp
// for the higher-level mint/redeem and access-token-separation coverage;
// this file exercises store_openid_token itself in isolation.

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
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
