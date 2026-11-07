// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// CS8 (ADR-0548): the in-memory store behind POST /login/get_token. Single use, bounded, swept.

#include "merovingian/homeserver/LoginTokenStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{
using merovingian::homeserver::LoginTokenStore;
constexpr auto lifetime = 120000U;
} // namespace

SCENARIO("The login token store hands a token out once", "[cs8][login-token][homeserver]")
{
    GIVEN("a store holding one token for alice")
    {
        auto store = LoginTokenStore{};
        REQUIRE(store.issue("@alice:example.org", "hash-a", 1000U, lifetime, 4U, 16U).outcome ==
                LoginTokenStore::IssueOutcome::issued);

        WHEN("the token is redeemed twice")
        {
            auto const first = store.redeem("hash-a", 2000U);
            auto const second = store.redeem("hash-a", 2001U);

            THEN("only the first redemption names alice")
            {
                REQUIRE(first.has_value());
                REQUIRE(*first == "@alice:example.org");
                REQUIRE_FALSE(second.has_value());
                REQUIRE(store.size() == 0U);
            }
        }

        WHEN("an unknown hash is redeemed")
        {
            auto const result = store.redeem("hash-b", 2000U);

            THEN("nothing is returned and alice's token is kept")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(store.size() == 1U);
            }
        }

        WHEN("the token is redeemed exactly at its expiry")
        {
            auto const result = store.redeem("hash-a", 1000U + lifetime);

            THEN("it is refused and removed")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(store.size() == 0U);
            }
        }

        WHEN("the token is redeemed one millisecond before its expiry")
        {
            auto const result = store.redeem("hash-a", 1000U + lifetime - 1U);

            THEN("it is accepted")
            {
                REQUIRE(result.has_value());
            }
        }
    }
}

SCENARIO("The login token store is bounded and never evicts", "[cs8][login-token][homeserver]")
{
    GIVEN("a store with a per-user cap of two and a total cap of three")
    {
        auto store = LoginTokenStore{};
        REQUIRE(store.issue("@alice:example.org", "a1", 1000U, lifetime, 2U, 3U).outcome ==
                LoginTokenStore::IssueOutcome::issued);
        REQUIRE(store.issue("@alice:example.org", "a2", 2000U, lifetime, 2U, 3U).outcome ==
                LoginTokenStore::IssueOutcome::issued);

        WHEN("alice asks for a third")
        {
            auto const result = store.issue("@alice:example.org", "a3", 3000U, lifetime, 2U, 3U);

            THEN("it is refused with the delay until her oldest token expires")
            {
                REQUIRE(result.outcome == LoginTokenStore::IssueOutcome::user_cap_reached);
                REQUIRE(result.retry_after_ms == 1000U + lifetime - 3000U);
                REQUIRE(store.count_for_user("@alice:example.org") == 2U);
            }
        }

        WHEN("bob fills the server and carol asks")
        {
            REQUIRE(store.issue("@bob:example.org", "b1", 3000U, lifetime, 2U, 3U).outcome ==
                    LoginTokenStore::IssueOutcome::issued);
            auto const result = store.issue("@carol:example.org", "c1", 3001U, lifetime, 2U, 3U);

            THEN("carol is refused and nobody's token is evicted")
            {
                REQUIRE(result.outcome == LoginTokenStore::IssueOutcome::total_cap_reached);
                REQUIRE(store.size() == 3U);
            }
        }

        WHEN("alice's tokens have expired")
        {
            auto const result = store.issue("@alice:example.org", "a3", 2000U + lifetime, lifetime, 2U, 3U);

            THEN("the expired ones are swept and she can mint again")
            {
                REQUIRE(result.outcome == LoginTokenStore::IssueOutcome::issued);
                REQUIRE(store.size() == 1U);
            }
        }

        WHEN("alice's tokens are erased")
        {
            store.erase_user("@alice:example.org");

            THEN("none remain")
            {
                REQUIRE(store.size() == 0U);
            }
        }
    }
}
