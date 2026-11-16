// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Plan P6 (ADR-0796): the in-memory sessions of the account pages. Hashed, 15 minutes and never extended, four per user
// (the user's oldest goes), 4096 in all (a new sign-in is refused), and a form token bound to the session.

#include "merovingian/homeserver/AccountSessionStore.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

namespace
{

using merovingian::homeserver::AccountSessionStore;

constexpr auto start_ms = std::uint64_t{5'000'000U};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

[[nodiscard]] auto secret_of(std::variant<std::string, AccountSessionStore::Refusal> const& created) -> std::string
{
    REQUIRE(std::holds_alternative<std::string>(created));
    return std::get<std::string>(created);
}

} // namespace

SCENARIO("An account-page session is found by its secret alone and lives a fixed 15 minutes",
         "[oauth][oauth-account-session]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding one session of alice")
    {
        auto store = AccountSessionStore{};
        auto const secret = secret_of(store.create(alice, start_ms));

        WHEN("it is looked up just before its end, at its end, and with other secrets")
        {
            auto const live = store.find(secret, start_ms + AccountSessionStore::lifetime_ms - 1U);
            auto const wrong = store.find(std::string(64U, 'a'), start_ms + 1U);
            auto const empty = store.find({}, start_ms + 1U);
            auto const truncated = store.find(std::string_view{secret}.substr(0U, 63U), start_ms + 1U);
            auto const ended = store.find(secret, start_ms + AccountSessionStore::lifetime_ms);

            THEN("only the secret finds it, a use does not extend it, and the secret is 64 hex digits")
            {
                CHECK(secret.size() == 64U);
                CHECK(secret.find_first_not_of("0123456789abcdef") == std::string::npos);
                REQUIRE(live.has_value());
                CHECK(live->user_id == alice);
                CHECK(live->created_at_ms == start_ms);
                CHECK(live->expires_at_ms == start_ms + AccountSessionStore::lifetime_ms);
                CHECK_FALSE(wrong.has_value());
                CHECK_FALSE(empty.has_value());
                CHECK_FALSE(truncated.has_value());
                CHECK_FALSE(ended.has_value());
                CHECK(store.size() == 0U);
            }
        }
    }
}

SCENARIO("An account-page session ends alone, or with every session of its user", "[oauth][oauth-account-session]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("two sessions of alice and one of bob")
    {
        auto store = AccountSessionStore{};
        auto const first = secret_of(store.create(alice, start_ms));
        auto const second = secret_of(store.create(alice, start_ms + 1U));
        auto const bobs = secret_of(store.create(bob, start_ms + 2U));

        WHEN("one of alice's is ended, then all of alice's")
        {
            auto const ended_one = store.end(first, start_ms + 3U);
            auto const ended_again = store.end(first, start_ms + 3U);
            auto const second_after_one = store.find(second, start_ms + 3U).has_value();
            auto const ended_user = store.end_user(alice);

            THEN("each ends what it names and nothing of bob's")
            {
                CHECK(ended_one);
                CHECK_FALSE(ended_again);
                CHECK(second_after_one);
                CHECK(ended_user == 1U);
                CHECK_FALSE(store.find(second, start_ms + 3U).has_value());
                CHECK(store.find(bobs, start_ms + 3U).has_value());
                CHECK(store.live_count_for_user(alice, start_ms + 3U) == 0U);
                CHECK(store.live_count_for_user(bob, start_ms + 3U) == 1U);
            }
        }
    }
}

SCENARIO("A fifth sign-in of a user replaces that user's oldest session, never another user's",
         "[oauth][oauth-account-session]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("alice at the per-user cap and one session of bob")
    {
        auto store = AccountSessionStore{};
        auto alice_secrets = std::vector<std::string>{};
        for (auto index = std::size_t{0U}; index < AccountSessionStore::max_sessions_per_user; ++index)
        {
            alice_secrets.push_back(secret_of(store.create(alice, start_ms + index)));
        }
        auto const bobs = secret_of(store.create(bob, start_ms + 10U));

        WHEN("alice signs in once more")
        {
            auto const newest = secret_of(store.create(alice, start_ms + 20U));

            THEN("her oldest session is gone, the others and bob's stay")
            {
                CHECK_FALSE(store.find(alice_secrets.front(), start_ms + 21U).has_value());
                for (auto index = std::size_t{1U}; index < alice_secrets.size(); ++index)
                {
                    CHECK(store.find(alice_secrets.at(index), start_ms + 21U).has_value());
                }
                CHECK(store.find(newest, start_ms + 21U).has_value());
                CHECK(store.find(bobs, start_ms + 21U).has_value());
                CHECK(store.live_count_for_user(alice, start_ms + 21U) == AccountSessionStore::max_sessions_per_user);
            }
        }
    }
}

SCENARIO("A full account-session store refuses a new user's sign-in until a session expires",
         "[oauth][oauth-account-session]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("a store holding max_sessions sessions of other users")
    {
        auto store = AccountSessionStore{};
        for (auto index = std::size_t{0U}; index < AccountSessionStore::max_sessions; ++index)
        {
            std::ignore = secret_of(store.create("@user" + std::to_string(index) + ":example.org", start_ms));
        }

        WHEN("alice signs in while they live, and again once they have expired, and an empty user is given")
        {
            auto const refused = store.create(alice, start_ms + 1U);
            auto const no_user = store.create({}, start_ms + 1U);
            auto const later = store.create(alice, start_ms + AccountSessionStore::lifetime_ms);

            THEN("the first is store_full, the empty user no_user, and the later one succeeds after the purge")
            {
                REQUIRE(std::holds_alternative<AccountSessionStore::Refusal>(refused));
                CHECK(std::get<AccountSessionStore::Refusal>(refused) == AccountSessionStore::Refusal::store_full);
                REQUIRE(std::holds_alternative<AccountSessionStore::Refusal>(no_user));
                CHECK(std::get<AccountSessionStore::Refusal>(no_user) == AccountSessionStore::Refusal::no_user);
                CHECK(std::holds_alternative<std::string>(later));
                CHECK(store.size() == 1U);
            }
        }
    }
}

SCENARIO("The form token is bound to its session and is not the cookie value", "[oauth][oauth-account-session]")
{
    REQUIRE(sodium_init() >= 0);
    GIVEN("the secrets of two sessions")
    {
        auto store = AccountSessionStore{};
        auto const first = secret_of(store.create(alice, start_ms));
        auto const second = secret_of(store.create(bob, start_ms));

        WHEN("their form tokens are derived and compared")
        {
            auto const token = AccountSessionStore::form_token(first);
            auto const other = AccountSessionStore::form_token(second);
            auto const of_empty = AccountSessionStore::form_token({});

            THEN("each matches only its own session, and none is the secret")
            {
                REQUIRE(token.has_value());
                REQUIRE(other.has_value());
                CHECK(token->size() == 64U);
                CHECK(*token != first);
                CHECK(*token != *other);
                CHECK(AccountSessionStore::form_token(first) == token);
                CHECK(AccountSessionStore::form_token_matches(first, *token));
                CHECK_FALSE(AccountSessionStore::form_token_matches(first, *other));
                CHECK_FALSE(AccountSessionStore::form_token_matches(second, *token));
                CHECK_FALSE(AccountSessionStore::form_token_matches(first, first));
                CHECK_FALSE(AccountSessionStore::form_token_matches(first, {}));
                CHECK_FALSE(AccountSessionStore::form_token_matches(first, std::string_view{*token}.substr(0U, 63U)));
                CHECK_FALSE(of_empty.has_value());
            }
        }
    }
}
