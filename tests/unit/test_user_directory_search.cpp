// SPDX-License-Identifier: GPL-3.0-or-later
//
// matching_directory_profiles: which profiles POST /user_directory/search offers (security audit run 2, F-50;
// ADR-0334).
// Spec: Matrix CS API v1.19 § User Directory: the search term is matched against "user ID and display name",
// and `limited` says the result list was truncated by the limit. Deactivated accounts are left out by this
// project (0.12.13 audit item 5).
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#user-directory

#include "merovingian/core/FoldedSubstringMatcher.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentUser.hpp"
#include "merovingian/homeserver/UserDirectorySearchStats.hpp"
#include "merovingian/homeserver/user_directory_search.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <utility>

namespace
{

using merovingian::core::FoldedSubstringMatcher;
using merovingian::database::PersistentProfile;
using merovingian::database::PersistentStore;
using merovingian::database::PersistentUser;
using merovingian::homeserver::matching_directory_profiles;
using merovingian::homeserver::UserDirectorySearchStats;

auto add_account(PersistentStore& store, std::string const& localpart, std::string const& displayname,
                 bool deactivated = false) -> void
{
    auto const user_id = "@" + localpart + ":example.org";
    auto account = PersistentUser{};
    account.user_id = user_id;
    account.deactivated = deactivated;
    store.users.push_back(std::move(account));
    store.profiles.push_back(PersistentProfile{user_id, displayname, {}});
}

} // namespace

SCENARIO("a user directory search matches names and IDs and leaves out deactivated accounts",
         "[user-directory][search]")
{
    GIVEN("three accounts, one of them deactivated")
    {
        auto store = PersistentStore{};
        add_account(store, "alice", "Alice Liddell");
        add_account(store, "alicia", "Other Name", true);
        add_account(store, "bob", "Bob");

        WHEN("a term in a display name and an ID is searched")
        {
            auto matcher = FoldedSubstringMatcher{"ALI"};
            auto stats = UserDirectorySearchStats{};
            auto const matched = matching_directory_profiles(store, matcher, stats);

            THEN("only the active account is offered")
            {
                REQUIRE(matched.size() == 1U);
                REQUIRE(matched.front()->user_id == "@alice:example.org");
            }
        }

        WHEN("a term only in a user ID is searched")
        {
            auto matcher = FoldedSubstringMatcher{"@bob:"};
            auto stats = UserDirectorySearchStats{};
            auto const matched = matching_directory_profiles(store, matcher, stats);

            THEN("the account is offered")
            {
                REQUIRE(matched.size() == 1U);
                REQUIRE(matched.front()->user_id == "@bob:example.org");
            }
        }
    }
}

// F-50: for every matching profile the old handler ran std::ranges::any_of over every account, so a one
// character term that matches everyone cost accounts * accounts comparisons under runtime.mutex.
SCENARIO("a search that matches every profile reads the account table once", "[user-directory][search][security]")
{
    auto const accounts_walked = [](std::size_t count) {
        auto store = PersistentStore{};
        for (auto i = std::size_t{0U}; i < count; ++i)
        {
            add_account(store, "user" + std::to_string(i), "Name " + std::to_string(i), i % 10U == 0U);
        }
        auto matcher = FoldedSubstringMatcher{"@"}; // in every user ID
        auto stats = UserDirectorySearchStats{};
        auto const matched = matching_directory_profiles(store, matcher, stats);
        return std::pair{stats, matched.size()};
    };

    GIVEN("stores of 10 and of 2000 accounts, a tenth of them deactivated")
    {
        WHEN("a term that every user ID holds is searched in each")
        {
            auto const [small_stats, small_matched] = accounts_walked(10U);
            auto const [large_stats, large_matched] = accounts_walked(2000U);

            THEN("each search walked the account table once, and examined each profile once")
            {
                REQUIRE(small_stats.user_table_walks == 1U);
                REQUIRE(large_stats.user_table_walks == 1U);
                REQUIRE(small_stats.profiles_examined == 10U);
                REQUIRE(large_stats.profiles_examined == 2000U);
            }

            THEN("every active account matched")
            {
                REQUIRE(small_matched == 9U);
                REQUIRE(large_matched == 1800U);
            }
        }
    }
}

SCENARIO("a display name built to nearly match costs no more than a pass over it", "[user-directory][search][security]")
{
    GIVEN("an account whose display name is 60000 a's and a term of 30000 a's ending in b")
    {
        auto store = PersistentStore{};
        add_account(store, "attacker", std::string(60000U, 'a'));
        auto matcher = FoldedSubstringMatcher{std::string(30000U, 'a') + "b"};
        auto stats = UserDirectorySearchStats{};

        WHEN("the directory is searched")
        {
            auto const matched = matching_directory_profiles(store, matcher, stats);

            THEN("nothing matches, in a number of steps linear in the bytes searched")
            {
                REQUIRE(matched.empty());
                REQUIRE(matcher.steps() <= 2U * (60000U + std::string{"@attacker:example.org"}.size()));
            }
        }
    }
}
