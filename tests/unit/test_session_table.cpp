// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SessionTable.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace
{

using merovingian::homeserver::LocalSession;
using merovingian::homeserver::SessionTable;

auto hash_of(std::size_t number) -> std::string
{
    return "token-hash:v4:" + std::to_string(number);
}

auto session_with(std::size_t number) -> LocalSession
{
    return LocalSession{"@user" + std::to_string(number) + ":example.org",
                        "DEV" + std::to_string(number),
                        hash_of(number),
                        false,
                        std::nullopt,
                        {}};
}

auto fill(SessionTable& table, std::size_t count) -> void
{
    for (auto number = std::size_t{0U}; number < count; ++number)
    {
        table.push_back(session_with(number));
    }
}

} // namespace

SCENARIO("A session is found by its token hash without looking at the others", "[homeserver][session_table][p7]")
{
    GIVEN("a table of five thousand sessions")
    {
        auto table = SessionTable{};
        fill(table, 5000U);
        auto confirmations = std::size_t{0U};
        auto const accept = [&confirmations](LocalSession const& session, std::string const& hash) {
            ++confirmations;
            return session.access_token_hash == hash;
        };

        WHEN("the hash of one session is looked up")
        {
            auto const candidates = std::vector<std::string>{hash_of(4321U)};
            auto const* found = table.find(candidates, accept);

            THEN("that session is returned after confirming almost none of the others")
            {
                REQUIRE(found != nullptr);
                REQUIRE(found->user_id == "@user4321:example.org");
                REQUIRE(confirmations <= 4U);
            }
        }

        WHEN("a hash that belongs to no session is looked up")
        {
            auto const candidates = std::vector<std::string>{hash_of(999999U)};
            auto const* found = table.find(candidates, accept);

            THEN("nothing is found and almost no session is looked at")
            {
                REQUIRE(found == nullptr);
                REQUIRE(confirmations <= 4U);
            }
        }

        WHEN("one of several candidate hashes belongs to a session")
        {
            auto const candidates = std::vector<std::string>{hash_of(999998U), hash_of(17U), hash_of(999999U)};
            auto const* found = table.find(candidates, accept);

            THEN("the session is found")
            {
                REQUIRE(found != nullptr);
                REQUIRE(found->device_id == "DEV17");
            }
        }
    }
}

SCENARIO("A session whose hash is replaced is found by the new hash only", "[homeserver][session_table][p7]")
{
    GIVEN("a table of sessions")
    {
        auto table = SessionTable{};
        fill(table, 50U);
        auto const same = [](LocalSession const& session, std::string const& hash) {
            return session.access_token_hash == hash;
        };

        WHEN("one session's hash is replaced")
        {
            table.set_access_token_hash(table.front(), "token-hash:v4:upgraded");

            THEN("the old hash finds nothing and the new one finds the session")
            {
                REQUIRE(table.find(std::vector<std::string>{hash_of(0U)}, same) == nullptr);
                auto const* found = table.find(std::vector<std::string>{"token-hash:v4:upgraded"}, same);
                REQUIRE(found != nullptr);
                REQUIRE(found->device_id == "DEV0");
                REQUIRE(table.find(std::vector<std::string>{hash_of(1U)}, same) != nullptr);
            }
        }
    }
}

SCENARIO("Sessions that can no longer authenticate are erased and the rest stay findable",
         "[homeserver][session_table][p7]")
{
    GIVEN("a table where every other session is revoked")
    {
        auto table = SessionTable{};
        fill(table, 100U);
        for (auto number = std::size_t{0U}; number < table.size(); number += 2U)
        {
            (table.begin() + static_cast<std::ptrdiff_t>(number))->revoked = true;
        }
        auto const same = [](LocalSession const& session, std::string const& hash) {
            return session.access_token_hash == hash;
        };

        WHEN("the unusable sessions are erased")
        {
            auto const removed = table.erase_if([](LocalSession const& session) {
                return session.revoked;
            });

            THEN("only the live ones remain and each is still found by its hash")
            {
                REQUIRE(removed == 50U);
                REQUIRE(table.size() == 50U);
                REQUIRE(table.find(std::vector<std::string>{hash_of(0U)}, same) == nullptr);
                for (auto number = std::size_t{1U}; number < 100U; number += 2U)
                {
                    auto const* found = table.find(std::vector<std::string>{hash_of(number)}, same);
                    REQUIRE(found != nullptr);
                    REQUIRE(found->access_token_hash == hash_of(number));
                }
            }
        }
    }
}

SCENARIO("An index hit is only a candidate: the caller's constant-time confirmation decides",
         "[homeserver][session_table][p7][security]")
{
    GIVEN("a table with a revoked session and a session whose hash was changed behind the index")
    {
        auto table = SessionTable{};
        fill(table, 10U);
        (table.begin() + 3)->revoked = true;
        (table.begin() + 5)->access_token_hash = "token-hash:v4:written-behind-the-index";
        auto const live_and_matching = [](LocalSession const& session, std::string const& hash) {
            return session.access_token_hash == hash && !session.revoked;
        };

        WHEN("the revoked session's hash is looked up")
        {
            auto const* found = table.find(std::vector<std::string>{hash_of(3U)}, live_and_matching);

            THEN("it is a candidate the confirmation refuses")
            {
                REQUIRE(found == nullptr);
            }
        }

        WHEN("the hash the changed session had when it was indexed is looked up")
        {
            auto const* old_hash = table.find(std::vector<std::string>{hash_of(5U)}, live_and_matching);
            auto const* new_hash =
                table.find(std::vector<std::string>{"token-hash:v4:written-behind-the-index"}, live_and_matching);

            THEN("the lookup fails closed: neither the stale digest nor the unindexed hash authenticates")
            {
                REQUIRE(old_hash == nullptr);
                REQUIRE(new_hash == nullptr);
            }
        }
    }
}
