// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Run-3 finding C38 (ADR-0653): the glob steps all the ACL checks of one EDU or request may spend together are bounded
// by one budget, however many rooms it names, and the answer for an (ACL event, server name) pair is remembered.
//
// Spec: Matrix Server-Server API v1.19, "Server Access Control Lists (ACLs) for rooms": a server is allowed when it
// matches no deny entry and at least one allow entry.
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/ServerAcl.hpp"
#include "merovingian/federation/ServerAclBudget.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstddef>
#include <string>
#include <tuple>
#include <utility>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;

// Adds a room whose ACL event holds `content`.
auto add_room_acl(db::PersistentStore& store, std::string const& room_id, std::string const& event_id,
                  std::string const& content) -> void
{
    store.state.push_back(db::PersistentStateEvent{room_id, "m.room.server_acl", "", event_id});
    store.events.push_back(
        db::PersistentEvent{event_id, room_id, "@a:example.org",
                            R"({"type":"m.room.server_acl","state_key":"","sender":"@a:example.org","content":)" +
                                content + R"(,"event_id":")" + event_id + R"("})",
                            0U, 0U});
}

// An event ID no earlier pass of a scenario has used: the ACL answer cache is process-wide and keyed by event, so each
// pass needs events of its own.
[[nodiscard]] auto fresh_event_id(std::string const& base) -> std::string
{
    static auto counter = std::atomic<std::size_t>{0U};
    return base + std::to_string(counter.fetch_add(1U));
}

// An ACL whose every deny pattern scans a long name to its end: far more steps than one check may spend.
[[nodiscard]] auto expensive_acl() -> std::string
{
    auto deny = std::string{};
    for (auto index = std::size_t{0U}; index < 4000U; ++index)
    {
        deny += (index == 0U ? "" : ",") + std::string{R"("*b")"};
    }
    return R"({"allow":["*"],"deny":[)" + deny + "]}";
}

} // namespace

SCENARIO("the ACL checks of one request spend from one shared step budget", "[federation][acl][c38][security]")
{
    GIVEN("thirty rooms, each with an ACL that costs a full check budget against a long server name")
    {
        auto store = db::PersistentStore{};
        for (auto room = std::size_t{0U}; room < 30U; ++room)
        {
            add_room_acl(store, "!r" + std::to_string(room) + ":example.org",
                         fresh_event_id("$acl" + std::to_string(room) + "-"), expensive_acl());
        }
        auto const long_name = std::string(200U, 'a') + ".example";

        WHEN("one request checks the origin against every room")
        {
            auto budget = fed::ServerAclBudget{};
            auto refused = std::size_t{0U};
            for (auto room = std::size_t{0U}; room < 30U; ++room)
            {
                if (!fed::room_server_acl_allows(store, "!r" + std::to_string(room) + ":example.org", long_name,
                                                 budget))
                {
                    ++refused;
                }
            }

            THEN("every check is refused and the whole request spent no more than its budget")
            {
                REQUIRE(refused == 30U);
                REQUIRE(budget.steps_left == 0U);
            }
        }
    }

    GIVEN("three hundred rooms with ordinary ACLs")
    {
        auto store = db::PersistentStore{};
        for (auto room = std::size_t{0U}; room < 300U; ++room)
        {
            add_room_acl(store, "!o" + std::to_string(room) + ":example.org",
                         fresh_event_id("$ordinary" + std::to_string(room) + "-"),
                         R"({"allow":["*.example.org","good.org"],"deny":["evil.org"]})");
        }

        WHEN("one request checks a legitimate origin against all of them")
        {
            auto budget = fed::ServerAclBudget{};
            auto allowed = std::size_t{0U};
            for (auto room = std::size_t{0U}; room < 300U; ++room)
            {
                if (fed::room_server_acl_allows(store, "!o" + std::to_string(room) + ":example.org", "good.org",
                                                budget))
                {
                    ++allowed;
                }
            }

            THEN("all are allowed and most of the budget is left")
            {
                REQUIRE(allowed == 300U);
                REQUIRE(budget.steps_left > fed::server_acl_request_glob_steps / 2U);
            }
        }
    }
}

SCENARIO("the answer for an ACL event and a server name is remembered", "[federation][acl][c38]")
{
    GIVEN("a room whose ACL denies one server")
    {
        auto store = db::PersistentStore{};
        auto const acl_event = fresh_event_id("$cacheacl");
        add_room_acl(store, "!c:example.org", acl_event, R"({"allow":["*"],"deny":["evil.org"]})");

        WHEN("the same name is checked twice, the second time in other letters and with a port")
        {
            auto first = fed::ServerAclBudget{};
            REQUIRE_FALSE(fed::room_server_acl_allows(store, "!c:example.org", "evil.org", first));
            auto second = fed::ServerAclBudget{};
            auto const again = fed::room_server_acl_allows(store, "!c:example.org", "EVIL.org:8448", second);

            THEN("the second check spends no step and gives the same answer")
            {
                REQUIRE_FALSE(again);
                REQUIRE(first.steps_left < fed::server_acl_request_glob_steps);
                REQUIRE(second.steps_left == fed::server_acl_request_glob_steps);
            }
        }

        WHEN("another name is checked")
        {
            auto budget = fed::ServerAclBudget{};
            REQUIRE(fed::room_server_acl_allows(store, "!c:example.org", "good.org", budget));

            THEN("it is evaluated on its own merits and spends steps")
            {
                REQUIRE(budget.steps_left < fed::server_acl_request_glob_steps);
            }
        }

        WHEN("the ACL event is redacted under the same event ID")
        {
            auto warm = fed::ServerAclBudget{};
            REQUIRE_FALSE(fed::room_server_acl_allows(store, "!c:example.org", "evil.org", warm));
            std::ignore = store.events.erase_if([&](db::PersistentEvent const& event) {
                return event.event_id == acl_event;
            });
            store.events.push_back(db::PersistentEvent{
                acl_event, "!c:example.org", "@a:example.org",
                R"({"type":"m.room.server_acl","state_key":"","sender":"@a:example.org","content":{},"event_id":")" +
                    acl_event + R"("})",
                0U, 0U});

            THEN("the remembered answer is not used for the new content")
            {
                auto budget = fed::ServerAclBudget{};
                REQUIRE_FALSE(fed::room_server_acl_allows(store, "!c:example.org", "good.org", budget));
            }
        }

        WHEN("a check runs out of a nearly spent request budget")
        {
            auto starved = fed::ServerAclBudget{3U};
            REQUIRE_FALSE(fed::room_server_acl_allows(store, "!c:example.org", "a-rather-long-name.example", starved));

            THEN("that refusal is not remembered: a fresh budget is allowed through")
            {
                auto fresh = fed::ServerAclBudget{};
                REQUIRE(fed::room_server_acl_allows(store, "!c:example.org", "a-rather-long-name.example", fresh));
            }
        }
    }
}

SCENARIO("a budget is never overspent and the per-check limit stays", "[federation][acl][c38]")
{
    GIVEN("an expensive ACL")
    {
        auto store = db::PersistentStore{};
        add_room_acl(store, "!e:example.org", fresh_event_id("$expensive"), expensive_acl());
        auto const long_name = std::string(200U, 'a') + ".example";

        WHEN("a check is given more than one check may spend")
        {
            auto budget = fed::ServerAclBudget{};
            REQUIRE_FALSE(fed::room_server_acl_allows(store, "!e:example.org", long_name, budget));

            THEN("it spent exactly the per-check limit")
            {
                REQUIRE(fed::server_acl_request_glob_steps - budget.steps_left == fed::server_acl_max_glob_steps);
            }
        }

        WHEN("a check is given a budget smaller than that")
        {
            auto budget = fed::ServerAclBudget{500U};
            REQUIRE_FALSE(fed::room_server_acl_allows(store, "!e:example.org", long_name, budget));

            THEN("the budget is spent to zero, never below")
            {
                REQUIRE(budget.steps_left == 0U);
            }
        }
    }
}
