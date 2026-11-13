// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C03 (ADR-0714): a federated join stores its auth chain and its member rows in one backend transaction each, however
// many the resident's answer holds, where it was one commit per event and per member.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto outlier(std::string const& room, std::size_t number) -> db::PersistentEvent
{
    auto event = db::PersistentEvent{};
    event.event_id = "$auth" + std::to_string(number);
    event.room_id = room;
    event.sender_user_id = "@a:remote.example";
    event.json = R"({"type":"m.room.message"})";
    event.depth = number;
    event.stream_ordering = number + 1U;
    event.status = "outlier";
    return event;
}

} // namespace

SCENARIO("A join's auth chain is stored in one transaction", "[database][join][c03]")
{
    GIVEN("an empty store and an auth chain of 200 events, one of them listed twice")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto events = std::vector<db::PersistentEvent>{};
        for (auto number = std::size_t{0U}; number < 200U; ++number)
        {
            events.push_back(outlier("!r:remote.example", number));
        }
        events.push_back(outlier("!r:remote.example", 7U));
        auto const before = store.committed_transactions;

        WHEN("they are stored as a batch")
        {
            auto const stored = db::store_outlier_events_batch(store, std::move(events));

            THEN("one transaction is committed and each event is held once")
            {
                REQUIRE(stored);
                REQUIRE(store.committed_transactions - before == 1U);
                REQUIRE(store.events.size() == 200U);
                REQUIRE(store.events.find_in_room("!r:remote.example", "$auth199") != store.events.end());
            }

            AND_WHEN("the same chain is stored again, with one event added")
            {
                auto again = std::vector<db::PersistentEvent>{};
                for (auto number = std::size_t{0U}; number < 201U; ++number)
                {
                    again.push_back(outlier("!r:remote.example", number));
                }
                auto const second_before = store.committed_transactions;
                auto const restored = db::store_outlier_events_batch(store, std::move(again));

                THEN("only the new event is written, in one transaction")
                {
                    REQUIRE(restored);
                    REQUIRE(store.committed_transactions - second_before == 1U);
                    REQUIRE(store.events.size() == 201U);
                }
            }
        }

        WHEN("one of the events is already held in another room")
        {
            REQUIRE(db::store_outlier_events_batch(store, {outlier("!other:remote.example", 3U)}));
            auto const stored = db::store_outlier_events_batch(store, {outlier("!r:remote.example", 3U)});

            THEN("the batch is refused and nothing of it is written")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.events.size() == 1U);
            }
        }
    }
}

SCENARIO("A join's member rows are stored in one transaction", "[database][join][c03]")
{
    GIVEN("a store that already holds one of 300 members, as an earlier stay in the room left it")
    {
        auto opened = db::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(db::store_membership(store, {"!r:remote.example", "@m5:remote.example", "leave", 1U}) ==
                db::MembershipStoreResult::stored);
        auto rows = std::vector<db::PersistentMembership>{};
        for (auto number = std::size_t{0U}; number < 300U; ++number)
        {
            rows.push_back(
                {"!r:remote.example", "@m" + std::to_string(number) + ":remote.example", "join", 10U + number});
        }
        auto const before = store.committed_transactions;

        WHEN("they are stored as a batch")
        {
            auto const stored = db::store_memberships_batch(store, std::move(rows));

            THEN("one transaction is committed, the held row is updated and the others are inserted")
            {
                REQUIRE(stored);
                REQUIRE(store.committed_transactions - before == 1U);
                REQUIRE(store.memberships.size() == 300U);
                auto const* const updated = db::find_membership_row(store, "!r:remote.example", "@m5:remote.example");
                REQUIRE(updated != nullptr);
                REQUIRE(updated->membership == "join");
                REQUIRE(updated->stream_ordering == 15U);
                REQUIRE(db::find_membership_row(store, "!r:remote.example", "@m299:remote.example") != nullptr);
            }
        }
    }
}
