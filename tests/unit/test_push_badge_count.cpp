// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// homeserver::count_push_badge: the Push Gateway `counts.unread` for one recipient, from one
// bounded pass over the store (ADR-0207). Under the budget it must equal the sum of the exact
// per-room counts /sync reports; when capped it must never count more than they would.

#include "../support/room_history_fixture.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/push_badge_count.hpp"
#include "merovingian/homeserver/push_rule_unread_classifier.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stored_push_rules.hpp"
#include "merovingian/sync/sliding_sync_room_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

auto add_event(merovingian::database::PersistentStore& store, std::string event_id, std::string_view room_id,
               std::string_view sender, std::string json, std::uint64_t stream_ordering,
               std::string status = "accepted") -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::string{room_id};
    event.sender_user_id = std::string{sender};
    event.json = std::move(json);
    event.depth = 1U;
    event.stream_ordering = stream_ordering;
    event.status = std::move(status);
    store.events.push_back(std::move(event));
}

auto add_message(merovingian::database::PersistentStore& store, std::string event_id, std::string_view room_id,
                 std::uint64_t stream_ordering, std::string status = "accepted") -> void
{
    add_event(store, std::move(event_id), room_id, bob,
              std::string{R"({"type":"m.room.message","sender":")"} + std::string{bob} + R"(","room_id":")" +
                  std::string{room_id} + R"(","content":{"msgtype":"m.text","body":"hi"}})",
              stream_ordering, std::move(status));
}

auto add_membership(merovingian::database::PersistentStore& store, std::string event_id, std::string_view room_id,
                    std::string_view membership, std::uint64_t stream_ordering) -> void
{
    add_event(store, std::move(event_id), room_id, alice,
              std::string{R"({"type":"m.room.member","sender":")"} + std::string{alice} + R"(","state_key":")" +
                  std::string{alice} + R"(","room_id":")" + std::string{room_id} + R"(","content":{"membership":")" +
                  std::string{membership} + R"(","displayname":"Al"}})",
              stream_ordering);
}

auto join_room(merovingian::database::PersistentStore& store, std::string_view room_id) -> void
{
    store.memberships.push_back({std::string{room_id}, std::string{alice}, "join", 1U});
}

// What /sync reports for alice: the exact per-room counts summed over her joined rooms.
[[nodiscard]] auto exact_total(merovingian::homeserver::HomeserverRuntime const& runtime) -> std::uint64_t
{
    auto const& store = runtime.database.persistent_store;
    auto const classifier = merovingian::homeserver::PushRuleUnreadClassifier{store, alice, 200U};
    auto total = std::uint64_t{0U};
    for (auto const& membership : store.memberships)
    {
        if (membership.user_id == alice && membership.membership == "join")
        {
            total += merovingian::sync::count_notifications(
                store, membership.room_id, alice,
                merovingian::sync::read_receipt_markers(runtime, store, membership.room_id, alice), classifier);
        }
    }
    return total;
}

[[nodiscard]] auto badge(merovingian::homeserver::HomeserverRuntime const& runtime,
                         std::uint64_t row_budget = merovingian::homeserver::push_badge_row_budget)
    -> merovingian::homeserver::PushBadgeCount
{
    auto const ruleset = merovingian::homeserver::load_push_ruleset(runtime.database.persistent_store, alice, 200U);
    return merovingian::homeserver::count_push_badge(runtime, alice, ruleset, row_budget);
}

} // namespace

SCENARIO("Under its budget the push badge equals the sum of /sync's exact counts", "[push][push-badge][r15]")
{
    GIVEN("three joined rooms: a read receipt and a displayname change, a leave and rejoin, and a backfilled "
          "pre-join event with a rejected one")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;

        // !a: a receipt on a10; alice's displayname change at 12 is a join->join, not a new join.
        join_room(store, "!a:example.org");
        add_membership(store, "$a1", "!a:example.org", "join", 1U);
        add_message(store, "$a10", "!a:example.org", 10U);
        add_message(store, "$a11", "!a:example.org", 11U);
        add_membership(store, "$a12", "!a:example.org", "join", 12U);
        add_message(store, "$a13", "!a:example.org", 13U);
        runtime.database.persistent_store.receipts.push_back(
            {"!a:example.org", "m.read", std::string{alice}, "$a10", 0U, 1U, ""});

        // !b: b22 was sent while alice had left; she rejoined at 23.
        join_room(store, "!b:example.org");
        add_membership(store, "$b20", "!b:example.org", "join", 20U);
        add_membership(store, "$b21", "!b:example.org", "leave", 21U);
        add_message(store, "$b22", "!b:example.org", 22U);
        add_membership(store, "$b23", "!b:example.org", "join", 23U);
        add_message(store, "$b24", "!b:example.org", 24U);

        // !c: c32 is rejected; c35 is history from before her join, stored after it.
        join_room(store, "!c:example.org");
        add_membership(store, "$c30", "!c:example.org", "join", 30U);
        add_message(store, "$c31", "!c:example.org", 31U);
        add_message(store, "$c32", "!c:example.org", 32U, "rejected");
        for (auto const* room : {"!a:example.org", "!b:example.org", "!c:example.org"})
        {
            merovingian::tests::record_joined_state_for_room(store, room, alice);
        }
        add_event(store, "$hv", "!fixture-state-holder:example.org", bob,
                  R"({"type":"m.room.history_visibility","state_key":"","content":{"history_visibility":"joined"}})",
                  2U);
        add_message(store, "$c35", "!c:example.org", 35U);
        auto const before_alice = merovingian::database::create_or_reuse_state_group(
            store, "!c:example.org", "sg:fixture:before-alice", std::nullopt,
            {
                {std::string{}, "m.room.history_visibility", std::string{}, "$hv"}
        });
        REQUIRE(before_alice.has_value());
        REQUIRE(merovingian::database::set_event_state_group(store, "$c35", *before_alice));

        WHEN("the badge is counted with room to spare")
        {
            auto const count = badge(runtime);
            auto const exact = exact_total(runtime);

            THEN("it visits every row and matches /sync")
            {
                // Fixture: a11 and a13, b24, c31 are unread; nothing else is.
                REQUIRE(exact == 4U);
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.unread == exact);
            }
        }
    }
}

SCENARIO("The push badge charges every row it visits and stops at its budget", "[push][push-badge][r15]")
{
    GIVEN("a joined room with three unread messages, then fifty newer rows from a room alice is not in")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        for (auto stream = std::uint64_t{10U}; stream < 13U; ++stream)
        {
            add_message(store, "$r" + std::to_string(stream), "!r:example.org", stream);
        }
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        for (auto stream = std::uint64_t{100U}; stream < 150U; ++stream)
        {
            add_message(store, "$z" + std::to_string(stream), "!z:example.org", stream);
        }

        WHEN("the badge is counted with a budget of twenty rows")
        {
            auto const count = badge(runtime, 20U);

            THEN("it stops after twenty rows, and the room it never reached adds nothing")
            {
                REQUIRE(count.rows_visited == 20U);
                REQUIRE(count.capped);
                REQUIRE(count.unread == 0U);
                REQUIRE(exact_total(runtime) == 3U);
            }
        }
    }
}

SCENARIO("A capped push badge never counts more than /sync would", "[push][push-badge][r15]")
{
    GIVEN("a room whose rows are stored out of stream order: a pre-join message first, then the join and two "
          "unread messages")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_message(store, "$r3", "!r:example.org", 3U);
        add_membership(store, "$r5", "!r:example.org", "join", 5U);
        add_message(store, "$r10", "!r:example.org", 10U);
        add_message(store, "$r11", "!r:example.org", 11U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        auto const exact = exact_total(runtime);

        WHEN("the budget reaches the join but not the oldest row, and when it reaches only the newest row")
        {
            auto const reaches_join = badge(runtime, store.events.size() - 1U);
            auto const newest_only = badge(runtime, 1U);

            THEN("each is capped and at most the exact count")
            {
                REQUIRE(exact == 2U);
                REQUIRE(reaches_join.capped);
                REQUIRE(reaches_join.unread <= exact);
                REQUIRE(reaches_join.unread == 2U);
                REQUIRE(newest_only.capped);
                REQUIRE(newest_only.unread == 0U);
            }
        }
    }
}

SCENARIO("A fully read user's badge is zero after visiting every row", "[push][push-badge][r15]")
{
    GIVEN("a joined room whose last message alice has read")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        add_message(store, "$r10", "!r:example.org", 10U);
        add_message(store, "$r11", "!r:example.org", 11U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        runtime.database.persistent_store.receipts.push_back(
            {"!r:example.org", "m.read", std::string{alice}, "$r11", 0U, 1U, ""});

        WHEN("the badge is counted")
        {
            auto const count = badge(runtime);

            THEN("it is zero and the rows visited are the whole store, which is under the budget")
            {
                REQUIRE(count.unread == 0U);
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.rows_visited == store.events.size());
            }
        }
    }
}

SCENARIO("The push badge saturates at its cap", "[push][push-badge][r15]")
{
    GIVEN("alice joined, with more unread messages than the badge cap")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        for (auto stream = std::uint64_t{10U}; stream < 10U + merovingian::homeserver::push_badge_unread_cap + 200U;
             ++stream)
        {
            add_message(store, "$m" + std::to_string(stream), "!r:example.org", stream);
        }
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);

        WHEN("the badge for a push is computed")
        {
            auto const count = badge(runtime);

            THEN("it reports the cap, not the full backlog")
            {
                // Project policy: counts.unread is a badge; it saturates (ADR-0207).
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.unread == merovingian::homeserver::push_badge_unread_cap);
            }
        }
    }
}

SCENARIO("A capped push badge falls back to the membership row when it did not reach the join",
         "[push][push-badge][r15]")
{
    GIVEN("alice's join stored first, three unread messages after it, and her membership row at ordering 8")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        // The row's ordering is that of her latest membership change (a profile change, say), which
        // is later than the join itself.
        store.memberships.push_back({"!r:example.org", std::string{alice}, "join", 8U});
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        add_message(store, "$r5", "!r:example.org", 5U);
        add_message(store, "$r8", "!r:example.org", 8U);
        add_message(store, "$r12", "!r:example.org", 12U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        auto const exact = exact_total(runtime);

        WHEN("the budget reaches every row but the join")
        {
            auto const count = badge(runtime, store.events.size() - 1U);

            THEN("only events after the row's ordering count, and never more than /sync would")
            {
                REQUIRE(exact == 3U);
                REQUIRE(count.capped);
                REQUIRE(count.unread == 1U);
                REQUIRE(count.unread <= exact);
            }
        }
    }

    GIVEN("the same room but a membership row with no ordering")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        store.memberships.push_back({"!r:example.org", std::string{alice}, "join", 0U});
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        add_message(store, "$r5", "!r:example.org", 5U);
        add_message(store, "$r12", "!r:example.org", 12U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);

        WHEN("the budget reaches every row but the join")
        {
            auto const count = badge(runtime, store.events.size() - 1U);

            THEN("the room adds nothing")
            {
                REQUIRE(count.capped);
                REQUIRE(count.unread == 0U);
            }
        }
    }
}
