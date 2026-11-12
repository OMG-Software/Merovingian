// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// homeserver::count_push_badge: the Push Gateway `counts.unread` for one recipient, from one
// bounded walk of the store, newest first in stream order (ADR-0207, ADR-0215). When it ends
// uncapped it must equal the sum of the exact per-room counts /sync reports; when capped it must
// never count more than they would.

#include "../support/RoomHistoryFixture.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/PushBadgeCount.hpp"
#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/homeserver/StoredPushRules.hpp"
#include "merovingian/push/PushCondition.hpp"
#include "merovingian/push/PushConditionKind.hpp"
#include "merovingian/push/PushEvaluationBudget.hpp"
#include "merovingian/push/PushRule.hpp"
#include "merovingian/push/PushRuleKind.hpp"
#include "merovingian/push/PushRuleset.hpp"
#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
    auto classifier = merovingian::homeserver::PushRuleUnreadClassifier{store, alice, 200U};
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

// An m.room.message alice sent, so a read of its thread up to it; `relates_to` is its
// m.relates_to object, or empty for the main timeline.
auto add_own_message(merovingian::database::PersistentStore& store, std::string event_id, std::string_view room_id,
                     std::uint64_t stream_ordering, std::string const& relates_to = {}) -> void
{
    auto content = std::string{R"({"msgtype":"m.text","body":"me")"};
    if (!relates_to.empty())
    {
        content += R"(,"m.relates_to":)" + relates_to;
    }
    content += "}";
    add_event(store, std::move(event_id), room_id, alice,
              std::string{R"({"type":"m.room.message","sender":")"} + std::string{alice} + R"(","room_id":")" +
                  std::string{room_id} + R"(","content":)" + content + "}",
              stream_ordering);
}

// Every budget from one row to the whole store: a capped badge never exceeds /sync's count, and
// one that ends uncapped (it visited every row, or stopped once every room was settled) equals it.
auto require_never_over_exact(merovingian::homeserver::HomeserverRuntime const& runtime) -> void
{
    auto const exact = exact_total(runtime);
    for (auto budget = std::uint64_t{1U}; budget <= runtime.database.persistent_store.events.size(); ++budget)
    {
        auto const count = badge(runtime, budget);
        INFO("budget " << budget << ", badge " << count.unread << ", exact " << exact);
        REQUIRE(count.unread <= exact);
        if (!count.capped)
        {
            REQUIRE(count.unread == exact);
        }
    }
    auto const full = badge(runtime);
    REQUIRE_FALSE(full.capped);
    REQUIRE(full.unread == exact);
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

            THEN("it matches /sync, and no smaller budget gives more")
            {
                // Fixture: a11 and a13, b24, c31 are unread; nothing else is.
                REQUIRE(exact == 4U);
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.unread == exact);
                require_never_over_exact(runtime);
            }
        }
    }
}

SCENARIO("A capped push badge sees the user's newer own event before the message it reads", "[push][push-badge][r15]")
{
    GIVEN("alice's own message at ordering 6 stored before her join at 1 and bob's message at 5")
    {
        // PR #523 review 5621537346: in arrival order a two-row pass reached the message and the
        // join but not her own later message, and counted the message she had read.
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_own_message(store, "$own6", "!r:example.org", 6U);
        add_membership(store, "$join1", "!r:example.org", "join", 1U);
        add_message(store, "$msg5", "!r:example.org", 5U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);

        WHEN("the badge is counted with a budget of two rows")
        {
            auto const count = badge(runtime, 2U);

            THEN("it counts nothing, as /sync does")
            {
                REQUIRE(exact_total(runtime) == 0U);
                REQUIRE(count.capped);
                REQUIRE(count.unread == 0U);
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

            THEN("it stops after twenty rows, all newer than the room's messages, and counts nothing")
            {
                REQUIRE(count.rows_visited == 20U);
                REQUIRE(count.capped);
                REQUIRE(count.unread == 0U);
                REQUIRE(exact_total(runtime) == 3U);
            }
        }
    }
}

SCENARIO("A fully read user's badge stops once every room is settled", "[push][push-badge][r15]")
{
    GIVEN("a joined room whose last message alice has read, above a hundred older rows")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        for (auto stream = std::uint64_t{1U}; stream <= 100U; ++stream)
        {
            add_message(store, "$old" + std::to_string(stream), "!z:example.org", stream);
        }
        join_room(store, "!r:example.org");
        add_membership(store, "$r200", "!r:example.org", "join", 200U);
        add_message(store, "$r210", "!r:example.org", 210U);
        add_message(store, "$r211", "!r:example.org", 211U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        store.receipts.push_back({"!r:example.org", "m.read", std::string{alice}, "$r211", 0U, 1U, ""});

        WHEN("the badge is counted")
        {
            auto const count = badge(runtime);

            THEN("it is exact and zero, and it stopped at her join instead of walking the whole store")
            {
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.unread == 0U);
                REQUIRE(count.rows_visited == 3U);
                REQUIRE(count.rows_visited < store.events.size());
            }
        }
    }
}

SCENARIO("A capped push badge never counts more than /sync would", "[push][push-badge][r15]")
{
    GIVEN("rooms stored out of stream order: own events in a thread and the main timeline, a leave and rejoin, "
          "and receipts both unthreaded and threaded")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        auto const thread_reply = [](std::string_view root) {
            return std::string{
                       R"({"type":"m.room.message","sender":"@bob:example.org","content":{"msgtype":"m.text",)"} +
                   R"("body":"t","m.relates_to":{"rel_type":"m.thread","event_id":")" + std::string{root} + R"("}}})";
        };

        // !a: bob's thread reply at 14 is read by alice's own reply at 16, stored first; bob's main
        // message at 15 is unread; a threaded receipt covers bob's thread reply at 12.
        join_room(store, "!a:example.org");
        add_own_message(store, "$a16", "!a:example.org", 16U, R"({"rel_type":"m.thread","event_id":"$a10"})");
        add_message(store, "$a15", "!a:example.org", 15U);
        add_membership(store, "$a1", "!a:example.org", "join", 1U);
        add_message(store, "$a10", "!a:example.org", 10U);
        add_event(store, "$a12", "!a:example.org", bob, thread_reply("$a10"), 12U);
        add_event(store, "$a14", "!a:example.org", bob, thread_reply("$a10"), 14U);
        store.receipts.push_back({"!a:example.org", "m.read", std::string{alice}, "$a12", 0U, 1U, "$a10"});

        // !b: she left at 21 and rejoined at 23, stored newest first; b22 is from while she was out.
        join_room(store, "!b:example.org");
        add_message(store, "$b24", "!b:example.org", 24U);
        add_membership(store, "$b23", "!b:example.org", "join", 23U);
        add_message(store, "$b22", "!b:example.org", 22U);
        add_membership(store, "$b21", "!b:example.org", "leave", 21U);
        add_membership(store, "$b20", "!b:example.org", "join", 20U);

        // !c: an unthreaded receipt on c31, stored after the messages it reads.
        join_room(store, "!c:example.org");
        add_message(store, "$c33", "!c:example.org", 33U);
        add_membership(store, "$c30", "!c:example.org", "join", 30U);
        add_message(store, "$c31", "!c:example.org", 31U);
        add_message(store, "$c32", "!c:example.org", 32U);
        store.receipts.push_back({"!c:example.org", "m.read", std::string{alice}, "$c31", 0U, 1U, ""});

        for (auto const* room : {"!a:example.org", "!b:example.org", "!c:example.org"})
        {
            merovingian::tests::record_joined_state_for_room(store, room, alice);
        }

        WHEN("the badge is counted with every budget from one row to the whole store")
        {
            THEN("no budget gives more than /sync, and every uncapped result equals it")
            {
                // Fixture: a10 and a15 in the main timeline; b24; c32 and c33.
                REQUIRE(exact_total(runtime) == 5U);
                require_never_over_exact(runtime);
            }
        }
    }
}

SCENARIO("Thread-parent lookups do not count as rows the push badge visits", "[push][push-badge][r15]")
{
    GIVEN("a thread root, a reply in it, and a reference to the reply whose thread is found through it")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        add_message(store, "$root", "!r:example.org", 10U);
        add_event(store, "$reply", "!r:example.org", bob,
                  R"({"type":"m.room.message","sender":"@bob:example.org","content":{"msgtype":"m.text","body":"t",)"
                  R"("m.relates_to":{"rel_type":"m.thread","event_id":"$root"}}})",
                  11U);
        add_event(store, "$ref", "!r:example.org", bob,
                  R"({"type":"m.room.message","sender":"@bob:example.org","content":{"msgtype":"m.text","body":"r",)"
                  R"("m.relates_to":{"rel_type":"m.reference","event_id":"$reply"}}})",
                  12U);
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);

        WHEN("the badge is counted")
        {
            auto const count = badge(runtime);

            THEN("it visits each stored row once and counts all three messages")
            {
                REQUIRE_FALSE(count.capped);
                REQUIRE(count.unread == 3U);
                REQUIRE(count.unread == exact_total(runtime));
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
    GIVEN("alice's join at 1, three unread messages after it, and her membership row at ordering 8")
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

        WHEN("the budget reaches the three messages but not the join")
        {
            auto const count = badge(runtime, 3U);

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

        WHEN("the budget reaches the two messages but not the join")
        {
            auto const count = badge(runtime, 2U);

            THEN("the room adds nothing")
            {
                REQUIRE(count.capped);
                REQUIRE(count.unread == 0U);
            }
        }
    }
}

namespace
{

// `rooms` joined rooms, each with one unread message after alice's join. The even rooms also hold
// an unthreaded read receipt on an older message stored before everything else.
auto add_rooms_with_old_receipts(merovingian::homeserver::HomeserverRuntime& runtime, std::size_t rooms) -> void
{
    auto& store = runtime.database.persistent_store;
    auto room_id = [](std::size_t index) {
        return "!r" + std::to_string(index) + ":example.org";
    };
    for (auto index = std::size_t{0U}; index < rooms; ++index)
    {
        add_message(store, "$old" + std::to_string(index), room_id(index), 1U + index);
    }
    for (auto index = std::size_t{0U}; index < rooms; ++index)
    {
        join_room(store, room_id(index));
        add_membership(store, "$j" + std::to_string(index), room_id(index), "join", 1000U + index);
        add_message(store, "$m" + std::to_string(index), room_id(index), 2000U + index);
        if (index % 2U == 0U)
        {
            store.receipts.push_back(
                {room_id(index), "m.read", std::string{alice}, "$old" + std::to_string(index), 0U, 1U, ""});
        }
    }
    for (auto index = std::size_t{0U}; index < rooms; ++index)
    {
        merovingian::tests::record_joined_state_for_room(store, room_id(index), alice);
    }
}

} // namespace

SCENARIO("A capped push badge over many rooms reads receipts up front and walks no table per room",
         "[push][push-badge][r15]")
{
    GIVEN("300 joined rooms, half with a read receipt on a message older than the join, and one such room alone")
    {
        constexpr auto rooms = std::size_t{300U};
        auto many = merovingian::homeserver::HomeserverRuntime{};
        add_rooms_with_old_receipts(many, rooms);
        auto one = merovingian::homeserver::HomeserverRuntime{};
        add_rooms_with_old_receipts(one, 1U);

        WHEN("each badge stops before the oldest rows, which hold the receipts' targets")
        {
            auto const count = badge(many, many.database.persistent_store.events.size() - rooms);
            auto const single = badge(one, one.database.persistent_store.events.size() - 1U);
            auto const exact = exact_total(many);

            THEN("every room's unread message counts, because its receipt's position was read before the walk")
            {
                REQUIRE(exact == rooms);
                REQUIRE(count.capped);
                REQUIRE(count.unread == exact);
            }

            THEN("its setup walks each table the same number of times as for one room")
            {
                REQUIRE(count.table_walks > 0U);
                REQUIRE(count.table_walks == single.table_walks);
            }
        }
    }
}

// Security audit run-2 release gate (ADR-0608): the badges one event causes share one budget, so
// the work under the lock does not grow with the number of recipients.
SCENARIO("The badges of one event share a row and call budget", "[push][push-badge][gate-h]")
{
    GIVEN("a joined room with 1000 unread messages")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        for (auto stream = std::uint64_t{10U}; stream < 1010U; ++stream)
        {
            add_message(store, "$r" + std::to_string(stream), "!r:example.org", stream);
        }
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);
        auto const ruleset = merovingian::homeserver::load_push_ruleset(store, alice, 200U);

        WHEN("thirty recipients are counted against one event's budget")
        {
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            auto rows = std::uint64_t{0U};
            auto walks = std::uint64_t{0U};
            auto counted = std::uint32_t{0U};
            auto skipped = std::uint32_t{0U};
            for (auto recipient = 0; recipient < 30; ++recipient)
            {
                auto const count = merovingian::homeserver::count_push_badge(runtime, alice, ruleset, budget);
                if (!count.has_value())
                {
                    ++skipped;
                    continue;
                }
                ++counted;
                rows += count->rows_visited;
                walks += count->table_walks;
                if (recipient < 9)
                {
                    REQUIRE(count->unread == 1000U);
                }
            }

            THEN("the rows visited stay within the event's budget and the table walks within its call cap")
            {
                REQUIRE(rows <= merovingian::homeserver::push_badge_event_row_budget);
                REQUIRE(walks <= 16U * 3U + 3U);
                REQUIRE(counted + skipped == 30U);
                REQUIRE(skipped > 0U);
            }
            THEN("recipients past the budget get no count and no walk")
            {
                REQUIRE_FALSE(merovingian::homeserver::count_push_badge(runtime, alice, ruleset, budget).has_value());
                REQUIRE_FALSE(
                    merovingian::homeserver::push_badge_unread_count(runtime, alice, ruleset, budget).has_value());
            }
        }

        WHEN("a recipient with a fresh budget is counted")
        {
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            auto const count = merovingian::homeserver::count_push_badge(runtime, alice, ruleset, budget);

            THEN("the badge is exact and equals the unbudgeted one")
            {
                REQUIRE(count.has_value());
                REQUIRE_FALSE(count->capped);
                REQUIRE(count->unread == badge(runtime).unread);
                REQUIRE(count->unread == 1000U);
            }
        }

        WHEN("the event's row budget is already spent")
        {
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            budget.rows_left = 0U;

            THEN("there is no count")
            {
                REQUIRE_FALSE(
                    merovingian::homeserver::push_badge_unread_count(runtime, alice, ruleset, budget).has_value());
            }
        }
    }
}

// The recipients draw on the budget from a point that moves with the event, so the same members are not
// always the ones left without a count (ADR-0608).
SCENARIO("Which recipients are left without a badge changes from one event to the next", "[push][push-badge][gate-h]")
{
    GIVEN("eighteen recipients and a budget that counts sixteen of them")
    {
        auto const recipients = std::size_t{18U};
        auto const skipped_for = [](std::uint64_t stream_ordering) {
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            auto skipped = std::vector<std::size_t>{};
            auto const start = merovingian::homeserver::push_badge_draw_start(stream_ordering, recipients);
            for (auto position = std::size_t{0U}; position < recipients; ++position)
            {
                // What count_push_badge does to the budget when it has a call left.
                if (budget.calls_left == 0U)
                {
                    skipped.push_back((start + position) % recipients);
                    continue;
                }
                --budget.calls_left;
            }
            std::ranges::sort(skipped);
            return skipped;
        };

        WHEN("two events with different stream orderings are delivered")
        {
            auto const first = skipped_for(100U);
            auto const second = skipped_for(101U);

            THEN("two recipients are skipped each time and they are different ones")
            {
                REQUIRE(first.size() == 2U);
                REQUIRE(second.size() == 2U);
                REQUIRE(first != second);
            }
        }

        WHEN("the recipient list is empty")
        {
            THEN("the start is zero")
            {
                REQUIRE(merovingian::homeserver::push_badge_draw_start(7U, 0U) == 0U);
            }
        }
    }
}

// C15 (ADR-0722): each row the badge walk visits runs a rule evaluation, and each used to get a fresh glob budget, so
// an event's badge cost the row budget times 2^21 steps under the runtime lock.
SCENARIO("The badge walk of one event stops when its rule evaluations have spent their shared glob budget",
         "[push][push-badge][c15]")
{
    GIVEN("a recipient with one wildcard rule, and 60 messages whose body field is 4096 bytes the rule must scan")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        auto& store = runtime.database.persistent_store;
        join_room(store, "!r:example.org");
        add_membership(store, "$r1", "!r:example.org", "join", 1U);
        auto const heavy = std::string(4096U, 'a');
        for (auto stream = std::uint64_t{10U}; stream < 70U; ++stream)
        {
            add_event(store, "$r" + std::to_string(stream), "!r:example.org", bob,
                      std::string{R"({"type":"m.room.message","sender":")"} + std::string{bob} +
                          R"(","room_id":"!r:example.org","content":{"msgtype":"m.text","body":"hi","x":")" + heavy +
                          R"("}})",
                      stream);
        }
        merovingian::tests::record_joined_state_for_room(store, "!r:example.org", alice);

        auto rule = merovingian::push::PushRule{};
        rule.rule_id = "heavy";
        rule.kind = merovingian::push::PushRuleKind::override_kind;
        rule.notify = true;
        auto condition = merovingian::push::PushCondition{};
        condition.kind = merovingian::push::PushConditionKind::event_match;
        condition.key = "content.x";
        condition.pattern = "*" + std::string(508U, 'a') + "b";
        rule.conditions.push_back(std::move(condition));
        auto ruleset = merovingian::push::PushRuleset{};
        ruleset.override_rules.push_back(std::move(rule));

        WHEN("the event's badge is counted")
        {
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            auto const count = merovingian::homeserver::count_push_badge(runtime, alice, ruleset, budget);

            THEN("the walk ended capped after the glob budget was spent, within a few rows, not after every row")
            {
                REQUIRE(count.has_value());
                REQUIRE(count->capped);
                REQUIRE(count->rows_visited <= 3U);
                REQUIRE(budget.glob.exhausted);
                REQUIRE(budget.glob.spent <= merovingian::push::max_push_glob_steps_per_evaluation);
                REQUIRE(count->unread == 0U);
            }
        }

        WHEN("the badge is counted without an event budget, as a due email digest does")
        {
            auto const count = merovingian::homeserver::count_push_badge(runtime, alice, ruleset);
            auto digest_budget = merovingian::homeserver::PushBadgeBudget{};
            auto const budgeted =
                merovingian::homeserver::push_badge_unread_count(runtime, alice, ruleset, digest_budget);

            THEN(
                "it is still bounded by one glob budget: capped within a few rows, and the same through a fresh budget")
            {
                REQUIRE(count.capped);
                REQUIRE(count.rows_visited <= 3U);
                REQUIRE(count.unread == 0U);
                REQUIRE(budgeted.has_value());
                REQUIRE(*budgeted == 0U);
                REQUIRE(digest_budget.glob.exhausted);
            }
        }

        WHEN("a recipient without that rule is counted")
        {
            auto const plain = merovingian::homeserver::load_push_ruleset(store, alice, 200U);
            auto budget = merovingian::homeserver::PushBadgeBudget{};
            auto const count = merovingian::homeserver::count_push_badge(runtime, alice, plain, budget);

            THEN("the badge is exact and the glob budget is not exhausted")
            {
                REQUIRE(count.has_value());
                REQUIRE_FALSE(count->capped);
                REQUIRE(count->unread == 60U);
                REQUIRE_FALSE(budget.glob.exhausted);
            }
        }
    }
}
