// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, classic-sync full-history scan: unread counts and read markers (ADR-0617).
//
// Spec: client-server-api.md, "Marking notifications as read": notifications up to and including the receipted event
// are read, so nothing at or before the marker can count. The walk now starts at the newest row, stops at the marker
// and at the start of the user's join, and reads a fixed number of rows at most.

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/PushRuleUnreadClassifier.hpp"
#include "merovingian/push/PushRuleset.hpp"
#include "merovingian/sync/ReadMarkers.hpp"
#include "merovingian/sync/SlidingSyncRoomBuilder.hpp"
#include "merovingian/sync/UnreadEventClassifier.hpp"
#include "merovingian/sync/UnreadEventOutcome.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;

constexpr auto room = std::string_view{"!room:example.org"};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};
// sync::max_unread_rows_examined: named here as a number, so a change to it is a change to this test.
constexpr auto row_budget = std::uint64_t{1000U};

class EveryMessageNotifies final : public merovingian::sync::UnreadEventClassifier
{
public:
    explicit EveryMessageNotifies(std::uint64_t after)
        : after_{after}
    {
    }

    [[nodiscard]] auto counted_after(std::string_view /*room_id*/) -> std::optional<std::uint64_t> override
    {
        return after_;
    }

    [[nodiscard]] auto classify(std::string_view /*room_id*/, merovingian::canonicaljson::Value const& /*event*/)
        -> merovingian::sync::UnreadEventOutcome override
    {
        return {true, false};
    }

    [[nodiscard]] auto visible(db::PersistentEvent const& /*event*/) -> bool override
    {
        return true;
    }

private:
    std::uint64_t after_{0U};
};

auto add_messages(db::PersistentStore& store, std::string_view sender, std::uint64_t first, std::uint64_t last) -> void
{
    for (auto ordering = first; ordering <= last; ++ordering)
    {
        store.events.push_back({"$m" + std::to_string(ordering),
                                std::string{room},
                                std::string{sender},
                                std::string{R"({"type":"m.room.message","sender":")"} + std::string{sender} +
                                    R"(","content":{"body":"x"}})",
                                1U,
                                ordering,
                                {},
                                {},
                                {}});
    }
}

auto store_member_event(db::PersistentStore& store, std::string_view event_id, std::string_view membership,
                        std::uint64_t ordering, std::string_view previous = {}) -> void
{
    auto event = db::PersistentEvent{};
    event.event_id = std::string{event_id};
    event.room_id = std::string{room};
    event.sender_user_id = std::string{alice};
    if (!previous.empty())
    {
        event.auth_event_ids.emplace_back(previous);
    }
    event.json = std::string{R"({"type":"m.room.member","sender":")"} + std::string{alice} + R"(","state_key":")" +
                 std::string{alice} + R"(","content":{"membership":")" + std::string{membership} + R"("}})";
    event.stream_ordering = ordering;
    auto state = std::optional<db::PersistentStateEvent>{
        db::PersistentStateEvent{std::string{room}, "m.room.member", std::string{alice}, std::string{event_id}}
    };
    REQUIRE(db::store_event_with_state(store, std::move(event), std::move(state), std::nullopt));
}

} // namespace

SCENARIO("unread counting reads only what could still be unread", "[sync][unread][security][gate-m-sync]")
{
    GIVEN("three thousand messages before the read marker and five after it")
    {
        auto store = db::PersistentStore{};
        add_messages(store, bob, 1U, 3005U);
        auto markers = merovingian::sync::ReadMarkers{};
        markers.unthreaded = 3000U;

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{0U};
            auto const before = store.sync_unread_rows_examined.value();
            auto const counts = merovingian::sync::count_unread_by_thread(store, room, alice, markers, classifier);

            THEN("the count is exact and only the unread rows were read")
            {
                REQUIRE(counts.total().notification_count == 5U);
                REQUIRE(store.sync_unread_rows_examined.value() - before == 5U);
            }
        }
    }

    GIVEN("three thousand messages before the user joined, no marker, and two after the join")
    {
        auto store = db::PersistentStore{};
        add_messages(store, bob, 1U, 3002U);

        WHEN("the room is counted from the join")
        {
            auto classifier = EveryMessageNotifies{3000U};
            auto const before = store.sync_unread_rows_examined.value();
            auto const counts = merovingian::sync::count_unread_by_thread(store, room, alice,
                                                                          merovingian::sync::ReadMarkers{}, classifier);

            THEN("the count is exact and the history before the join was not read")
            {
                REQUIRE(counts.total().notification_count == 2U);
                REQUIRE(store.sync_unread_rows_examined.value() - before == 2U);
            }
        }
    }

    GIVEN("more unread messages than the budget")
    {
        auto store = db::PersistentStore{};
        add_messages(store, bob, 1U, row_budget + 500U);

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{0U};
            auto const before = store.sync_unread_rows_examined.value();
            auto const counts = merovingian::sync::count_unread_by_thread(store, room, alice,
                                                                          merovingian::sync::ReadMarkers{}, classifier);

            THEN("the walk stops at the budget and reports the newest rows it read")
            {
                REQUIRE(store.sync_unread_rows_examined.value() - before == row_budget);
                REQUIRE(counts.total().notification_count == row_budget);
            }
        }
    }

    GIVEN("exactly as many unread messages as the budget")
    {
        auto store = db::PersistentStore{};
        add_messages(store, bob, 1U, row_budget);

        WHEN("the room is counted")
        {
            auto classifier = EveryMessageNotifies{0U};
            auto const counts = merovingian::sync::count_unread_by_thread(store, room, alice,
                                                                          merovingian::sync::ReadMarkers{}, classifier);

            THEN("every one of them counts")
            {
                REQUIRE(counts.total().notification_count == row_budget);
            }
        }
    }
}

SCENARIO("read markers read the newest rows only", "[sync][unread][security][gate-m-sync]")
{
    GIVEN("a room with more rows than the budget, the user's own message among the newest")
    {
        auto store = db::PersistentStore{};
        add_messages(store, bob, 1U, row_budget + 500U);
        add_messages(store, alice, row_budget + 501U, row_budget + 501U);
        add_messages(store, bob, row_budget + 502U, row_budget + 505U);

        WHEN("the markers are read")
        {
            auto const before = store.sync_unread_rows_examined.value();
            auto const markers = merovingian::sync::read_markers_for({}, store, room, alice);

            THEN("the user's message reads its thread up to itself, and the walk stopped at the budget")
            {
                REQUIRE(markers.threads.at(std::string{merovingian::sync::main_thread_id}) == row_budget + 501U);
                REQUIRE(store.sync_unread_rows_examined.value() - before == row_budget);
            }
        }
    }
}

SCENARIO("the start of a user's join comes from their member events, not a walk of the table",
         "[sync][unread][homeserver][security][gate-m-sync]")
{
    GIVEN("a user who joined, left, joined again and changed their profile, among other rooms' events")
    {
        auto store = db::PersistentStore{};
        store_member_event(store, "$join1", "join", 10U);
        store_member_event(store, "$leave", "leave", 20U, "$join1");
        store_member_event(store, "$join2", "join", 30U, "$leave");
        store_member_event(store, "$profile", "join", 40U, "$join2");

        WHEN("the counting start is asked for")
        {
            auto classifier =
                merovingian::homeserver::PushRuleUnreadClassifier{store, alice, merovingian::push::PushRuleset{}};
            auto const start = classifier.counted_after(room);

            THEN("it is the join that began the current stay, found without walking a table")
            {
                REQUIRE(start == std::optional<std::uint64_t>{30U});
                REQUIRE(classifier.table_walks() == 0U);
            }
        }
    }

    GIVEN("a user whose last membership change was to leave")
    {
        auto store = db::PersistentStore{};
        store_member_event(store, "$join1", "join", 10U);
        store_member_event(store, "$leave", "leave", 20U, "$join1");

        WHEN("the counting start is asked for")
        {
            auto classifier =
                merovingian::homeserver::PushRuleUnreadClassifier{store, alice, merovingian::push::PushRuleset{}};

            THEN("nothing counts")
            {
                REQUIRE_FALSE(classifier.counted_after(room).has_value());
            }
        }
    }

    GIVEN("member events held with no current state row, as a hand-built store has")
    {
        auto store = db::PersistentStore{};
        store.events.push_back({"$join",
                                std::string{room},
                                std::string{alice},
                                std::string{R"({"type":"m.room.member","sender":")"} + std::string{alice} +
                                    R"(","state_key":")" + std::string{alice} + R"(","content":{"membership":"join"}})",
                                1U,
                                7U,
                                {},
                                {},
                                {}});

        WHEN("the counting start is asked for")
        {
            auto classifier =
                merovingian::homeserver::PushRuleUnreadClassifier{store, alice, merovingian::push::PushRuleset{}};

            THEN("the room's own newest rows supply it")
            {
                REQUIRE(classifier.counted_after(room) == std::optional<std::uint64_t>{7U});
            }
        }
    }
}
