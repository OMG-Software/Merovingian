// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The in-memory delayed-events table (migration 003, ADR-0824): every index, the due order, the ownership lookup, the
// being-sent mark, restart re-ordering, finalising, erasing, and that no lookup scans the rows.
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStatusText.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::DelayedEventStatus;
using merovingian::database::DelayedEventTable;
using merovingian::database::PersistentDelayedEvent;

constexpr auto largest_delay_ms = std::uint64_t{2'678'400'000U};

[[nodiscard]] auto scheduled(std::string delay_id, std::string user_id, std::uint64_t since_ms, std::uint64_t delay_ms,
                             std::string txn_id = {}) -> PersistentDelayedEvent
{
    auto row = PersistentDelayedEvent{};
    row.delay_id = std::move(delay_id);
    row.user_id = std::move(user_id);
    row.device_id = "DEVICE";
    row.room_id = "!room:example.org";
    row.event_type = "m.room.message";
    row.content_json = "{}";
    row.txn_id = std::move(txn_id);
    row.delay_ms = delay_ms;
    row.delayed_since_ms = since_ms;
    return row;
}

[[nodiscard]] auto due_id(DelayedEventTable const& table) -> std::string
{
    auto const* row = table.earliest_due();
    return row == nullptr ? std::string{"<none>"} : row->delay_id;
}

[[nodiscard]] auto ids_of(std::vector<PersistentDelayedEvent const*> const& rows) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const* row : rows)
    {
        ids.push_back(row->delay_id);
    }
    return ids;
}

} // namespace

SCENARIO("The status text round-trips and any other text is not a status", "[database][delayed-events]")
{
    GIVEN("the four statuses")
    {
        WHEN("each is turned into column text and parsed back")
        {
            THEN("the text is the one the schema documents, and unknown text is refused")
            {
                using merovingian::database::delayed_event_status_text;
                using merovingian::database::parse_delayed_event_status;
                REQUIRE(delayed_event_status_text(DelayedEventStatus::scheduled) == "scheduled");
                REQUIRE(delayed_event_status_text(DelayedEventStatus::sent) == "sent");
                REQUIRE(delayed_event_status_text(DelayedEventStatus::cancelled) == "cancelled");
                REQUIRE(delayed_event_status_text(DelayedEventStatus::failed) == "failed");
                for (auto const status : {DelayedEventStatus::scheduled, DelayedEventStatus::sent,
                                          DelayedEventStatus::cancelled, DelayedEventStatus::failed})
                {
                    REQUIRE(parse_delayed_event_status(delayed_event_status_text(status)) == status);
                }
                REQUIRE_FALSE(parse_delayed_event_status("").has_value());
                REQUIRE_FALSE(parse_delayed_event_status("Scheduled").has_value());
                REQUIRE_FALSE(parse_delayed_event_status("scheduled ").has_value());
                REQUIRE_FALSE(parse_delayed_event_status("done").has_value());
            }
        }
    }
}

SCENARIO("A delayed event is found by ID and only by its owner", "[database][delayed-events]")
{
    GIVEN("a table holding one row of each of two users")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-a", "@a:example.org", 0U, 1000U)));
        REQUIRE(table.insert(scheduled("d-b", "@b:example.org", 0U, 1000U)));

        WHEN("the rows are looked up")
        {
            THEN("an unknown ID and another user's ID are the same nullptr, and the owner finds its row")
            {
                REQUIRE(table.size() == 2U);
                REQUIRE(table.find("d-a") != nullptr);
                REQUIRE(table.find_owned("@a:example.org", "d-a") == table.find("d-a"));
                REQUIRE(table.find_owned("@b:example.org", "d-a") == nullptr);
                REQUIRE(table.find_owned("@a:example.org", "d-missing") == nullptr);
                REQUIRE(table.find_owned("@a:example.org", "") == nullptr);
                REQUIRE(table.find("d-missing") == nullptr);
            }
        }

        WHEN("the same delay ID is inserted again, by the same or another user")
        {
            auto const same_user = table.insert(scheduled("d-a", "@a:example.org", 5U, 5U));
            auto const other_user = table.insert(scheduled("d-a", "@b:example.org", 5U, 5U));

            THEN("both are refused and the first row is unchanged")
            {
                REQUIRE_FALSE(same_user);
                REQUIRE_FALSE(other_user);
                REQUIRE(table.size() == 2U);
                REQUIRE(table.find("d-a")->user_id == "@a:example.org");
                REQUIRE(table.find("d-a")->delay_ms == 1000U);
            }
        }
    }
}

SCENARIO("Scheduled rows come due in due-time order, ties by delay ID", "[database][delayed-events]")
{
    GIVEN("rows due at 5000 (two of them), 3000 and 9000")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-9000", "@a:example.org", 8000U, 1000U)));
        REQUIRE(table.insert(scheduled("d-5000-b", "@a:example.org", 4000U, 1000U)));
        REQUIRE(table.insert(scheduled("d-3000", "@b:example.org", 0U, 3000U)));
        REQUIRE(table.insert(scheduled("d-5000-a", "@b:example.org", 1000U, 4000U)));

        WHEN("the earliest is taken and finalised, again and again")
        {
            auto order = std::vector<std::string>{};
            while (table.earliest_due() != nullptr)
            {
                auto const id = due_id(table);
                order.push_back(id);
                REQUIRE(table.finalise(id, DelayedEventStatus::cancelled, 1U, {}, {}));
            }

            THEN("the order is by due time, and the two equal due times by delay ID")
            {
                REQUIRE(order == std::vector<std::string>{"d-3000", "d-5000-a", "d-5000-b", "d-9000"});
            }
        }

        WHEN("the due time of a row is asked for")
        {
            THEN("it is the since time plus the delay")
            {
                REQUIRE(merovingian::database::delayed_event_due_ms(*table.find("d-9000")) == 9000U);
                REQUIRE(merovingian::database::delayed_event_due_ms(*table.find("d-5000-a")) == 5000U);
            }
        }
    }

    GIVEN("a row with the largest allowed delay and one whose sum would overflow")
    {
        auto table = DelayedEventTable{};
        constexpr auto largest = std::numeric_limits<std::uint64_t>::max();
        REQUIRE(table.insert(scheduled("d-largest", "@a:example.org", 1'000'000U, largest_delay_ms)));
        REQUIRE(table.insert(scheduled("d-wraps", "@a:example.org", largest - 10U, 100U)));
        REQUIRE(table.insert(scheduled("d-small", "@a:example.org", 1U, 1U)));

        WHEN("the due times are computed and the order is read")
        {
            THEN("the largest delay is exact, the overflowing sum saturates, and the saturated row is last")
            {
                REQUIRE(merovingian::database::delayed_event_due_ms(*table.find("d-largest")) ==
                        1'000'000U + largest_delay_ms);
                REQUIRE(merovingian::database::delayed_event_due_ms(*table.find("d-wraps")) == largest);
                REQUIRE(due_id(table) == "d-small");
                REQUIRE(table.finalise("d-small", DelayedEventStatus::cancelled, 1U, {}, {}));
                REQUIRE(due_id(table) == "d-largest");
                REQUIRE(table.finalise("d-largest", DelayedEventStatus::cancelled, 1U, {}, {}));
                REQUIRE(due_id(table) == "d-wraps");
            }
        }
    }
}

SCENARIO("A row marked as being sent is not offered as due and is reported as being sent", "[database][delayed-events]")
{
    GIVEN("two scheduled rows, the earlier one marked as being sent")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-first", "@a:example.org", 0U, 1000U)));
        REQUIRE(table.insert(scheduled("d-second", "@a:example.org", 0U, 2000U)));
        REQUIRE(table.mark_being_sent("d-first"));

        WHEN("the due order is read")
        {
            THEN("the marked row is hidden from it but still counted as scheduled and still the user's earliest")
            {
                REQUIRE(table.is_being_sent("d-first"));
                REQUIRE_FALSE(table.is_being_sent("d-second"));
                REQUIRE(due_id(table) == "d-second");
                REQUIRE(table.scheduled_count("@a:example.org") == 2U);
                REQUIRE(table.earliest_due_ms_of_user("@a:example.org") == std::optional<std::uint64_t>{1000U});
                REQUIRE_FALSE(table.mark_being_sent("d-first"));
                REQUIRE_FALSE(table.mark_being_sent("d-missing"));
            }
        }

        WHEN("the mark is cleared")
        {
            REQUIRE(table.clear_being_sent("d-first"));
            auto const again = table.clear_being_sent("d-first");

            THEN("the row is offered again, and clearing twice reports it was not marked")
            {
                REQUIRE_FALSE(again);
                REQUIRE_FALSE(table.is_being_sent("d-first"));
                REQUIRE(due_id(table) == "d-first");
            }
        }

        WHEN("the marked row is restarted and then unmarked")
        {
            REQUIRE(table.restart("d-first", 10'000U));
            REQUIRE(table.clear_being_sent("d-first"));

            THEN("it comes back at its new place in the order")
            {
                REQUIRE(due_id(table) == "d-second");
                REQUIRE(table.finalise("d-second", DelayedEventStatus::cancelled, 1U, {}, {}));
                REQUIRE(due_id(table) == "d-first");
            }
        }

        WHEN("the marked row is finalised")
        {
            REQUIRE(table.finalise("d-first", DelayedEventStatus::sent, 7U, "$event", {}));

            THEN("the mark is gone with it")
            {
                REQUIRE_FALSE(table.is_being_sent("d-first"));
                REQUIRE_FALSE(table.clear_being_sent("d-first"));
                REQUIRE(due_id(table) == "d-second");
            }
        }

        WHEN("a finalised row is marked")
        {
            REQUIRE(table.finalise("d-second", DelayedEventStatus::cancelled, 7U, {}, {}));

            THEN("the mark is refused")
            {
                REQUIRE_FALSE(table.mark_being_sent("d-second"));
                REQUIRE_FALSE(table.is_being_sent("d-second"));
            }
        }
    }
}

SCENARIO("A restart moves a scheduled row in the due order and a finalised row cannot be restarted",
         "[database][delayed-events]")
{
    GIVEN("three scheduled rows, one already cancelled")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-1", "@a:example.org", 0U, 1000U)));
        REQUIRE(table.insert(scheduled("d-2", "@a:example.org", 0U, 2000U)));
        REQUIRE(table.insert(scheduled("d-3", "@a:example.org", 0U, 3000U)));
        REQUIRE(table.insert(scheduled("d-4", "@a:example.org", 0U, 500U)));
        REQUIRE(table.finalise("d-4", DelayedEventStatus::cancelled, 9U, {}, {}));

        WHEN("the first row is restarted at 2500")
        {
            REQUIRE(table.restart("d-1", 2500U));

            THEN("it is due at 3500, after the other two, and the user's earliest due follows")
            {
                REQUIRE(table.find("d-1")->delayed_since_ms == 2500U);
                REQUIRE(due_id(table) == "d-2");
                REQUIRE(table.earliest_due_ms_of_user("@a:example.org") == std::optional<std::uint64_t>{2000U});
                REQUIRE(table.finalise("d-2", DelayedEventStatus::cancelled, 1U, {}, {}));
                REQUIRE(due_id(table) == "d-3");
                REQUIRE(table.finalise("d-3", DelayedEventStatus::cancelled, 1U, {}, {}));
                REQUIRE(due_id(table) == "d-1");
            }
        }

        WHEN("a finalised row and an unknown row are restarted")
        {
            auto const finalised = table.restart("d-4", 100U);
            auto const unknown = table.restart("d-nope", 100U);

            THEN("both are refused and nothing moves")
            {
                REQUIRE_FALSE(finalised);
                REQUIRE_FALSE(unknown);
                REQUIRE(table.find("d-4")->delayed_since_ms == 0U);
                REQUIRE(due_id(table) == "d-1");
            }
        }
    }
}

SCENARIO("Finalising moves a row from the scheduled to the finalised structures", "[database][delayed-events]")
{
    GIVEN("a user with two scheduled rows and another with one")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-1", "@a:example.org", 0U, 1000U, "txn-1")));
        REQUIRE(table.insert(scheduled("d-2", "@a:example.org", 0U, 2000U, "txn-2")));
        REQUIRE(table.insert(scheduled("d-3", "@b:example.org", 0U, 3000U)));

        WHEN("one row is finalised as sent with an event ID")
        {
            REQUIRE(table.finalise("d-1", DelayedEventStatus::sent, 500U, "$event:example.org", {}));
            auto const again = table.finalise("d-1", DelayedEventStatus::cancelled, 600U, {}, {});

            THEN("the counts move, the row is findable by event ID, and a second finalise is refused")
            {
                REQUIRE_FALSE(again);
                REQUIRE(table.scheduled_count("@a:example.org") == 1U);
                REQUIRE(table.finalised_count("@a:example.org") == 1U);
                REQUIRE(table.scheduled_count("@b:example.org") == 1U);
                REQUIRE(table.finalised_count("@b:example.org") == 0U);
                auto const* row = table.find("d-1");
                REQUIRE(row->status == DelayedEventStatus::sent);
                REQUIRE(row->finalised_at_ms == 500U);
                REQUIRE(row->event_id == "$event:example.org");
                REQUIRE(table.find_sent_by_event_id("$event:example.org") == row);
                REQUIRE(table.find_sent_by_event_id("$other:example.org") == nullptr);
                REQUIRE(due_id(table) == "d-2");
                REQUIRE(table.earliest_due_ms_of_user("@a:example.org") == std::optional<std::uint64_t>{2000U});
            }
        }

        WHEN("rows are finalised as cancelled and as failed, and scheduled is passed as the new status")
        {
            auto const to_scheduled = table.finalise("d-1", DelayedEventStatus::scheduled, 1U, {}, {});
            REQUIRE(table.finalise("d-1", DelayedEventStatus::failed, 40U, {}, R"({"errcode":"M_FORBIDDEN"})"));
            REQUIRE(table.finalise("d-2", DelayedEventStatus::cancelled, 30U, {}, {}));
            auto const unknown = table.finalise("d-nope", DelayedEventStatus::cancelled, 30U, {}, {});

            THEN("a finalise back to scheduled and one of an unknown row are refused, and the error is kept")
            {
                REQUIRE_FALSE(to_scheduled);
                REQUIRE_FALSE(unknown);
                REQUIRE(table.find("d-1")->error_json == R"({"errcode":"M_FORBIDDEN"})");
                REQUIRE(table.find("d-1")->event_id.empty());
                REQUIRE(table.scheduled_count("@a:example.org") == 0U);
                REQUIRE_FALSE(table.earliest_due_ms_of_user("@a:example.org").has_value());
                REQUIRE(table.find_sent_by_event_id("") == nullptr);
                REQUIRE(ids_of(table.finalised_of_user("@a:example.org", 10U)) ==
                        std::vector<std::string>{"d-2", "d-1"});
            }
        }
    }
}

SCENARIO("A user's finalised rows and the whole table's finalised rows are read oldest first",
         "[database][delayed-events]")
{
    GIVEN("finalised rows of two users at several times, two of them at the same time")
    {
        auto table = DelayedEventTable{};
        for (auto const& [id, user, when] : std::vector<std::tuple<std::string, std::string, std::uint64_t>>{
                 {"d-a", "@a:example.org", 300U},
                 {"d-b", "@a:example.org", 100U},
                 {"d-c", "@b:example.org", 200U},
                 {"d-d", "@a:example.org", 100U},
                 {"d-e", "@b:example.org", 400U}
        })
        {
            REQUIRE(table.insert(scheduled(id, user, 0U, 1000U)));
            REQUIRE(table.finalise(id, DelayedEventStatus::cancelled, when, {}, {}));
        }
        REQUIRE(table.insert(scheduled("d-live", "@a:example.org", 0U, 1000U)));

        WHEN("one user's rows and the table's rows are read")
        {
            THEN("each list is by finalised time then delay ID, bounded by the limit and the cutoff")
            {
                REQUIRE(ids_of(table.finalised_of_user("@a:example.org", 10U)) ==
                        std::vector<std::string>{"d-b", "d-d", "d-a"});
                REQUIRE(ids_of(table.finalised_of_user("@a:example.org", 2U)) ==
                        std::vector<std::string>{"d-b", "d-d"});
                REQUIRE(table.finalised_of_user("@a:example.org", 0U).empty());
                REQUIRE(table.finalised_of_user("@nobody:example.org", 5U).empty());
                REQUIRE(table.finalised_count("@a:example.org") == 3U);
                REQUIRE(ids_of(table.finalised_before(1000U, 10U)) ==
                        std::vector<std::string>{"d-b", "d-d", "d-c", "d-a", "d-e"});
                REQUIRE(ids_of(table.finalised_before(1000U, 3U)) == std::vector<std::string>{"d-b", "d-d", "d-c"});
                REQUIRE(ids_of(table.finalised_before(300U, 10U)) == std::vector<std::string>{"d-b", "d-d", "d-c"});
                REQUIRE(ids_of(table.finalised_before(301U, 10U)).size() == 4U);
                REQUIRE(table.finalised_before(100U, 10U).empty());
                REQUIRE(table.finalised_before(1000U, 0U).empty());
            }
        }
    }
}

SCENARIO("A transaction ID is looked up by user, device, room, event type and ID, and an empty one is not indexed",
         "[database][delayed-events]")
{
    GIVEN("a row with a transaction ID and two rows with none")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("d-txn", "@a:example.org", 0U, 1000U, "txn-1")));
        REQUIRE(table.insert(scheduled("d-none-1", "@a:example.org", 0U, 1000U)));
        REQUIRE(table.insert(scheduled("d-none-2", "@a:example.org", 0U, 1000U)));

        WHEN("each part of the key is changed in turn")
        {
            auto const row = table.find("d-txn");
            auto const find = [&table](std::string_view user, std::string_view device, std::string_view room,
                                       std::string_view type, std::string_view txn) {
                return table.find_by_transaction(user, device, room, type, txn);
            };

            THEN("only the exact tuple finds the row, and an empty transaction ID finds nothing")
            {
                REQUIRE(find("@a:example.org", "DEVICE", "!room:example.org", "m.room.message", "txn-1") == row);
                REQUIRE(find("@b:example.org", "DEVICE", "!room:example.org", "m.room.message", "txn-1") == nullptr);
                REQUIRE(find("@a:example.org", "OTHER", "!room:example.org", "m.room.message", "txn-1") == nullptr);
                REQUIRE(find("@a:example.org", "DEVICE", "!other:example.org", "m.room.message", "txn-1") == nullptr);
                REQUIRE(find("@a:example.org", "DEVICE", "!room:example.org", "m.room.other", "txn-1") == nullptr);
                REQUIRE(find("@a:example.org", "DEVICE", "!room:example.org", "m.room.message", "txn-2") == nullptr);
                REQUIRE(find("@a:example.org", "DEVICE", "!room:example.org", "m.room.message", "") == nullptr);
            }
        }

        WHEN("fields that would join into the same text are split differently")
        {
            auto shifted = scheduled("d-shift", "@a:example.org", 0U, 1000U, "txn-1");
            shifted.device_id = "DEVICE!room:example.org";
            shifted.room_id = "";
            auto const accepted = table.insert(shifted);

            THEN("the keys differ, so the row is accepted and the first row is still the one found")
            {
                REQUIRE(accepted);
                REQUIRE(table.find_by_transaction("@a:example.org", "DEVICE", "!room:example.org", "m.room.message",
                                                  "txn-1") == table.find("d-txn"));
                REQUIRE(table.find_by_transaction("@a:example.org", "DEVICE!room:example.org", "", "m.room.message",
                                                  "txn-1") == table.find("d-shift"));
            }
        }

        WHEN("a second row with the same transaction tuple is inserted")
        {
            auto const accepted = table.insert(scheduled("d-twin", "@a:example.org", 0U, 1000U, "txn-1"));
            REQUIRE(table.finalise("d-txn", DelayedEventStatus::cancelled, 5U, {}, {}));

            THEN("it is refused, and the finalised row still answers the lookup (any status)")
            {
                REQUIRE_FALSE(accepted);
                REQUIRE(table.find("d-twin") == nullptr);
                REQUIRE(table.find_by_transaction("@a:example.org", "DEVICE", "!room:example.org", "m.room.message",
                                                  "txn-1") == table.find("d-txn"));
            }
        }
    }
}

SCENARIO("A second sent row claiming an event ID another row holds is refused", "[database][delayed-events]")
{
    GIVEN("a sent row")
    {
        auto table = DelayedEventTable{};
        auto first = scheduled("d-first", "@a:example.org", 0U, 1000U);
        first.status = DelayedEventStatus::sent;
        first.finalised_at_ms = 5U;
        first.event_id = "$event:example.org";
        REQUIRE(table.insert(first));

        WHEN("another sent row with the same event ID is inserted")
        {
            auto second = scheduled("d-second", "@a:example.org", 0U, 1000U);
            second.status = DelayedEventStatus::sent;
            second.finalised_at_ms = 6U;
            second.event_id = "$event:example.org";
            auto const accepted = table.insert(second);

            THEN("it is refused, and the first row still owns the event ID and erasing it frees the ID")
            {
                REQUIRE_FALSE(accepted);
                REQUIRE(table.find("d-second") == nullptr);
                REQUIRE(table.find_sent_by_event_id("$event:example.org") == table.find("d-first"));
                REQUIRE(table.erase("d-first"));
                REQUIRE(table.find_sent_by_event_id("$event:example.org") == nullptr);
            }
        }
    }
}

SCENARIO("Erasing a row, or all of a user's rows, removes it from every index", "[database][delayed-events]")
{
    GIVEN("two users with scheduled, sent and cancelled rows")
    {
        auto table = DelayedEventTable{};
        REQUIRE(table.insert(scheduled("a-1", "@a:example.org", 0U, 1000U, "txn-a")));
        REQUIRE(table.insert(scheduled("a-2", "@a:example.org", 0U, 2000U)));
        REQUIRE(table.insert(scheduled("a-3", "@a:example.org", 0U, 3000U)));
        REQUIRE(table.insert(scheduled("b-1", "@b:example.org", 0U, 4000U)));
        REQUIRE(table.insert(scheduled("b-2", "@b:example.org", 0U, 5000U)));
        REQUIRE(table.finalise("a-2", DelayedEventStatus::sent, 10U, "$sent-a", {}));
        REQUIRE(table.finalise("a-3", DelayedEventStatus::cancelled, 11U, {}, {}));
        REQUIRE(table.finalise("b-2", DelayedEventStatus::sent, 12U, "$sent-b", {}));
        REQUIRE(table.mark_being_sent("b-1"));

        WHEN("one row is erased")
        {
            auto const erased = table.erase("a-2");
            auto const again = table.erase("a-2");

            THEN("it leaves the table, its event index and its user's finalised list; a second erase is false")
            {
                REQUIRE(erased);
                REQUIRE_FALSE(again);
                REQUIRE(table.size() == 4U);
                REQUIRE(table.find("a-2") == nullptr);
                REQUIRE(table.find_sent_by_event_id("$sent-a") == nullptr);
                REQUIRE(table.finalised_count("@a:example.org") == 1U);
                REQUIRE(table.find_sent_by_event_id("$sent-b") != nullptr);
            }
        }

        WHEN("all of the first user's rows are erased")
        {
            auto const erased = table.erase_user("@a:example.org");
            auto const none = table.erase_user("@a:example.org");

            THEN("every row of that user is gone from every index and the other user's rows are untouched")
            {
                REQUIRE(erased == 3U);
                REQUIRE(none == 0U);
                REQUIRE(table.size() == 2U);
                REQUIRE(table.scheduled_count("@a:example.org") == 0U);
                REQUIRE(table.finalised_count("@a:example.org") == 0U);
                REQUIRE(table.find_by_transaction("@a:example.org", "DEVICE", "!room:example.org", "m.room.message",
                                                  "txn-a") == nullptr);
                REQUIRE(table.find_sent_by_event_id("$sent-a") == nullptr);
                REQUIRE(ids_of(table.finalised_before(1000U, 10U)) == std::vector<std::string>{"b-2"});
                REQUIRE(table.scheduled_count("@b:example.org") == 1U);
                REQUIRE(table.find_owned("@b:example.org", "b-1") != nullptr);
            }
        }

        WHEN("the row marked as being sent is erased")
        {
            REQUIRE(table.erase("b-1"));

            THEN("the mark goes with it")
            {
                REQUIRE_FALSE(table.is_being_sent("b-1"));
                REQUIRE(due_id(table) == "a-1");
            }
        }

        WHEN("the table is cleared")
        {
            table.clear();

            THEN("nothing is left in any index")
            {
                REQUIRE(table.size() == 0U);
                REQUIRE(table.earliest_due() == nullptr);
                REQUIRE(table.scheduled_count("@b:example.org") == 0U);
                REQUIRE_FALSE(table.is_being_sent("b-1"));
                REQUIRE(table.finalised_before(1000U, 10U).empty());
                REQUIRE(table.find_sent_by_event_id("$sent-b") == nullptr);
            }
        }
    }
}

SCENARIO("No lookup of the delayed-events table examines more rows than it returns", "[database][delayed-events]")
{
    GIVEN("a table of 2000 rows across 20 users, half of them with a transaction ID")
    {
        auto table = DelayedEventTable{};
        for (auto index = std::size_t{0U}; index < 2000U; ++index)
        {
            auto const user = "@user" + std::to_string(index % 20U) + ":example.org";
            auto const txn = index % 2U == 0U ? "txn-" + std::to_string(index) : std::string{};
            REQUIRE(table.insert(scheduled("d-" + std::to_string(index), user, index, 100'000U, txn)));
        }
        REQUIRE(table.finalise("d-7", DelayedEventStatus::sent, 5U, "$seven", {}));
        auto const before = table.rows_examined();

        WHEN("each single-key question is asked once")
        {
            auto const* by_id = table.find("d-1500");
            auto const* owned = table.find_owned("@user0:example.org", "d-1500");
            auto const* due = table.earliest_due();
            auto const* by_txn = table.find_by_transaction("@user0:example.org", "DEVICE", "!room:example.org",
                                                           "m.room.message", "txn-1500");
            auto const* by_event = table.find_sent_by_event_id("$seven");
            auto const count = table.scheduled_count("@user3:example.org");
            auto const earliest = table.earliest_due_ms_of_user("@user3:example.org");
            auto const finalised = table.finalised_of_user("@user7:example.org", 5U);
            auto const old = table.finalised_before(1000U, 5U);
            auto const examined = table.rows_examined() - before;

            THEN("the answers are right and the rows examined stay at the few rows the answers hold")
            {
                REQUIRE(by_id != nullptr);
                REQUIRE(owned == by_id);
                REQUIRE(due != nullptr);
                REQUIRE(due->delay_id == "d-0");
                REQUIRE(by_txn == by_id);
                REQUIRE(by_event == table.find("d-7"));
                REQUIRE(count == 100U);
                REQUIRE(earliest.has_value());
                REQUIRE(finalised.size() == 1U);
                REQUIRE(old.size() == 1U);
                REQUIRE(examined <= 8U);
            }
        }
    }
}
