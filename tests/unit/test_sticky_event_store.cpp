// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The sticky-event store functions (migration 005, ADR-0854): the per-sender cap and which row it evicts, the no-op
// cases, that memory changes only after a commit, bound parameters only, the prune, the delete of a user's rows, the
// sticky duration a delayed event keeps in a side table, and a round trip through a SQLite file with strict hydration.
#include "../support/TempDirectory.hpp"
#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/DelayedEventOutcomeResult.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStore.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/StickyEventCaps.hpp"
#include "merovingian/database/StickyEventRowText.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/database/StickyEventTable.hpp"
#include "merovingian/database/TableLoadProfile.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
using db::DelayedEventOutcomeResult;
using db::DelayedEventStatus;
using db::PersistentDelayedEvent;
using db::PersistentStickyEvent;

constexpr auto room = "!room:example.org";
constexpr auto alice = "@alice:example.org";
constexpr auto bob = "@bob:example.org";
// The clock every store test passes, and an expiry the real clock will not reach for a very long time.
constexpr auto now_ms = std::int64_t{1000};
constexpr auto far_future_ms = std::int64_t{9'000'000'000'000};

[[nodiscard]] auto sticky(std::string event_id, std::int64_t expires_at_ms, std::string sender = alice)
    -> PersistentStickyEvent
{
    return {std::move(event_id), room, std::move(sender), 500, expires_at_ms};
}

// Senders of three servers for the room cap (ADR-0857): `flood.example` has two users, so one server can hold more rows
// than any one of its senders.
constexpr auto flood_a = "@a:flood.example";
constexpr auto flood_b = "@b:flood.example";
constexpr auto calm = "@c:calm.example";
constexpr auto other_room = "!other:example.org";

// Caps under which only the room cap can bite.
[[nodiscard]] constexpr auto room_caps(std::size_t max_per_room) -> db::StickyEventCaps
{
    return {100U, max_per_room};
}

[[nodiscard]] auto sticky_in(std::string_view room_id, std::string event_id, std::int64_t expires_at_ms,
                             std::string sender) -> PersistentStickyEvent
{
    return {std::move(event_id), std::string{room_id}, std::move(sender), 500, expires_at_ms};
}

// Records each row in order under `caps`, requiring every one to succeed.
auto record_all(db::PersistentStore& store, std::vector<PersistentStickyEvent> rows, db::StickyEventCaps caps) -> void
{
    for (auto& row : rows)
    {
        REQUIRE(db::record_sticky_event(store, std::move(row), caps, now_ms));
    }
}

[[nodiscard]] auto delayed(std::string delay_id, std::optional<std::int64_t> duration = std::nullopt)
    -> PersistentDelayedEvent
{
    auto made = PersistentDelayedEvent{};
    made.delay_id = std::move(delay_id);
    made.user_id = alice;
    made.device_id = "DEVICE";
    made.room_id = room;
    made.event_type = "org.matrix.msc4143.rtc.member";
    made.content_json = "{}";
    made.delay_ms = 60'000U;
    made.delayed_since_ms = 1'000U;
    made.sticky_duration_ms = duration;
    return made;
}

[[nodiscard]] auto opened_store() -> db::PersistentStoreOpenResult
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    return opened;
}

[[nodiscard]] auto ids_in_room(db::PersistentStore const& store, std::int64_t at) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const* found : store.sticky_events.unexpired_of_room(room, at))
    {
        ids.push_back(found->event_id);
    }
    return ids;
}

struct SqliteClose final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

// Runs one query on its own connection to the file and returns the text of its first column of its first row.
[[nodiscard]] auto sqlite_first_text(std::filesystem::path const& path, char const* sql) -> std::string
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    auto text = std::string{};
    if (opened != SQLITE_OK)
    {
        return text;
    }
    auto* statement = static_cast<sqlite3_stmt*>(nullptr);
    if (sqlite3_prepare_v2(connection.get(), sql, -1, &statement, nullptr) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW)
    {
        auto const* value = sqlite3_column_text(statement, 0);
        if (value != nullptr)
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            text = reinterpret_cast<char const*>(value);
        }
    }
    sqlite3_finalize(statement);
    return text;
}

[[nodiscard]] auto temporary_database(std::string_view stem) -> std::filesystem::path
{
    return merovingian::tests::temporary_directory() /
           (std::string{stem} + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
            ".sqlite3");
}

// Writes `values` to the database as one `sticky_events` row without touching memory, the way a damaged or foreign
// file would hold it (a bound-parameter insert, so any text goes in).
[[nodiscard]] auto insert_raw_sticky(db::PersistentStore& store, std::array<std::string, 5> const& values) -> bool
{
    auto statement = db::PreparedStatement{
        "insert_raw_sticky_event",
        "INSERT INTO sticky_events (event_id, room_id, sender, received_at_ms, expires_at_ms) VALUES ($1, $2, $3, $4, "
        "$5)",
        {}};
    for (auto const& value : values)
    {
        statement.parameters.push_back(db::BoundValue{value, false});
    }
    return db::commit_persistent_transaction(store, {statement});
}

[[nodiscard]] auto insert_raw_duration(db::PersistentStore& store, std::string delay_id, std::string duration) -> bool
{
    auto const statement = db::PreparedStatement{
        "insert_raw_sticky_duration",
        "INSERT INTO delayed_event_sticky_durations (delay_id, sticky_duration_ms) VALUES ($1, $2)",
        {db::BoundValue{std::move(delay_id), false}, db::BoundValue{std::move(duration), false}}
    };
    return db::commit_persistent_transaction(store, {statement});
}

} // namespace

SCENARIO("A sticky event is recorded once, and an expired one is not recorded",
         "[database][sticky-events][sticky-event-store]")
{
    GIVEN("a memory store")
    {
        auto opened = opened_store();
        auto& store = opened.store;

        WHEN("a row is recorded, recorded again with different columns, and an expired row is recorded")
        {
            auto const before = db::committed_transaction_count(store);
            auto const first = db::record_sticky_event(store, sticky("$one", 5000), {10U}, now_ms);
            auto const after_first = db::committed_transaction_count(store);
            auto const duplicate = db::record_sticky_event(store, sticky("$one", 9000, bob), {10U}, now_ms);
            auto const expired = db::record_sticky_event(store, sticky("$stale", 1000), {10U}, now_ms);
            auto const long_gone = db::record_sticky_event(store, sticky("$older", 5), {10U}, now_ms);
            // A negative `origin_server_ts` gives a negative expiry; it is expired before any other check, even with
            // caps that would refuse a storable row.
            auto const negative = db::record_sticky_event(store, sticky("$negative", -3'600'000), {0U, 0U}, now_ms);
            auto const after_all = db::committed_transaction_count(store);

            THEN("the first is stored in one transaction, and the other four succeed without writing anything")
            {
                REQUIRE(first);
                REQUIRE(after_first - before == 1U);
                REQUIRE(duplicate);
                REQUIRE(expired);
                REQUIRE(long_gone);
                REQUIRE(negative);
                REQUIRE(after_all == after_first);
                REQUIRE(store.sticky_events.size() == 1U);
                REQUIRE(store.sticky_events.find("$one", now_ms)->sender == alice);
                REQUIRE(store.sticky_events.find("$one", now_ms)->expires_at_ms == 5000);
            }
        }

        WHEN("a row that is not storable is recorded, and a cap of 0 is given")
        {
            auto const empty_sender = db::record_sticky_event(store, sticky("$a", 5000, ""), {10U}, now_ms);
            auto const over_long = db::record_sticky_event(store, sticky(std::string(256U, 'x'), 5000), {10U}, now_ms);
            auto const no_cap = db::record_sticky_event(store, sticky("$b", 5000), {0U}, now_ms);
            auto const no_room_cap = db::record_sticky_event(store, sticky("$c", 5000), {10U, 0U}, now_ms);

            THEN("each is refused and nothing is written")
            {
                REQUIRE_FALSE(empty_sender);
                REQUIRE_FALSE(over_long);
                REQUIRE_FALSE(no_cap);
                REQUIRE_FALSE(no_room_cap);
                REQUIRE(store.sticky_events.size() == 0U);
            }
        }
    }
}

SCENARIO("Recording a sticky event expires the sender's oldest rows past the cap",
         "[database][sticky-events][sticky-event-store]")
{
    GIVEN("a sender holding three unexpired rows, a cap of three, and another sender holding one")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::record_sticky_event(store, sticky("$b-2000", 2000), {3U}, now_ms));
        REQUIRE(db::record_sticky_event(store, sticky("$a-2000", 2000), {3U}, now_ms));
        REQUIRE(db::record_sticky_event(store, sticky("$c-3000", 3000), {3U}, now_ms));
        REQUIRE(db::record_sticky_event(store, sticky("$bob", 1500, bob), {3U}, now_ms));

        WHEN("a fourth row is recorded that expires last")
        {
            auto const before = db::committed_transaction_count(store);
            auto const recorded = db::record_sticky_event(store, sticky("$d-4000", 4000), {3U}, now_ms);
            auto const transactions = db::committed_transaction_count(store) - before;

            THEN("the oldest by expiry, ties by event ID, goes in the same transaction and the other sender is kept")
            {
                REQUIRE(recorded);
                REQUIRE(transactions == 1U);
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, now_ms) == 3U);
                REQUIRE_FALSE(store.sticky_events.contains("$a-2000"));
                REQUIRE(store.sticky_events.contains("$b-2000"));
                REQUIRE(store.sticky_events.contains("$c-3000"));
                REQUIRE(store.sticky_events.contains("$d-4000"));
                REQUIRE(store.sticky_events.contains("$bob"));
            }
        }

        WHEN("a fourth row is recorded that expires before every other row")
        {
            auto const recorded = db::record_sticky_event(store, sticky("$e-1100", 1100), {3U}, now_ms);

            THEN("the new row is the oldest, so it is not stored and the other rows stay")
            {
                REQUIRE(recorded);
                REQUIRE_FALSE(store.sticky_events.contains("$e-1100"));
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, now_ms) == 3U);
                REQUIRE(store.sticky_events.contains("$a-2000"));
            }
        }

        WHEN("a row is recorded with a cap of one")
        {
            auto const recorded = db::record_sticky_event(store, sticky("$f-9000", 9000), {1U}, now_ms);

            THEN("every earlier row of the sender goes and only the new one stays")
            {
                REQUIRE(recorded);
                REQUIRE(ids_in_room(store, now_ms) == std::vector<std::string>{"$bob", "$f-9000"});
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, now_ms) == 1U);
            }
        }

        WHEN("the sender holds expired rows too and one more row is recorded under a cap of three")
        {
            REQUIRE(db::record_sticky_event(store, sticky("$g-9000", 9000), {3U}, now_ms));
            auto const later = std::int64_t{2500};
            REQUIRE(db::record_sticky_event(store, sticky("$h-9500", 9500), {3U}, later));

            THEN("an expired row is neither counted nor evicted for the cap")
            {
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, later) == 3U);
                REQUIRE(store.sticky_events.contains("$c-3000"));
                REQUIRE(store.sticky_events.contains("$g-9000"));
                REQUIRE(store.sticky_events.contains("$h-9500"));
            }
        }

        WHEN("rows are recorded far past the cap, one after another")
        {
            for (auto index = 0; index < 20; ++index)
            {
                REQUIRE(db::record_sticky_event(store, sticky("$n-" + std::to_string(10 + index), 10'000 + index), {3U},
                                                now_ms));
            }

            THEN("the sender still holds three, the newest three")
            {
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, now_ms) == 3U);
                REQUIRE(store.sticky_events.contains("$n-29"));
                REQUIRE(store.sticky_events.contains("$n-28"));
                REQUIRE(store.sticky_events.contains("$n-27"));
                REQUIRE_FALSE(store.sticky_events.contains("$n-26"));
            }
        }
    }
}

SCENARIO("Past the room cap, the server holding the most rows in the room loses its oldest",
         "[database][sticky-events][sticky-event-store][security]")
{
    GIVEN("a room at its cap of 4: calm.example's row is the oldest, and flood.example's two users hold three")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        record_all(store,
                   {sticky_in(room, "$calm-old", 2000, calm), sticky_in(room, "$f1", 3000, flood_a),
                    sticky_in(room, "$f2", 4000, flood_b), sticky_in(room, "$f3", 5000, flood_a)},
                   room_caps(4U));
        auto const before = db::committed_transaction_count(store);

        WHEN("another flood.example user records a row")
        {
            auto const recorded =
                db::record_sticky_event(store, sticky_in(room, "$f4", 6000, flood_b), room_caps(4U), now_ms);

            THEN("flood.example's oldest row goes in the same transaction, and calm.example's older row stays")
            {
                REQUIRE(recorded);
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.sticky_events.contains("$calm-old"));
                REQUIRE_FALSE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.contains("$f4"));
                REQUIRE(store.sticky_events.unexpired_of_room(room, now_ms).size() == 4U);
            }
        }

        WHEN("calm.example records a second row")
        {
            auto const recorded =
                db::record_sticky_event(store, sticky_in(room, "$calm-new", 9000, calm), room_caps(4U), now_ms);

            THEN("flood.example, still holding the most, gives up its oldest row")
            {
                REQUIRE(recorded);
                REQUIRE(store.sticky_events.contains("$calm-old"));
                REQUIRE(store.sticky_events.contains("$calm-new"));
                REQUIRE_FALSE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.contains("$f2"));
            }
        }

        WHEN("flood.example records a row older than every row it holds")
        {
            auto const recorded =
                db::record_sticky_event(store, sticky_in(room, "$f0", 2500, flood_a), room_caps(4U), now_ms);

            THEN("the new row is the one that goes: it is not stored, nothing is written, and the call succeeds")
            {
                REQUIRE(recorded);
                REQUIRE(db::committed_transaction_count(store) == before);
                REQUIRE_FALSE(store.sticky_events.contains("$f0"));
                REQUIRE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.unexpired_of_room(room, now_ms).size() == 4U);
            }
        }

        WHEN("flood.example records a row in another room")
        {
            auto const recorded =
                db::record_sticky_event(store, sticky_in(other_room, "$o1", 6000, flood_a), room_caps(4U), now_ms);

            THEN("the full room is untouched: its cap counts its own rows only")
            {
                REQUIRE(recorded);
                REQUIRE(store.sticky_events.contains("$o1"));
                REQUIRE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.unexpired_of_room(room, now_ms).size() == 4U);
            }
        }
    }
}

SCENARIO("A room-cap tie goes against the new row's server, else the smallest server name",
         "[database][sticky-events][sticky-event-store]")
{
    auto opened = opened_store();
    auto& store = opened.store;

    GIVEN("a room at its cap of 4: calm.example holds two rows, flood.example one and example.org one")
    {
        record_all(store,
                   {sticky_in(room, "$c1", 2000, calm), sticky_in(room, "$c2", 2500, calm),
                    sticky_in(room, "$f1", 3000, flood_a), sticky_in(room, "$x1", 3500, alice)},
                   room_caps(4U));

        WHEN("flood.example records a second row, tying with calm.example")
        {
            REQUIRE(db::record_sticky_event(store, sticky_in(room, "$f2", 6000, flood_b), room_caps(4U), now_ms));

            THEN("the tie goes against flood.example, the new row's server, though calm.example's rows are older")
            {
                REQUIRE(store.sticky_events.contains("$c1"));
                REQUIRE(store.sticky_events.contains("$c2"));
                REQUIRE_FALSE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.contains("$f2"));
            }
        }
    }

    GIVEN("a room at its cap of 4: calm.example and flood.example hold two rows each")
    {
        record_all(store,
                   {sticky_in(room, "$c1", 2000, calm), sticky_in(room, "$c2", 2500, calm),
                    sticky_in(room, "$f1", 1500, flood_a), sticky_in(room, "$f2", 3200, flood_b)},
                   room_caps(4U));

        WHEN("example.org, holding none, records a row")
        {
            REQUIRE(db::record_sticky_event(store, sticky_in(room, "$x1", 7000, alice), room_caps(4U), now_ms));

            THEN("the tie between the other two goes against the smaller name, calm.example, whose oldest row goes")
            {
                REQUIRE_FALSE(store.sticky_events.contains("$c1"));
                REQUIRE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.contains("$x1"));
            }
        }
    }

    GIVEN("a room capped at 2 holding one row each from calm.example and flood.example, and a per-sender cap of 1")
    {
        record_all(store, {sticky_in(room, "$c1", 2000, calm), sticky_in(room, "$f1", 3000, flood_a)},
                   db::StickyEventCaps{1U, 2U});

        WHEN("the flood.example sender records a second row")
        {
            REQUIRE(db::record_sticky_event(store, sticky_in(room, "$f2", 6000, flood_a), db::StickyEventCaps{1U, 2U},
                                            now_ms));

            THEN("the sender's own cap expires its first row, which then leaves the room within its cap")
            {
                REQUIRE(store.sticky_events.contains("$c1"));
                REQUIRE_FALSE(store.sticky_events.contains("$f1"));
                REQUIRE(store.sticky_events.contains("$f2"));
            }
        }
    }
}

SCENARIO("A sticky event is written with bound parameters only", "[database][sticky-events][sticky-event-store]")
{
    GIVEN("a memory store capturing statements")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        db::enable_statement_capture(store, 16U);

        WHEN("a row is recorded over the cap, then deleted, its sender's rows deleted and the store pruned")
        {
            REQUIRE(db::record_sticky_event(store, sticky("$old-event", 2000), {1U}, now_ms));
            REQUIRE(db::record_sticky_event(store, sticky("$new-event", 3000), {1U}, now_ms));
            REQUIRE(db::delete_sticky_event(store, "$new-event"));
            REQUIRE(db::delete_sticky_events_of_user(store, alice));
            REQUIRE(db::prune_expired_sticky_events(store, 5000));
            auto const& captured = store.captured_statements;

            THEN("every statement uses $n placeholders and none carries a value")
            {
                REQUIRE(captured.size() >= 6U);
                for (auto const& statement : captured)
                {
                    INFO("statement " << statement.name);
                    REQUIRE(statement.sql.find('$') != std::string::npos);
                    REQUIRE(statement.sql.find("event") != std::string::npos);
                    REQUIRE(statement.sql.find("$old-event") == std::string::npos);
                    REQUIRE(statement.sql.find("$new-event") == std::string::npos);
                    REQUIRE(statement.sql.find(alice) == std::string::npos);
                }
                REQUIRE(captured[0].name == "insert_sticky_event");
                REQUIRE(captured[0].parameters.size() == 5U);
                REQUIRE(captured[0].parameters[0].value == "$old-event");
                REQUIRE(captured[0].parameters[3].value == "500");
                REQUIRE(captured[0].parameters[4].value == "2000");
            }
        }
    }
}

SCENARIO("A failed commit leaves the sticky events mirror unchanged", "[database][sticky-events][sticky-event-store]")
{
    GIVEN("a store holding a sender at the cap, an expired row and a delayed event with a sticky duration")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::record_sticky_event(store, sticky("$one", 2000), {2U}, now_ms));
        REQUIRE(db::record_sticky_event(store, sticky("$two", 3000), {2U}, now_ms));
        REQUIRE(db::store_delayed_event(store, delayed("d-live", 60'000)));

        WHEN("the commit fails for a record that would evict, a delete, a user delete and a prune")
        {
            db::force_next_persist_failures(store, 1U);
            auto const recorded = db::record_sticky_event(store, sticky("$three", 4000), {2U}, now_ms);
            db::force_next_persist_failures(store, 1U);
            auto const deleted = db::delete_sticky_event(store, "$one");
            db::force_next_persist_failures(store, 1U);
            auto const user_deleted = db::delete_sticky_events_of_user(store, alice);
            db::force_next_persist_failures(store, 1U);
            auto const pruned = db::prune_expired_sticky_events(store, 2500);
            db::force_next_persist_failures(store, 1U);
            auto const cancelled = db::cancel_delayed_event(store, "d-live", 9000U, 10U);

            THEN("each reports the failure and memory is exactly as it was")
            {
                REQUIRE_FALSE(recorded);
                REQUIRE_FALSE(deleted);
                REQUIRE_FALSE(user_deleted);
                REQUIRE_FALSE(pruned);
                REQUIRE_FALSE(cancelled);
                REQUIRE(store.sticky_events.size() == 2U);
                REQUIRE(store.sticky_events.contains("$one"));
                REQUIRE(store.sticky_events.contains("$two"));
                REQUIRE_FALSE(store.sticky_events.contains("$three"));
                REQUIRE(store.delayed_events.find("d-live")->status == DelayedEventStatus::scheduled);
                REQUIRE(store.delayed_events.find("d-live")->sticky_duration_ms == std::optional<std::int64_t>{60'000});
            }
        }
    }
}

SCENARIO("A failed commit still finalises a delayed event in memory and drops its sticky duration (ADR-0825)",
         "[database][sticky-events][sticky-event-store]")
{
    GIVEN("a memory store holding a scheduled delayed event with a sticky duration")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_delayed_event(store, delayed("d-send", 3'600'000)));

        WHEN("the outcome is recorded and its commit fails")
        {
            db::force_next_persist_failures(store, 1U);
            auto const result =
                db::record_delayed_event_outcome(store, "d-send", DelayedEventStatus::sent, 2001U, "$sent", {}, 10U);

            THEN("memory is finalised and holds no sticky duration, and the caller is told the commit failed")
            {
                REQUIRE(result == DelayedEventOutcomeResult::commit_failed);
                REQUIRE(store.delayed_events.find("d-send")->status == DelayedEventStatus::sent);
                REQUIRE_FALSE(store.delayed_events.find("d-send")->sticky_duration_ms.has_value());
            }
        }
    }
}

SCENARIO("Redaction and deactivation delete sticky events, also those only the database holds",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite store with rows of two senders, and a row of the first sender that only the file holds")
    {
        auto const path = temporary_database("merovingian-sticky-delete-");
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        REQUIRE(db::record_sticky_event(opened.store, sticky("$a1", 5000), {10U}, now_ms));
        REQUIRE(db::record_sticky_event(opened.store, sticky("$a2", 6000), {10U}, now_ms));
        REQUIRE(db::record_sticky_event(opened.store, sticky("$b1", 7000, bob), {10U}, now_ms));
        REQUIRE(insert_raw_sticky(opened.store, {"$only-in-file", room, alice, "1", "99999"}));

        WHEN("one event is deleted, as a redaction does")
        {
            auto const deleted = db::delete_sticky_event(opened.store, "$a1");
            auto const again = db::delete_sticky_event(opened.store, "$missing");

            THEN("its row is gone from memory and the file, and deleting a missing row succeeds")
            {
                REQUIRE(deleted);
                REQUIRE(again);
                REQUIRE_FALSE(opened.store.sticky_events.contains("$a1"));
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM sticky_events WHERE event_id = '$a1'") == "0");
                REQUIRE(opened.store.sticky_events.contains("$a2"));
            }
        }

        WHEN("the first sender's rows are deleted, as a deactivation does")
        {
            auto const deleted = db::delete_sticky_events_of_user(opened.store, alice);

            THEN("every one of that sender's rows is gone from memory and the file, and the other sender's stays")
            {
                REQUIRE(deleted);
                REQUIRE(opened.store.sticky_events.size() == 1U);
                REQUIRE(opened.store.sticky_events.contains("$b1"));
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM sticky_events") == "1");
                REQUIRE(sqlite_first_text(path, "SELECT sender FROM sticky_events") == bob);
            }
        }
        opened = {};
        std::filesystem::remove(path);
    }
}

SCENARIO("Pruning deletes every expired sticky event and the orphaned sticky durations",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite store with live and expired rows, a row only the file holds, and four sticky durations")
    {
        auto const path = temporary_database("merovingian-sticky-prune-");
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(db::record_sticky_event(store, sticky("$live", 9000), {10U}, now_ms));
        REQUIRE(db::record_sticky_event(store, sticky("$soon", 3000), {10U}, now_ms));
        // Written to the file but not to memory, with a shorter and a longer number than the cutoff has digits.
        REQUIRE(insert_raw_sticky(store, {"$file-short", room, alice, "1", "900"}));
        REQUIRE(insert_raw_sticky(store, {"$file-long", room, alice, "1", "12345678"}));
        REQUIRE(db::store_delayed_event(store, delayed("d-scheduled", 60'000)));
        REQUIRE(db::store_delayed_event(store, delayed("d-cancelled", 60'000)));
        REQUIRE(db::cancel_delayed_event(store, "d-cancelled", 2000U, 10U));
        // Side rows that finalising would have deleted, and one for a delayed event that does not exist.
        REQUIRE(insert_raw_duration(store, "d-cancelled", "60000"));
        REQUIRE(insert_raw_duration(store, "d-missing", "60000"));
        REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_event_sticky_durations") == "3");

        WHEN("the store is pruned at 5000")
        {
            auto const pruned = db::prune_expired_sticky_events(store, 5000);

            THEN("the rows expiring at or before 5000 are gone from memory and the file, the rest stay")
            {
                REQUIRE(pruned);
                REQUIRE(sqlite_first_text(path, "SELECT group_concat(event_id) FROM (SELECT event_id FROM sticky_events "
                                                "ORDER BY event_id)") == "$file-long,$live");
                REQUIRE(store.sticky_events.size() == 1U);
                REQUIRE(store.sticky_events.contains("$live"));
            }

            AND_THEN("only the side row of a scheduled delayed event stays")
            {
                REQUIRE(sqlite_first_text(path, "SELECT group_concat(delay_id) FROM delayed_event_sticky_durations") ==
                        "d-scheduled");
                REQUIRE(store.delayed_events.find("d-scheduled")->sticky_duration_ms ==
                        std::optional<std::int64_t>{60'000});
            }
        }
        opened = {};
        std::filesystem::remove(path);
    }
}

SCENARIO("A delayed event keeps its sticky duration in a side row for as long as it is scheduled",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite store holding scheduled delayed events, two with a sticky duration")
    {
        auto const path = temporary_database("merovingian-sticky-duration-");
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(db::store_delayed_event(store, delayed("d-plain")));
        REQUIRE(db::store_delayed_event(store, delayed("d-cancel", 1)));
        REQUIRE(db::store_delayed_event(store, delayed("d-send", 3'600'000)));
        REQUIRE(db::store_delayed_event(store, delayed("d-fail", 90'000)));
        auto other = delayed("d-bob", 5000);
        other.user_id = bob;
        REQUIRE(db::store_delayed_event(store, std::move(other)));

        WHEN("the rows are inspected")
        {
            THEN("each sticky row has its side row, written in the transaction that stored it")
            {
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_event_sticky_durations") == "4");
                REQUIRE(sqlite_first_text(path, "SELECT sticky_duration_ms FROM delayed_event_sticky_durations WHERE "
                                                "delay_id = 'd-send'") == "3600000");
                REQUIRE(store.delayed_events.find("d-send")->sticky_duration_ms ==
                        std::optional<std::int64_t>{3'600'000});
                REQUIRE_FALSE(store.delayed_events.find("d-plain")->sticky_duration_ms.has_value());
            }
        }

        WHEN("a row with a sticky duration of 0 or a negative one is stored")
        {
            auto const zero = db::store_delayed_event(store, delayed("d-zero", 0));
            auto const negative = db::store_delayed_event(store, delayed("d-negative", -5));

            THEN("it is refused and writes nothing")
            {
                REQUIRE_FALSE(zero);
                REQUIRE_FALSE(negative);
                REQUIRE(store.delayed_events.find("d-zero") == nullptr);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "5");
            }
        }

        WHEN("one is cancelled, one is sent and one fails")
        {
            REQUIRE(db::cancel_delayed_event(store, "d-cancel", 2000U, 10U));
            REQUIRE(db::record_delayed_event_outcome(store, "d-send", DelayedEventStatus::sent, 2001U, "$sent", {},
                                                     10U) == DelayedEventOutcomeResult::recorded);
            REQUIRE(db::record_delayed_event_outcome(store, "d-fail", DelayedEventStatus::failed, 2002U, {},
                                                     R"({"errcode":"M_FORBIDDEN","error":"no"})",
                                                     10U) == DelayedEventOutcomeResult::recorded);

            THEN("each finalised row loses its side row and its memory duration, in the same transaction")
            {
                REQUIRE(sqlite_first_text(path, "SELECT group_concat(delay_id) FROM delayed_event_sticky_durations") ==
                        "d-bob");
                REQUIRE_FALSE(store.delayed_events.find("d-cancel")->sticky_duration_ms.has_value());
                REQUIRE_FALSE(store.delayed_events.find("d-send")->sticky_duration_ms.has_value());
                REQUIRE_FALSE(store.delayed_events.find("d-fail")->sticky_duration_ms.has_value());
            }
        }

        WHEN("a user's delayed events are deleted")
        {
            auto const deleted = db::delete_delayed_events_of_user(store, alice);

            THEN("their side rows go with them and the other user's stays")
            {
                REQUIRE(deleted);
                REQUIRE(sqlite_first_text(path, "SELECT group_concat(delay_id) FROM delayed_event_sticky_durations") ==
                        "d-bob");
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "1");
            }
        }
        opened = {};
        std::filesystem::remove(path);
    }
}

SCENARIO("Sticky events and sticky durations survive a reopen of a SQLite store",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite store holding live sticky events, an expired one, and delayed events with sticky durations")
    {
        auto const path = temporary_database("merovingian-sticky-reopen-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            auto& store = opened.store;
            // The store is told a clock in the past, so the stored expiries are in the real clock's future.
            REQUIRE(db::record_sticky_event(store, sticky("$live-1", far_future_ms), {10U}, now_ms));
            REQUIRE(db::record_sticky_event(store, sticky("$live-2", far_future_ms + 1, bob), {10U}, now_ms));
            REQUIRE(db::record_sticky_event(store, sticky("$expired", 5000), {10U}, 10));
            REQUIRE(db::store_delayed_event(store, delayed("d-sticky", 60'000)));
            REQUIRE(db::store_delayed_event(store, delayed("d-plain")));
            REQUIRE(db::store_delayed_event(store, delayed("d-done", 7000)));
            REQUIRE(db::cancel_delayed_event(store, "d-done", 2000U, 10U));
            // A side row for a finalised row and for a missing one are ignored at load, not counted.
            REQUIRE(insert_raw_duration(store, "d-done", "7000"));
            REQUIRE(insert_raw_duration(store, "d-missing", "7000"));
        }

        WHEN("the store is opened again")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const& store = reopened.store;

            THEN("the live rows are back with every column and the expired row is not loaded or counted")
            {
                REQUIRE(store.sticky_events.size() == 2U);
                auto const* live = store.sticky_events.find("$live-1", now_ms);
                REQUIRE(live != nullptr);
                REQUIRE(live->room_id == room);
                REQUIRE(live->sender == alice);
                REQUIRE(live->received_at_ms == 500);
                REQUIRE(live->expires_at_ms == far_future_ms);
                REQUIRE(store.sticky_events.find("$live-2", now_ms)->sender == bob);
                REQUIRE_FALSE(store.sticky_events.contains("$expired"));
                REQUIRE(store.sticky_events.unexpired_count_of_sender(alice, now_ms) == 1U);
                REQUIRE(store.sticky_event_rows_skipped_at_load == 0U);
            }

            AND_THEN("a scheduled row has its duration back, and finalised and missing owners' side rows are ignored")
            {
                REQUIRE(store.delayed_events.find("d-sticky")->sticky_duration_ms ==
                        std::optional<std::int64_t>{60'000});
                REQUIRE_FALSE(store.delayed_events.find("d-plain")->sticky_duration_ms.has_value());
                REQUIRE_FALSE(store.delayed_events.find("d-done")->sticky_duration_ms.has_value());
                REQUIRE(store.delayed_events.find("d-missing") == nullptr);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Hydration reads a sticky event row strictly and counts the rows it skips",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite file holding one valid row and rows that are not read exactly")
    {
        auto const path = temporary_database("merovingian-sticky-strict-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            auto& store = opened.store;
            REQUIRE(db::record_sticky_event(store, sticky("$good", far_future_ms), {10U}, now_ms));
            REQUIRE(insert_raw_sticky(store, {"$bad-expiry-text", room, alice, "1", "abc"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-expiry-empty", room, alice, "1", ""}));
            REQUIRE(insert_raw_sticky(store, {"$bad-expiry-negative", room, alice, "1", "-5"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-expiry-signed", room, alice, "1", "+9000000000000"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-expiry-overflow", room, alice, "1", "9223372036854775808"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-received", room, alice, "x", "9000000000000"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-sender", room, "", "1", "9000000000000"}));
            REQUIRE(insert_raw_sticky(store, {"$bad-room", std::string(256U, 'r'), alice, "1", "9000000000000"}));
            REQUIRE(insert_raw_sticky(store, {std::string(256U, 'e'), room, alice, "1", "9000000000000"}));
            REQUIRE(insert_raw_sticky(store, {"$expired-and-fine", room, alice, "1", "12345"}));
            REQUIRE(db::store_delayed_event(store, delayed("d-ok")));
            REQUIRE(insert_raw_duration(store, "d-ok", "0"));
        }

        WHEN("the store is opened")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the valid row loads, every damaged row is skipped and counted, an expired one is neither")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.sticky_events.size() == 1U);
                REQUIRE(reopened.store.sticky_events.contains("$good"));
                // Nine damaged sticky rows and one sticky duration of 0.
                REQUIRE(reopened.store.sticky_event_rows_skipped_at_load == 10U);
                REQUIRE_FALSE(reopened.store.delayed_events.find("d-ok")->sticky_duration_ms.has_value());
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM sticky_events") == "11");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("The strict readers of a sticky row and a sticky duration accept digits only",
         "[database][sticky-events][sticky-event-store]")
{
    GIVEN("texts for a sticky duration and columns for a sticky row")
    {
        WHEN("durations are read")
        {
            THEN("only one or more digits that are at least 1 and fit 63 bits are accepted")
            {
                REQUIRE(db::parse_sticky_duration_ms("1") == std::optional<std::int64_t>{1});
                REQUIRE(db::parse_sticky_duration_ms("3600000") == std::optional<std::int64_t>{3'600'000});
                REQUIRE(db::parse_sticky_duration_ms("9223372036854775807") ==
                        std::optional<std::int64_t>{INT64_MAX});
                REQUIRE_FALSE(db::parse_sticky_duration_ms("").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms("0").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms("-1").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms("+1").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms(" 1").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms("1.0").has_value());
                REQUIRE_FALSE(db::parse_sticky_duration_ms("9223372036854775808").has_value());
            }
        }

        WHEN("a row with too few columns is read")
        {
            auto const columns = std::array<std::string, 4>{"$a", room, alice, "1"};

            THEN("it is refused")
            {
                REQUIRE_FALSE(db::parse_sticky_event_row(columns).has_value());
            }
        }
    }
}

SCENARIO("A store opened with the federation worker profile does not load sticky events",
         "[database][sticky-events][sticky-event-store][sqlite]")
{
    GIVEN("a SQLite store holding a sticky event, a damaged row and a delayed event with a sticky duration")
    {
        auto const path = temporary_database("merovingian-sticky-profile-");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::record_sticky_event(opened.store, sticky("$live", far_future_ms), {10U}, now_ms));
            REQUIRE(insert_raw_sticky(opened.store, {"$bad", room, alice, "x", "y"}));
            REQUIRE(db::store_delayed_event(opened.store, delayed("d-one", 60'000)));
        }

        WHEN("it is opened with the full profile and with the federation worker profile")
        {
            auto const full = db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::full);
            auto const worker =
                db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::federation_worker);

            THEN("the full profile loads them, the worker profile loads none and counts no skipped row")
            {
                REQUIRE(full.ok);
                REQUIRE(full.store.sticky_events.size() == 1U);
                REQUIRE(full.store.sticky_event_rows_skipped_at_load == 1U);
                REQUIRE(worker.ok);
                REQUIRE(worker.store.sticky_events.size() == 0U);
                REQUIRE(worker.store.sticky_event_rows_skipped_at_load == 0U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM sticky_events") == "2");
            }
        }
        std::filesystem::remove(path);
    }
}
