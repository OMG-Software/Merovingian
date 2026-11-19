// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The delayed-events store functions (migration 003, ADR-0824, ADR-0825): what each refuses, that memory changes only
// after a commit (and the one exception), the per-user eviction in the finalising transaction, the age prune, bound
// parameters only, and a round trip through a SQLite file.
#include "../support/TempDirectory.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/DelayedEventOutcomeResult.hpp"
#include "merovingian/database/DelayedEventRowText.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventStore.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentDelayedEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/TableLoadProfile.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
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

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};
constexpr auto secret_content = std::string_view{R"({"body":"SECRET-CONTENT-MARKER"})"};

[[nodiscard]] auto row(std::string delay_id, std::string_view user = alice) -> PersistentDelayedEvent
{
    auto made = PersistentDelayedEvent{};
    made.delay_id = std::move(delay_id);
    made.user_id = std::string{user};
    made.device_id = "DEVICE";
    made.room_id = "!room:example.org";
    made.event_type = "m.room.message";
    made.content_json = std::string{secret_content};
    made.delay_ms = 60'000U;
    made.delayed_since_ms = 1'000U;
    return made;
}

[[nodiscard]] auto opened_store() -> db::PersistentStoreOpenResult
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    return opened;
}

// Stores `count` scheduled rows for `user` named `<prefix>-<n>` and finalises each as cancelled at `100 + n`.
auto fill_finalised(db::PersistentStore& store, std::string_view prefix, std::string_view user, std::size_t count)
    -> void
{
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        auto const id = std::string{prefix} + "-" + std::to_string(index);
        REQUIRE(db::store_delayed_event(store, row(id, user)));
        REQUIRE(db::cancel_delayed_event(store, id, 100U + index, 1000U));
    }
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

using RawRow = std::array<std::string, db::delayed_event_row_columns>;

// The 16 columns of a valid scheduled row, as the text the store writes, for a test to change one of.
[[nodiscard]] auto raw_row(std::string delay_id) -> RawRow
{
    return {std::move(delay_id),
            std::string{alice},
            "DEVICE",
            "!room:example.org",
            "m.room.message",
            "false",
            "",
            "{}",
            "",
            "false",
            "60000",
            "1000",
            "scheduled",
            "0",
            "",
            ""};
}

// Writes `values` to the store's database as one row of `delayed_events`, without touching memory (a bound-parameter
// insert, so any text goes in), the way a damaged or foreign file would hold it.
[[nodiscard]] auto insert_raw_row(db::PersistentStore& store, RawRow const& values) -> bool
{
    auto statement = db::PreparedStatement{
        "insert_raw_delayed_event",
        "INSERT INTO delayed_events (delay_id, user_id, device_id, room_id, event_type, is_state, state_key, "
        "content_json, txn_id, via_appservice, delay_ms, delayed_since_ms, status, finalised_at_ms, event_id, "
        "error_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
        {}};
    for (auto const& value : values)
    {
        statement.parameters.push_back(db::BoundValue{value, false});
    }
    return db::commit_persistent_transaction(store, {statement});
}

struct RawRowCase final
{
    std::string_view name{};
    std::size_t column{0U};
    std::string_view value{};
};

} // namespace

SCENARIO("The delayed-event delay maximum is one number in the config and the database module",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("the config module's longest delay and the store's")
    {
        THEN("they are equal, or a configured delay could be accepted by the config and refused by the store")
        {
            REQUIRE(merovingian::config::max_delayed_event_delay_ms == db::max_delayed_event_delay_ms);
        }
    }
}

// `store_delayed_event` is the one place a new row enters the table, and it judges the row before it builds a statement
// (ADR-0824). This scenario proves what it refuses and what it accepts: every length cap is tested at the cap and one
// byte over, a refusal writes nothing, and a repeated delay ID or transaction is refused without a write. The caps are
// cases of one table, not scenarios, because each case is the same call on a fresh store and only the changed field
// differs. The per-user cap on scheduled rows is not enforced here on purpose, and the last WHEN pins that.
SCENARIO("A delayed event is stored once, within its caps, and refused outside them",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("a memory store")
    {
        auto opened = opened_store();
        auto& store = opened.store;

        WHEN("rows at each cap and one over each cap are offered")
        {
            struct Case final
            {
                std::string label;
                std::function<void(PersistentDelayedEvent&)> change;
                bool stored;
            };
            // Each limit is a pair, the largest accepted value and one over it, so a comparison written as < instead of
            // <= moves the boundary by one and fails a case. The lambda changes one field of an otherwise valid row, so
            // a refusal can only be that field's.
            auto const cases = std::vector<Case>{
                {"baseline",
                 [](PersistentDelayedEvent&) {
                 }, true },
                {"empty delay id",
                 [](PersistentDelayedEvent& r) {
                     r.delay_id.clear();
                 }, false},
                {"empty user",
                 [](PersistentDelayedEvent& r) {
                     r.user_id.clear();
                 }, false},
                {"empty room",
                 [](PersistentDelayedEvent& r) {
                     r.room_id.clear();
                 }, false},
                {"empty event type",
                 [](PersistentDelayedEvent& r) {
                     r.event_type.clear();
                 }, false},
                {"empty content",
                 [](PersistentDelayedEvent& r) {
                     r.content_json.clear();
                 }, false},
                {"delay id at cap",
                 [](PersistentDelayedEvent& r) {
                     r.delay_id = std::string(db::max_delayed_event_id_bytes, 'd');
                 }, true },
                {"delay id over cap",
                 [](PersistentDelayedEvent& r) {
                     r.delay_id = std::string(db::max_delayed_event_id_bytes + 1U, 'd');
                 }, false},
                {"content at cap",
                 [](PersistentDelayedEvent& r) {
                     r.content_json = std::string(db::max_delayed_event_content_bytes, 'c');
                 }, true },
                {"content over cap",
                 [](PersistentDelayedEvent& r) {
                     r.content_json = std::string(db::max_delayed_event_content_bytes + 1U, 'c');
                 }, false},
                {"event type at cap",
                 [](PersistentDelayedEvent& r) {
                     r.event_type = std::string(db::max_delayed_event_field_bytes, 't');
                 }, true },
                {"event type over cap",
                 [](PersistentDelayedEvent& r) {
                     r.event_type = std::string(db::max_delayed_event_field_bytes + 1U, 't');
                 }, false},
                {"state key at cap",
                 [](PersistentDelayedEvent& r) {
                     r.state_key = std::string(db::max_delayed_event_field_bytes, 's');
                 }, true },
                {"state key over cap",
                 [](PersistentDelayedEvent& r) {
                     r.state_key = std::string(db::max_delayed_event_field_bytes + 1U, 's');
                 }, false},
                {"txn id at cap",
                 [](PersistentDelayedEvent& r) {
                     r.txn_id = std::string(db::max_delayed_event_field_bytes, 'x');
                 }, true },
                {"txn id over cap",
                 [](PersistentDelayedEvent& r) {
                     r.txn_id = std::string(db::max_delayed_event_field_bytes + 1U, 'x');
                 }, false},
                {"device id at cap",
                 [](PersistentDelayedEvent& r) {
                     r.device_id = std::string(db::max_delayed_event_field_bytes, 'v');
                 }, true },
                // A NUL byte in any text column is refused, because PostgreSQL TEXT cannot hold one and the table's
                // transaction key joins its parts with one. Every column gets its own case so that a check missing from
                // one column is a failure.
                {"delay id with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.delay_id += std::string{'\0'} + "x";
                 }, false},
                {"user id with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.user_id += std::string{'\0'} + "x";
                 }, false},
                {"device id with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.device_id += std::string{'\0'} + "x";
                 }, false},
                {"room id with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.room_id += std::string{'\0'} + "x";
                 }, false},
                {"event type with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.event_type += std::string{'\0'} + "x";
                 }, false},
                {"state key with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.state_key += std::string{'\0'} + "x";
                 }, false},
                {"txn id with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.txn_id += std::string{'\0'} + "x";
                 }, false},
                {"content json with a NUL byte",
                 [](PersistentDelayedEvent& r) {
                     r.content_json += std::string{'\0'} + "x";
                 }, false},
                {"device id over cap",
                 [](PersistentDelayedEvent& r) {
                     r.device_id = std::string(db::max_delayed_event_field_bytes + 1U, 'v');
                 }, false},
                {"user id at cap",
                 [](PersistentDelayedEvent& r) {
                     r.user_id = std::string(db::max_delayed_event_field_bytes, 'u');
                 }, true },
                {"user id over cap",
                 [](PersistentDelayedEvent& r) {
                     r.user_id = std::string(db::max_delayed_event_field_bytes + 1U, 'u');
                 }, false},
                {"room id at cap",
                 [](PersistentDelayedEvent& r) {
                     r.room_id = std::string(db::max_delayed_event_field_bytes, 'r');
                 }, true },
                {"room id over cap",
                 [](PersistentDelayedEvent& r) {
                     r.room_id = std::string(db::max_delayed_event_field_bytes + 1U, 'r');
                 }, false},
                {"delay of one millisecond",
                 [](PersistentDelayedEvent& r) {
                     r.delay_ms = 1U;
                 }, true },
                // A delay of 0 is refused. Read back as a scheduled row it would be due at once, which is sending early
                // (ADR-0824). The largest delay is the 31 day maximum that the config module must agree with (the first
                // scenario of this file).
                {"delay of zero",
                 [](PersistentDelayedEvent& r) {
                     r.delay_ms = 0U;
                 }, false},
                {"largest delay",
                 [](PersistentDelayedEvent& r) {
                     r.delay_ms = db::max_delayed_event_delay_ms;
                 }, true },
                {"delay over the largest",
                 [](PersistentDelayedEvent& r) {
                     r.delay_ms = db::max_delayed_event_delay_ms + 1U;
                 }, false},
                // A new row is always scheduled with no outcome. A row reaches sent, cancelled or failed only by
                // finalising a scheduled one, so a row that already claims an outcome, a finalised time, an event ID or
                // an error is refused.
                {"status sent",
                 [](PersistentDelayedEvent& r) {
                     r.status = DelayedEventStatus::sent;
                 }, false},
                {"status cancelled",
                 [](PersistentDelayedEvent& r) {
                     r.status = DelayedEventStatus::cancelled;
                 }, false},
                {"status failed",
                 [](PersistentDelayedEvent& r) {
                     r.status = DelayedEventStatus::failed;
                 }, false},
                {"a finalised time",
                 [](PersistentDelayedEvent& r) {
                     r.finalised_at_ms = 5U;
                 }, false},
                {"an event id",
                 [](PersistentDelayedEvent& r) {
                     r.event_id = "$e";
                 }, false},
                {"an error",
                 [](PersistentDelayedEvent& r) {
                     r.error_json = "{}";
                 }, false},
            };
            // The outcomes and the transaction counts are collected first and judged in the THEN, so the loop only acts
            // and the THEN holds every assertion about it.
            auto outcomes = std::vector<std::pair<std::string, bool>>{};
            auto transactions_by_refusal = std::vector<std::uint64_t>{};
            for (auto const& each : cases)
            {
                auto candidate = row("d-case");
                each.change(candidate);
                // A refused row must leave the database untouched, so the transaction count is read before the call and
                // the difference is recorded for every refused case.
                // A fresh store per case: the baseline's ID would otherwise collide with the next case.
                auto fresh = opened_store();
                auto const before = db::committed_transaction_count(fresh.store);
                auto const stored = db::store_delayed_event(fresh.store, std::move(candidate));
                outcomes.emplace_back(each.label, stored);
                if (!each.stored)
                {
                    transactions_by_refusal.push_back(db::committed_transaction_count(fresh.store) - before);
                }
                REQUIRE(fresh.store.delayed_events.size() == (stored ? 1U : 0U));
            }

            THEN("every case is stored or refused as listed, and a refusal writes nothing")
            {
                for (auto index = std::size_t{0U}; index < cases.size(); ++index)
                {
                    INFO("case " << cases[index].label);
                    REQUIRE(outcomes[index].second == cases[index].stored);
                }
                REQUIRE(std::ranges::all_of(transactions_by_refusal, [](std::uint64_t count) {
                    return count == 0U;
                }));
            }
        }

        // The delay ID is the primary key and the (user, device, room, type, transaction ID) key is the idempotency
        // key, so a second row for either is refused without a commit. The same transaction ID on another device is a
        // different key. The repeat of `d-1` is by another user, to show that the existing row is not overwritten.
        WHEN("a delay ID is stored twice, and the same transaction is stored under a second delay ID")
        {
            auto first = row("d-1");
            first.txn_id = "txn";
            auto twin = row("d-2");
            twin.txn_id = "txn";
            auto other_device = row("d-3");
            other_device.txn_id = "txn";
            other_device.device_id = "ELSEWHERE";
            auto const stored = db::store_delayed_event(store, first);
            auto const before = db::committed_transaction_count(store);
            auto const repeated = db::store_delayed_event(store, row("d-1", bob));
            auto const same_transaction = db::store_delayed_event(store, twin);
            auto const refused_transactions = db::committed_transaction_count(store) - before;
            auto const second_device = db::store_delayed_event(store, other_device);

            THEN("the repeat and the twin are refused without a write; another device's transaction is its own")
            {
                REQUIRE(stored);
                REQUIRE_FALSE(repeated);
                REQUIRE_FALSE(same_transaction);
                REQUIRE(refused_transactions == 0U);
                REQUIRE(second_device);
                REQUIRE(store.delayed_events.find("d-1")->user_id == alice);
                REQUIRE(store.delayed_events.size() == 2U);
            }
        }

        // 150 is above the default cap of 100 per user. The caller needs the count of scheduled rows to compute
        // `Retry-After` (ADR-0826), so the cap is the caller's check and the store accepts all of them.
        WHEN("rows are stored for a user beyond any plausible per-user cap")
        {
            auto all = true;
            for (auto index = 0; index < 150; ++index)
            {
                all = db::store_delayed_event(store, row("d-" + std::to_string(index))) && all;
            }

            THEN("the store does not enforce the per-user cap: that is the caller's check")
            {
                REQUIRE(all);
                REQUIRE(store.delayed_events.scheduled_count(alice) == 150U);
            }
        }
    }
}

SCENARIO("A delayed event is written with bound parameters only", "[database][delayed-events][delayed-event-store]")
{
    GIVEN("a memory store capturing statements")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        db::enable_statement_capture(store, 16U);

        WHEN("a state event is stored and later restarted and cancelled")
        {
            auto stored_row = row("d-1");
            stored_row.is_state = true;
            stored_row.state_key = "@alice:example.org";
            stored_row.txn_id = "txn-9";
            stored_row.via_appservice = true;
            REQUIRE(db::store_delayed_event(store, stored_row));
            REQUIRE(db::restart_delayed_event(store, "d-1", 7000U));
            REQUIRE(db::cancel_delayed_event(store, "d-1", 8000U, 10U));
            auto const& captured = store.captured_statements;

            THEN("every statement uses $n placeholders, none carries a value, and the boolean columns hold text")
            {
                REQUIRE(captured.size() == 4U);
                for (auto const& statement : captured)
                {
                    INFO("statement " << statement.name);
                    REQUIRE(statement.sql.find('$') != std::string::npos);
                    REQUIRE(statement.sql.find("SECRET-CONTENT-MARKER") == std::string::npos);
                    REQUIRE(statement.sql.find("d-1") == std::string::npos);
                    REQUIRE(statement.sql.find(std::string{alice}) == std::string::npos);
                }
                auto const& insert = captured[0];
                REQUIRE(insert.name == "insert_delayed_event");
                REQUIRE(insert.parameters.size() == 16U);
                REQUIRE(insert.sql.find("$16") != std::string::npos);
                REQUIRE(insert.parameters[0].value == "d-1");
                REQUIRE(insert.parameters[5].value == "true");
                REQUIRE(insert.parameters[7].value == std::string{secret_content});
                REQUIRE(insert.parameters[9].value == "true");
                REQUIRE(insert.parameters[10].value == "60000");
                REQUIRE(insert.parameters[12].value == "scheduled");
                REQUIRE(captured[1].sql == "UPDATE delayed_events SET delayed_since_ms = $1 WHERE delay_id = $2");
                REQUIRE(captured[1].parameters[0].value == "7000");
                REQUIRE(captured[2].parameters[0].value == "cancelled");
                REQUIRE(captured[2].parameters[1].value == "8000");
            }
        }
    }
}

SCENARIO("A failed commit leaves the delayed-events mirror unchanged",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("a memory store holding a scheduled row and a finalised one")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_delayed_event(store, row("d-live")));
        REQUIRE(db::store_delayed_event(store, row("d-done")));
        REQUIRE(db::cancel_delayed_event(store, "d-done", 500U, 100U));

        WHEN("the commit fails for a store, a restart, a cancel, a user delete and a prune")
        {
            db::force_next_persist_failures(store, 1U);
            auto const stored = db::store_delayed_event(store, row("d-new"));
            db::force_next_persist_failures(store, 1U);
            auto const restarted = db::restart_delayed_event(store, "d-live", 9000U);
            db::force_next_persist_failures(store, 1U);
            auto const cancelled = db::cancel_delayed_event(store, "d-live", 9000U, 100U);
            db::force_next_persist_failures(store, 1U);
            auto const deleted = db::delete_delayed_events_of_user(store, alice);
            db::force_next_persist_failures(store, 1U);
            auto const pruned = db::prune_finalised_delayed_events(store, 100'000U, 10U);

            THEN("each reports the failure and memory is exactly as it was")
            {
                REQUIRE_FALSE(stored);
                REQUIRE_FALSE(restarted);
                REQUIRE_FALSE(cancelled);
                REQUIRE_FALSE(deleted);
                REQUIRE_FALSE(pruned.has_value());
                REQUIRE(store.delayed_events.size() == 2U);
                REQUIRE(store.delayed_events.find("d-new") == nullptr);
                REQUIRE(store.delayed_events.find("d-live")->delayed_since_ms == 1000U);
                REQUIRE(store.delayed_events.find("d-live")->status == DelayedEventStatus::scheduled);
                REQUIRE(store.delayed_events.find("d-done") != nullptr);
                REQUIRE(store.delayed_events.earliest_due() == store.delayed_events.find("d-live"));
            }
        }

        WHEN("each of those writes is repeated with the database working")
        {
            auto const restarted = db::restart_delayed_event(store, "d-live", 9000U);
            auto const absent = db::restart_delayed_event(store, "d-nope", 9000U);
            auto const finalised = db::restart_delayed_event(store, "d-done", 9000U);
            auto const cancelled_again = db::cancel_delayed_event(store, "d-done", 9000U, 100U);

            THEN("a restart moves the start, and a row that is absent or finalised is refused")
            {
                REQUIRE(restarted);
                REQUIRE_FALSE(absent);
                REQUIRE_FALSE(finalised);
                REQUIRE_FALSE(cancelled_again);
                REQUIRE(store.delayed_events.find("d-live")->delayed_since_ms == 9000U);
            }
        }

        WHEN("the row is being sent")
        {
            REQUIRE(store.delayed_events.mark_being_sent("d-live"));
            auto const restarted = db::restart_delayed_event(store, "d-live", 9000U);
            auto const cancelled = db::cancel_delayed_event(store, "d-live", 9000U, 100U);

            THEN("neither a restart nor a cancel acts on it")
            {
                REQUIRE_FALSE(restarted);
                REQUIRE_FALSE(cancelled);
                REQUIRE(store.delayed_events.find("d-live")->status == DelayedEventStatus::scheduled);
            }
        }
    }
}

// `record_delayed_event_outcome` finalises a row after the send was attempted (ADR-0825). It is the one store function
// whose memory changes even when its commit fails, because the event is already sent and a row left scheduled would be
// sent again on every run of the job. The first WHEN proves that exception and the second proves that an outcome of the
// wrong shape is refused and writes nothing. They share one GIVEN because both start from scheduled rows that the job
// has marked as being sent.
SCENARIO("The outcome of a send is recorded, and a failed commit still finalises memory",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("a memory store holding two scheduled rows, both marked as being sent")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        REQUIRE(db::store_delayed_event(store, row("d-ok")));
        REQUIRE(db::store_delayed_event(store, row("d-bad")));
        REQUIRE(db::store_delayed_event(store, row("d-lost")));
        REQUIRE(store.delayed_events.mark_being_sent("d-ok"));
        REQUIRE(store.delayed_events.mark_being_sent("d-bad"));
        REQUIRE(store.delayed_events.mark_being_sent("d-lost"));

        // `force_next_persist_failures` makes the next commit fail with no write. The transaction count after equals
        // the count before, which shows the database changed nothing while memory still finalised the row.
        WHEN("a success, a failure and a success whose commit fails are recorded")
        {
            auto const sent =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 5000U, "$event", {}, 10U);
            auto const failed = db::record_delayed_event_outcome(store, "d-bad", DelayedEventStatus::failed, 5001U, {},
                                                                 R"({"errcode":"M_FORBIDDEN","error":"no"})", 10U);
            auto const before = db::committed_transaction_count(store);
            db::force_next_persist_failures(store, 1U);
            auto const lost =
                db::record_delayed_event_outcome(store, "d-lost", DelayedEventStatus::sent, 5002U, "$lost", {}, 10U);
            auto const after = db::committed_transaction_count(store);

            THEN("the first two are recorded; the third reports the failed commit but memory says sent")
            {
                REQUIRE(sent == DelayedEventOutcomeResult::recorded);
                REQUIRE(failed == DelayedEventOutcomeResult::recorded);
                REQUIRE(lost == DelayedEventOutcomeResult::commit_failed);
                REQUIRE(after == before);
                REQUIRE(store.delayed_events.find("d-ok")->status == DelayedEventStatus::sent);
                REQUIRE(store.delayed_events.find("d-ok")->event_id == "$event");
                REQUIRE(store.delayed_events.find("d-bad")->status == DelayedEventStatus::failed);
                REQUIRE(store.delayed_events.find("d-bad")->error_json == R"({"errcode":"M_FORBIDDEN","error":"no"})");
                REQUIRE(store.delayed_events.find("d-lost")->status == DelayedEventStatus::sent);
                REQUIRE(store.delayed_events.find("d-lost")->finalised_at_ms == 5002U);
                REQUIRE(store.delayed_events.find_sent_by_event_id("$lost") == store.delayed_events.find("d-lost"));
                REQUIRE(store.delayed_events.scheduled_count(alice) == 0U);
                REQUIRE(store.delayed_events.earliest_due() == nullptr);
                REQUIRE_FALSE(store.delayed_events.is_being_sent("d-lost"));
            }
        }

        // A sent outcome needs an event ID and no error, a failed outcome needs an error and no event ID, and no other
        // status is an outcome, so each wrong shape is a separate call on the same scheduled row. The row is then
        // finalised once, and a second outcome for it is refused, because an outcome is recorded once.
        WHEN("an outcome is recorded with the wrong shape, for an absent row and for a finalised row")
        {
            auto const no_event =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 1U, {}, {}, 10U);
            auto const no_error =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::failed, 1U, {}, {}, 10U);
            auto const both =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 1U, "$e", "{}", 10U);
            auto const cancelled =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::cancelled, 1U, {}, {}, 10U);
            auto const scheduled =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::scheduled, 1U, "$e", {}, 10U);
            auto const long_error =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::failed, 1U, {},
                                                 std::string(db::max_delayed_event_error_bytes + 1U, 'e'), 10U);
            auto const long_event =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 1U,
                                                 std::string(db::max_delayed_event_field_bytes + 1U, 'e'), {}, 10U);
            auto const absent =
                db::record_delayed_event_outcome(store, "d-nope", DelayedEventStatus::sent, 1U, "$e", {}, 10U);
            REQUIRE(db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 1U, "$e", {}, 10U) ==
                    DelayedEventOutcomeResult::recorded);
            auto const twice =
                db::record_delayed_event_outcome(store, "d-ok", DelayedEventStatus::sent, 2U, "$f", {}, 10U);
            // The error exactly at its cap (1,024 bytes) is the one accepted case, against `long_error` one byte over.
            auto const at_cap =
                db::record_delayed_event_outcome(store, "d-bad", DelayedEventStatus::failed, 1U, {},
                                                 std::string(db::max_delayed_event_error_bytes, 'e'), 10U);

            THEN("every one is refused and writes nothing, except the error exactly at its cap")
            {
                REQUIRE(no_event == DelayedEventOutcomeResult::refused);
                REQUIRE(no_error == DelayedEventOutcomeResult::refused);
                REQUIRE(both == DelayedEventOutcomeResult::refused);
                REQUIRE(cancelled == DelayedEventOutcomeResult::refused);
                REQUIRE(scheduled == DelayedEventOutcomeResult::refused);
                REQUIRE(long_error == DelayedEventOutcomeResult::refused);
                REQUIRE(long_event == DelayedEventOutcomeResult::refused);
                REQUIRE(absent == DelayedEventOutcomeResult::refused);
                REQUIRE(twice == DelayedEventOutcomeResult::refused);
                REQUIRE(at_cap == DelayedEventOutcomeResult::recorded);
                REQUIRE(store.delayed_events.find("d-ok")->event_id == "$e");
            }
        }
    }
}

// A finalised row is kept for the spec's idempotent answers, bounded per user by `max_finalised_per_user` (ADR-0824).
// The row being finalised is still scheduled when the bound is judged, so a user at the bound loses the oldest
// finalised row to make room for it. The eviction must be in the same transaction as the status update, so a crash
// cannot leave the user over the bound or a row finalised without its eviction. The captured statements and the
// transaction counts prove that. The GIVENs differ in size: a small one for the exact arithmetic and one with 300 rows
// for the batching of the DELETE.
SCENARIO("Finalising keeps at most the bound of a user's finalised rows, evicting the oldest in the same transaction",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("a user holding three finalised rows and two scheduled ones, another user holding one finalised row")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        fill_finalised(store, "old", alice, 3U);
        fill_finalised(store, "bob", bob, 1U);
        REQUIRE(db::store_delayed_event(store, row("live-1")));
        REQUIRE(db::store_delayed_event(store, row("live-2")));
        db::enable_statement_capture(store, 16U);

        // Three finalised rows and a bound of 3: finalising a fourth evicts exactly the oldest (`old-0`, finalised
        // first), so the user ends at 3. The other user's row proves the eviction is per user.
        WHEN("a row is cancelled with a bound of 3")
        {
            auto const before = db::committed_transaction_count(store);
            REQUIRE(db::cancel_delayed_event(store, "live-1", 900U, 3U));
            auto const transactions = db::committed_transaction_count(store) - before;

            THEN(
                "the oldest row goes in the same transaction, the finalised row stays, and the other user is untouched")
            {
                REQUIRE(transactions == 1U);
                REQUIRE(store.captured_statements.size() == 3U);
                REQUIRE(store.captured_statements[0].name == "finalise_delayed_event");
                REQUIRE(store.captured_statements[1].name == "delete_delayed_event_sticky_duration");
                REQUIRE(store.captured_statements[2].name == "delete_delayed_events");
                REQUIRE(store.captured_statements[2].parameters.size() == 1U);
                REQUIRE(store.captured_statements[2].parameters[0].value == "old-0");
                REQUIRE(store.delayed_events.finalised_count(alice) == 3U);
                REQUIRE(store.delayed_events.find("old-0") == nullptr);
                REQUIRE(store.delayed_events.find("old-1") != nullptr);
                REQUIRE(store.delayed_events.find("live-1")->status == DelayedEventStatus::cancelled);
                REQUIRE(store.delayed_events.finalised_count(bob) == 1U);
            }
        }

        WHEN("a row is recorded as sent with a bound of 1")
        {
            auto const before = db::committed_transaction_count(store);
            auto const result =
                db::record_delayed_event_outcome(store, "live-2", DelayedEventStatus::sent, 901U, "$e", {}, 1U);
            auto const transactions = db::committed_transaction_count(store) - before;

            THEN("only the row just finalised remains for that user, all in one transaction")
            {
                REQUIRE(result == DelayedEventOutcomeResult::recorded);
                REQUIRE(transactions == 1U);
                REQUIRE(store.delayed_events.finalised_count(alice) == 1U);
                REQUIRE(store.delayed_events.find("live-2")->status == DelayedEventStatus::sent);
                REQUIRE(store.delayed_events.find("old-0") == nullptr);
                REQUIRE(store.delayed_events.find("old-1") == nullptr);
                REQUIRE(store.delayed_events.find("old-2") == nullptr);
            }
        }

        WHEN("a row is cancelled with a bound well above what the user holds")
        {
            auto const before = db::committed_transaction_count(store);
            REQUIRE(db::cancel_delayed_event(store, "live-1", 900U, 100U));

            THEN("nothing is evicted and the transaction holds the update and its sticky-duration delete")
            {
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.captured_statements.size() == 2U);
                REQUIRE(store.delayed_events.finalised_count(alice) == 4U);
            }
        }

        // The mirror changes only after the commit (ADR-0824), so a failed commit must leave both the status and the
        // rows that would have been evicted as they were.
        WHEN("the evicting commit fails")
        {
            db::force_next_persist_failures(store, 1U);
            auto const cancelled = db::cancel_delayed_event(store, "live-1", 900U, 1U);

            THEN("neither the status nor the evictions reach memory")
            {
                REQUIRE_FALSE(cancelled);
                REQUIRE(store.delayed_events.finalised_count(alice) == 3U);
                REQUIRE(store.delayed_events.find("live-1")->status == DelayedEventStatus::scheduled);
            }
        }
    }

    GIVEN("a user holding 300 finalised rows")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        fill_finalised(store, "many", alice, 300U);
        REQUIRE(db::store_delayed_event(store, row("live")));
        db::enable_statement_capture(store, 16U);

        // 300 held, 1 more, bound 100: 201 rows go and 99 old ones stay. A DELETE names at most 128 delay IDs, so 201
        // rows are two DELETE statements, and with the UPDATE and the delete of the sticky-duration side row that is four
        // statements in one transaction.
        WHEN("one more row is cancelled with a bound of 100")
        {
            auto const before = db::committed_transaction_count(store);
            REQUIRE(db::cancel_delayed_event(store, "live", 5000U, 100U));

            THEN("201 rows are deleted in batches within one transaction, leaving the newest 99 and the new row")
            {
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.captured_statements.size() == 4U);
                REQUIRE(store.delayed_events.finalised_count(alice) == 100U);
                REQUIRE(store.delayed_events.find("many-200") == nullptr);
                REQUIRE(store.delayed_events.find("many-201") != nullptr);
                REQUIRE(store.delayed_events.find("live")->status == DelayedEventStatus::cancelled);
            }
        }
    }
}

// Deactivation deletes every row of the user, scheduled and finalised, in one statement (ADR-0824). The second call is
// for a user with no rows, which still runs its DELETE, because a row that hydration skipped is in the database and not
// in memory (the next scenario).
SCENARIO("All of a user's delayed events are deleted in one statement",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("two users with scheduled and finalised rows")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        fill_finalised(store, "a-done", alice, 2U);
        REQUIRE(db::store_delayed_event(store, row("a-live")));
        REQUIRE(db::store_delayed_event(store, row("b-live", bob)));
        db::enable_statement_capture(store, 16U);

        WHEN("the first user's rows are deleted, and then those of a user with none")
        {
            auto const before = db::committed_transaction_count(store);
            auto const deleted = db::delete_delayed_events_of_user(store, alice);
            auto const transactions = db::committed_transaction_count(store) - before;
            auto const none = db::delete_delayed_events_of_user(store, "@nobody:example.org");

            THEN("one DELETE by user removes them all, the other user keeps theirs, and one for none is still made")
            {
                REQUIRE(deleted);
                REQUIRE(transactions == 1U);
                // The sticky-duration side rows go first, in the same transaction (ADR-0854).
                REQUIRE(store.captured_statements[0].sql ==
                        "DELETE FROM delayed_event_sticky_durations WHERE delay_id IN (SELECT delay_id FROM "
                        "delayed_events WHERE user_id = $1)");
                REQUIRE(store.captured_statements[0].parameters[0].value == std::string{alice});
                REQUIRE(store.captured_statements[1].sql == "DELETE FROM delayed_events WHERE user_id = $1");
                REQUIRE(store.captured_statements[1].parameters[0].value == std::string{alice});
                REQUIRE(none);
                REQUIRE(db::committed_transaction_count(store) - before == 2U);
                REQUIRE(store.captured_statements.size() == 4U);
                REQUIRE(store.captured_statements[3].parameters[0].value == "@nobody:example.org");
                REQUIRE(store.delayed_events.size() == 1U);
                REQUIRE(store.delayed_events.find("b-live") != nullptr);
            }
        }
    }
}

// A row the loader skipped is in the file and not in memory. If deletion asked memory first it would find nothing and
// skip the DELETE, and the row would outlive its account (ADR-0824). The row is written with raw SQL on purpose,
// because the store functions would also put it in memory.
SCENARIO("Deactivation deletes a delayed event that exists only in the database",
         "[database][delayed-events][delayed-event-store][sqlite]")
{
    GIVEN("a SQLite store with a row in the file that memory does not hold, for a user with no row in memory")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-delayed-events-only-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        auto opened = db::open_sqlite_persistent_store(path.string());
        REQUIRE(opened.ok);
        REQUIRE(insert_raw_row(opened.store, raw_row("only-in-file")));
        REQUIRE(opened.store.delayed_events.size() == 0U);
        REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "1");

        WHEN("the user's delayed events are deleted")
        {
            auto const deleted = db::delete_delayed_events_of_user(opened.store, alice);

            THEN("the row is gone from the file")
            {
                REQUIRE(deleted);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "0");
            }
        }
        opened = {};
        std::filesystem::remove(path);
    }
}

// The delayed-events job prunes finalised rows past the age bound, a bounded batch per run, oldest first (ADR-0824).
// This scenario proves the cutoff is exclusive, the batch limit is honoured, a scheduled row is never pruned, and a
// prune of nothing writes nothing. The rows are finalised at 100 to 109 so the cutoffs name exact rows.
SCENARIO("Pruning by age deletes the oldest finalised rows below the cutoff, up to the row limit",
         "[database][delayed-events][delayed-event-store]")
{
    GIVEN("finalised rows at 100 to 109, a scheduled row and a finalised row of another user at 50")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        fill_finalised(store, "r", alice, 10U);
        fill_finalised(store, "early", bob, 1U);
        // `early-0` was already cancelled by `fill_finalised`, so a second cancel is refused. It is finalised at 100,
        // the same time as `r-0`, so a prune must treat equal times alike and take both in delay ID order.
        REQUIRE(db::cancel_delayed_event(store, "early-0", 1U, 100U) == false);
        REQUIRE(db::store_delayed_event(store, row("live")));
        db::enable_statement_capture(store, 16U);

        // Six rows are below 105 (`r-0` to `r-4` and `early-0`), and a limit of 3 takes the three oldest of them.
        WHEN("rows below 105 are pruned with a limit of 3")
        {
            auto const before = db::committed_transaction_count(store);
            auto const pruned = db::prune_finalised_delayed_events(store, 105U, 3U);

            THEN("the three oldest go in one transaction and everything else stays")
            {
                REQUIRE(pruned == std::optional<std::size_t>{3U});
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.delayed_events.find("r-0") == nullptr);
                REQUIRE(store.delayed_events.find("r-1") == nullptr);
                REQUIRE(store.delayed_events.find("r-2") != nullptr);
                REQUIRE(store.delayed_events.find("live") != nullptr);
            }
        }

        WHEN("rows below 105 are pruned with a limit larger than the number due")
        {
            auto const pruned = db::prune_finalised_delayed_events(store, 105U, 500U);
            auto const rest = db::prune_finalised_delayed_events(store, 105U, 500U);

            THEN("exactly the rows below the cutoff go, the cutoff row stays, and a second prune finds none")
            {
                REQUIRE(pruned == std::optional<std::size_t>{6U});
                REQUIRE(rest == std::optional<std::size_t>{0U});
                REQUIRE(store.delayed_events.find("r-4") == nullptr);
                REQUIRE(store.delayed_events.find("r-5") != nullptr);
                REQUIRE(store.delayed_events.find("early-0") == nullptr);
            }
        }

        // Both calls find nothing. The cutoff is exclusive, so a cutoff equal to the oldest finalised time deletes
        // nothing, and neither call may open a transaction.
        WHEN("the limit is zero, or the cutoff is at the oldest row")
        {
            auto const before = db::committed_transaction_count(store);
            auto const zero = db::prune_finalised_delayed_events(store, 1'000'000U, 0U);
            auto const nothing = db::prune_finalised_delayed_events(store, 100U, 10U);

            THEN("nothing is deleted and nothing is written")
            {
                REQUIRE(zero == std::optional<std::size_t>{0U});
                REQUIRE(nothing == std::optional<std::size_t>{0U});
                REQUIRE(db::committed_transaction_count(store) == before);
                REQUIRE(store.delayed_events.size() == 12U);
            }
        }
    }

    // 300 rows exceed the 128 IDs one DELETE may name, so the batching is exercised: 128, 128 and 44.
    GIVEN("300 finalised rows")
    {
        auto opened = opened_store();
        auto& store = opened.store;
        fill_finalised(store, "bulk", alice, 300U);
        db::enable_statement_capture(store, 16U);

        WHEN("they are all pruned")
        {
            auto const before = db::committed_transaction_count(store);
            auto const pruned = db::prune_finalised_delayed_events(store, 1'000'000U, 500U);

            THEN("the DELETEs are batched in one transaction")
            {
                REQUIRE(pruned == std::optional<std::size_t>{300U});
                REQUIRE(db::committed_transaction_count(store) - before == 1U);
                REQUIRE(store.captured_statements.size() == 3U);
                REQUIRE(store.delayed_events.size() == 0U);
            }
        }
    }
}

// A delayed event must survive a restart, because a lost call leave leaves a vanished participant listed in the call
// (ADR-0824). This scenario writes rows of every status through the store functions into a file, opens the file again
// and compares every column and every index, so a column the writer or the loader forgets is a failure. The later WHENs
// prove the loader skips a row it cannot read exactly and that deletions reached the file, not just memory.
SCENARIO("Delayed events survive a reopen of a SQLite store with every column and index",
         "[database][delayed-events][delayed-event-store][sqlite]")
{
    GIVEN("a SQLite store holding a scheduled state event, a sent row, a cancelled row and a failed row")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-delayed-events-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        auto first = PersistentDelayedEvent{};
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            first = row("d-state");
            first.is_state = true;
            first.state_key = "@alice:example.org";
            first.device_id = "";
            first.via_appservice = true;
            first.txn_id = "";
            // The largest delay, an empty device ID, a state key and the appservice flag are set so that this row
            // exercises the columns a plain message leaves at their defaults.
            first.delay_ms = db::max_delayed_event_delay_ms;
            first.delayed_since_ms = 123'456'789U;
            auto message = row("d-message");
            message.txn_id = "txn-1";
            // Content with an escaped newline, escaped quotes and a non-ASCII letter proves the text comes back byte
            // for byte through the column.
            message.content_json = R"({"body":"line\nbreak \"quoted\" é"})";
            REQUIRE(db::store_delayed_event(opened.store, first));
            REQUIRE(db::store_delayed_event(opened.store, message));
            REQUIRE(db::store_delayed_event(opened.store, row("d-sent")));
            REQUIRE(db::store_delayed_event(opened.store, row("d-cancelled")));
            REQUIRE(db::store_delayed_event(opened.store, row("d-failed", bob)));
            REQUIRE(db::record_delayed_event_outcome(opened.store, "d-sent", DelayedEventStatus::sent, 2000U,
                                                     "$sent:example.org", {},
                                                     10U) == DelayedEventOutcomeResult::recorded);
            REQUIRE(db::cancel_delayed_event(opened.store, "d-cancelled", 2001U, 10U));
            REQUIRE(db::record_delayed_event_outcome(opened.store, "d-failed", DelayedEventStatus::failed, 2002U, {},
                                                     R"({"errcode":"M_FORBIDDEN","error":"nope"})",
                                                     10U) == DelayedEventOutcomeResult::recorded);
        }

        WHEN("the store is opened again")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(reopened.ok);
            auto const& table = reopened.store.delayed_events;

            THEN("every row is back with every column, and every index answers")
            {
                REQUIRE(table.size() == 5U);
                auto const* state = table.find("d-state");
                REQUIRE(state != nullptr);
                REQUIRE(state->user_id == alice);
                REQUIRE(state->device_id.empty());
                REQUIRE(state->room_id == "!room:example.org");
                REQUIRE(state->event_type == "m.room.message");
                REQUIRE(state->is_state);
                REQUIRE(state->state_key == "@alice:example.org");
                REQUIRE(state->content_json == std::string{secret_content});
                REQUIRE(state->txn_id.empty());
                REQUIRE(state->via_appservice);
                REQUIRE(state->delay_ms == db::max_delayed_event_delay_ms);
                REQUIRE(state->delayed_since_ms == 123'456'789U);
                REQUIRE(state->status == DelayedEventStatus::scheduled);
                REQUIRE(state->finalised_at_ms == 0U);
                REQUIRE(table.find("d-message")->content_json == R"({"body":"line\nbreak \"quoted\" é"})");
                REQUIRE_FALSE(table.find("d-message")->is_state);
                REQUIRE_FALSE(table.find("d-message")->via_appservice);
                REQUIRE(table.find("d-sent")->status == DelayedEventStatus::sent);
                REQUIRE(table.find("d-sent")->event_id == "$sent:example.org");
                REQUIRE(table.find("d-sent")->finalised_at_ms == 2000U);
                REQUIRE(table.find("d-cancelled")->status == DelayedEventStatus::cancelled);
                REQUIRE(table.find("d-failed")->status == DelayedEventStatus::failed);
                REQUIRE(table.find("d-failed")->error_json == R"({"errcode":"M_FORBIDDEN","error":"nope"})");
                REQUIRE(table.find_owned(bob, "d-failed") != nullptr);
                REQUIRE(table.find_owned(alice, "d-failed") == nullptr);
                REQUIRE(table.scheduled_count(alice) == 2U);
                REQUIRE(table.finalised_count(alice) == 2U);
                REQUIRE(table.finalised_count(bob) == 1U);
                // `d-message` is due at 61,000. `d-state` is due much later because its delay is the maximum, so the
                // due order index must rebuild with `d-message` first.
                REQUIRE(table.earliest_due() == table.find("d-message"));
                REQUIRE(table.earliest_due_ms_of_user(alice) == std::optional<std::uint64_t>{61'000U});
                REQUIRE(table.find_by_transaction(alice, "DEVICE", "!room:example.org", "m.room.message", "txn-1") ==
                        table.find("d-message"));
                REQUIRE(table.find_sent_by_event_id("$sent:example.org") == table.find("d-sent"));
                REQUIRE(table.finalised_before(2002U, 10U).size() == 2U);
            }
        }

        // 'done' is not a status the store writes. The loader skips the row and never repairs it (ADR-0824), and the
        // file still holds it afterwards, since a repair would be a guess.
        WHEN("the file holds a row whose status text is not one of the four, and the store is opened")
        {
            {
                auto* raw = static_cast<sqlite3*>(nullptr);
                REQUIRE(sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
                auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
                REQUIRE(sqlite3_exec(connection.get(),
                                     "UPDATE delayed_events SET status = 'done' WHERE delay_id = 'd-sent'", nullptr,
                                     nullptr, nullptr) == SQLITE_OK);
            }
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("that row is not loaded, never repaired, and the others are")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.delayed_events.size() == 4U);
                REQUIRE(reopened.store.delayed_events.find("d-sent") == nullptr);
                REQUIRE(reopened.store.delayed_events.find("d-state") != nullptr);
                REQUIRE(sqlite_first_text(path, "SELECT status FROM delayed_events WHERE delay_id = 'd-sent'") ==
                        "done");
            }
        }

        // A prune below 2001 takes `d-sent` (finalised at 2000) and not `d-cancelled` (2001), and the user deletion
        // takes `d-failed`. Reopening shows that the file, and not only memory, lost them.
        WHEN("the rows are deleted by user and by prune and the store is opened again")
        {
            {
                auto opened = db::open_sqlite_persistent_store(path.string());
                REQUIRE(opened.ok);
                REQUIRE(db::delete_delayed_events_of_user(opened.store, bob));
                REQUIRE(db::prune_finalised_delayed_events(opened.store, 2001U, 10U) == std::optional<std::size_t>{1U});
            }
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the file agrees with memory")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.delayed_events.size() == 3U);
                REQUIRE(reopened.store.delayed_events.find("d-failed") == nullptr);
                REQUIRE(reopened.store.delayed_events.find("d-sent") == nullptr);
                REQUIRE(reopened.store.delayed_events.find("d-cancelled") != nullptr);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "3");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Hydration reads a delayed event row strictly and counts the rows it skips",
         "[database][delayed-events][delayed-event-store][sqlite]")
{
    GIVEN("a SQLite file holding a valid scheduled row, a sent row and one row that is not read exactly")
    {
        auto const bad = GENERATE(RawRowCase{"a delay_ms that is not a number", 10U, "abc"},
                                  RawRowCase{"an empty delay_ms", 10U, ""},
                                  RawRowCase{"a negative delay_ms", 10U, "-5"}, RawRowCase{"a delay_ms of 0", 10U, "0"},
                                  RawRowCase{"a delay_ms over the maximum", 10U, "2678400001"},
                                  RawRowCase{"a delay_ms of 21 digits", 10U, "123456789012345678901"},
                                  RawRowCase{"a delayed_since_ms that is not a number", 11U, "abc"},
                                  RawRowCase{"a boolean column holding yes", 5U, "yes"},
                                  RawRowCase{"a finalised row with no finalised time", 13U, "0"});
        INFO(bad.name);
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-delayed-events-strict-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_delayed_event(opened.store, row("m-good")));
            REQUIRE(db::store_delayed_event(opened.store, row("a-sent")));
            REQUIRE(db::record_delayed_event_outcome(opened.store, "a-sent", DelayedEventStatus::sent, 2000U,
                                                     "$sent:example.org", {},
                                                     10U) == DelayedEventOutcomeResult::recorded);
            auto damaged = raw_row("z-bad");
            damaged[bad.column] = std::string{bad.value};
            if (bad.column == 13U)
            {
                damaged[12] = "cancelled";
            }
            REQUIRE(insert_raw_row(opened.store, damaged));
        }

        WHEN("the store is opened")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the row is not loaded, stays in the file and is counted, and the valid rows load")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.delayed_events.size() == 2U);
                REQUIRE(reopened.store.delayed_events.find("z-bad") == nullptr);
                REQUIRE(reopened.store.delayed_events.find("m-good") != nullptr);
                REQUIRE(reopened.store.delayed_events.find("a-sent") != nullptr);
                REQUIRE(reopened.store.delayed_event_rows_skipped_at_load == 1U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events WHERE delay_id = 'z-bad'") == "1");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("Hydration skips a second sent row that claims an event ID another row holds",
         "[database][delayed-events][delayed-event-store][sqlite]")
{
    GIVEN("a SQLite file holding a sent row and a second sent row with the same event ID")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-delayed-events-dup-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_delayed_event(opened.store, row("a-sent")));
            REQUIRE(db::record_delayed_event_outcome(opened.store, "a-sent", DelayedEventStatus::sent, 2000U,
                                                     "$sent:example.org", {},
                                                     10U) == DelayedEventOutcomeResult::recorded);
            auto duplicate = raw_row("z-sent");
            duplicate[12] = "sent";
            duplicate[13] = "2001";
            duplicate[14] = "$sent:example.org";
            REQUIRE(insert_raw_row(opened.store, duplicate));
        }

        WHEN("the store is opened")
        {
            auto reopened = db::open_sqlite_persistent_store(path.string());

            THEN("the first row keeps the event ID, the second is skipped and counted, and stays in the file")
            {
                REQUIRE(reopened.ok);
                REQUIRE(reopened.store.delayed_events.size() == 1U);
                REQUIRE(reopened.store.delayed_events.find_sent_by_event_id("$sent:example.org") ==
                        reopened.store.delayed_events.find("a-sent"));
                REQUIRE(reopened.store.delayed_event_rows_skipped_at_load == 1U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "2");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A store opened with the federation worker profile does not load delayed events and leaves them in the file",
         "[database][delayed-events][delayed-event-store][sqlite]")
{
    GIVEN("a SQLite store holding two scheduled events")
    {
        auto const path = merovingian::tests::temporary_directory() /
                          ("merovingian-delayed-events-profile-" +
                           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".sqlite3");
        {
            auto opened = db::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);
            REQUIRE(db::store_delayed_event(opened.store, row("d-one")));
            REQUIRE(db::store_delayed_event(opened.store, row("d-two", bob)));
        }

        WHEN("it is opened with the full profile and with the federation worker profile")
        {
            auto const full = db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::full);
            auto const worker =
                db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::federation_worker);

            THEN("the full profile loads both, the worker profile loads none and counts no skipped row")
            {
                REQUIRE(full.ok);
                REQUIRE(full.store.delayed_events.size() == 2U);
                REQUIRE(worker.ok);
                REQUIRE(worker.store.delayed_events.size() == 0U);
                REQUIRE(worker.store.delayed_event_rows_skipped_at_load == 0U);
            }
        }

        WHEN("it is opened with the worker profile and then with the full profile")
        {
            auto const worker =
                db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::federation_worker);
            auto const again = db::open_sqlite_persistent_store(path.string(), db::TableLoadProfile::full);

            THEN("the rows are still in the file")
            {
                REQUIRE(worker.ok);
                REQUIRE(again.ok);
                REQUIRE(again.store.delayed_events.size() == 2U);
                REQUIRE(sqlite_first_text(path, "SELECT count(*) FROM delayed_events") == "2");
            }
        }
        std::filesystem::remove(path);
    }
}
