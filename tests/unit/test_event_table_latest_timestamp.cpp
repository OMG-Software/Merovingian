// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// P11 (ADR-0497): `EventTable::room_latest_origin_server_ts` is the greatest `origin_server_ts` of a room's rows, of
// every status, kept as rows come and go, so a sliding sync room's `timestamp` costs one lookup rather than a parse of
// the room's history.

#include "merovingian/database/event_table.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using merovingian::database::EventTable;
using merovingian::database::PersistentEvent;

namespace
{

constexpr auto room_a = "!a:example.org";
constexpr auto room_b = "!b:example.org";

[[nodiscard]] auto event_at(std::string event_id, std::uint64_t stream_ordering, std::string room_id,
                            std::string timestamp_member, std::string status = "accepted") -> PersistentEvent
{
    auto event =
        PersistentEvent{std::move(event_id),
                        std::move(room_id),
                        "@alice:example.org",
                        R"({"type":"m.room.message","content":{"origin_server_ts":9999999},)" + timestamp_member + "}",
                        stream_ordering,
                        stream_ordering,
                        {},
                        {},
                        {}};
    event.status = std::move(status);
    return event;
}

[[nodiscard]] auto ts(std::int64_t value) -> std::string
{
    return R"("origin_server_ts":)" + std::to_string(value);
}

} // namespace

SCENARIO("A room's newest origin_server_ts follows its rows", "[database][event-table][p11]")
{
    // This scenario exercises the cached per-room maximum origin_server_ts across the full
    // event-row lifecycle: insertion order skew, status variation, and later mutations.
    // The invariant under test is that each room reports exactly the greatest timestamp among
    // its current rows (independent of other rooms), with 0 for rooms with no rows.
    GIVEN("a room whose events were stored with timestamps out of order, one of them rejected")
    {
        // Seed two rooms so we can validate both max-selection and room isolation.
        auto table = EventTable{};
        REQUIRE(table.insert(event_at("$1", 1, room_a, ts(100))));
        REQUIRE(table.insert(event_at("$2", 2, room_a, ts(300))));
        REQUIRE(table.insert(event_at("$3", 3, room_a, ts(200))));
        REQUIRE(table.insert(event_at("$4", 4, room_a, ts(400), "rejected")));
        REQUIRE(table.insert(event_at("$5", 5, room_b, ts(50))));

        THEN("the value is the greatest of the room's rows whatever their status, and not another room's")
        {
            REQUIRE(table.room_latest_origin_server_ts(room_a) == 400);
            REQUIRE(table.room_latest_origin_server_ts(room_b) == 50);
            REQUIRE(table.room_latest_origin_server_ts("!none:example.org") == 0);
        }

        WHEN("an event with a lower timestamp arrives later")
        {
            REQUIRE(table.insert(event_at("$6", 6, room_a, ts(250))));

            THEN("the value is unchanged")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 400);
            }
        }

        WHEN("an event with a higher timestamp arrives")
        {
            REQUIRE(table.insert(event_at("$6", 6, room_a, ts(900))));

            THEN("the value is that timestamp")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 900);
            }
        }

        WHEN("rows with no usable timestamp are stored")
        {
            REQUIRE(table.insert(event_at("$6", 6, room_a, R"("note":1)")));
            REQUIRE(table.insert(event_at("$7", 7, room_a, ts(0))));
            REQUIRE(table.insert(event_at("$8", 8, room_a, ts(-5))));

            THEN("they count as nothing")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 400);
            }
        }

        WHEN("the row holding the greatest timestamp is removed")
        {
            REQUIRE(table.erase_if([](PersistentEvent const& event) {
                return event.event_id == "$4";
            }) == 1U);

            THEN("the value falls to the next greatest")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 300);
            }
        }

        WHEN("every row of the room is removed")
        {
            REQUIRE(table.erase_if([](PersistentEvent const& event) {
                return event.room_id == room_a;
            }) == 4U);

            THEN("the room has none, and the other room is untouched")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 0);
                REQUIRE(table.room_latest_origin_server_ts(room_b) == 50);
            }
        }

        WHEN("the row holding the greatest timestamp is rewritten with a lower one")
        {
            table.modify(table.find("$4"), [](PersistentEvent& event) {
                event.json = R"({"type":"m.room.message","origin_server_ts":10})";
            });

            THEN("the value is recomputed from the rows")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 300);
            }
        }

        WHEN("a row is rewritten with a higher timestamp")
        {
            table.modify(table.find("$1"), [](PersistentEvent& event) {
                event.json = R"({"type":"m.room.message","origin_server_ts":1000})";
            });

            THEN("the value is that timestamp")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 1000);
            }
        }

        WHEN("a row is redacted, which keeps its timestamp")
        {
            table.modify(table.find("$4"), [](PersistentEvent& event) {
                event.json = R"({"type":"m.room.message","origin_server_ts":400,"content":{}})";
            });

            THEN("the value is unchanged")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 400);
            }
        }

        WHEN("a row is moved to the other room")
        {
            table.modify(table.find("$4"), [](PersistentEvent& event) {
                event.room_id = room_b;
            });

            THEN("both rooms follow")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 300);
                REQUIRE(table.room_latest_origin_server_ts(room_b) == 400);
            }
        }

        WHEN("the table is cleared")
        {
            table.clear();

            THEN("there is no value")
            {
                REQUIRE(table.room_latest_origin_server_ts(room_a) == 0);
            }
        }
    }

    // Hydration path: bulk insertion must produce the same per-room maxima as incremental inserts.
    GIVEN("rows added in one batch, as at hydration")
    {
        auto table = EventTable{};
        auto batch = std::vector<PersistentEvent>{};
        batch.push_back(event_at("$1", 1, room_a, ts(70)));
        batch.push_back(event_at("$2", 2, room_a, ts(30)));
        batch.push_back(event_at("$3", 3, room_b, ts(20)));
        REQUIRE(table.insert_all(std::move(batch)) == 3U);

        THEN("each room has its greatest")
        {
            REQUIRE(table.room_latest_origin_server_ts(room_a) == 70);
            REQUIRE(table.room_latest_origin_server_ts(room_b) == 20);
        }
    }
}
