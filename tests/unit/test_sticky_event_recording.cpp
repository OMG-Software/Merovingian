// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `record_sticky_event_of_pdu` (MSC4354, ADR-0854, ADR-0857): an accepted PDU that asks to be sticky is recorded with
// the expiry min(received, origin_server_ts) + min(duration, 1 h), read from the PDU as stored; anything it cannot
// read is not sticky and is skipped without a write. The proposal is not in Matrix v1.19, so these are project-level
// checks.
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/StickyEventCaps.hpp"
#include "merovingian/homeserver/StickyEventRecording.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

constexpr auto event_id = std::string_view{"$sticky:example.org"};
constexpr auto room = "!room:example.org";
constexpr auto received_ms = std::int64_t{20'000};
constexpr auto now_ms = std::int64_t{20'000};
constexpr auto caps = db::StickyEventCaps{60U, 1000U};

[[nodiscard]] auto opened_store() -> db::PersistentStoreOpenResult
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    return opened;
}

[[nodiscard]] auto record(db::PersistentStore& store, std::string_view pdu_json, db::StickyEventCaps with = caps)
    -> bool
{
    return hs::record_sticky_event_of_pdu(store, pdu_json, event_id, received_ms, with, now_ms);
}

} // namespace

SCENARIO("a sticky PDU is recorded with its room, sender and capped expiry", "[homeserver][sticky-events]")
{
    GIVEN("a store and sticky PDUs sent before, and after, they were received")
    {
        auto opened = opened_store();
        auto& store = opened.store;

        WHEN("a PDU with origin_server_ts before receipt asks for 5 seconds under the stable name")
        {
            auto const recorded = record(store, R"({"origin_server_ts":19000,"room_id":"!room:example.org",)"
                                                R"("sender":"@alice:example.org","sticky":{"duration_ms":5000},)"
                                                R"("type":"org.matrix.msc4143.rtc.member"})");
            auto const* row = store.sticky_events.find(event_id, now_ms);

            THEN("the row expires five seconds after origin_server_ts and names the PDU's room and sender")
            {
                REQUIRE(recorded);
                REQUIRE(row != nullptr);
                REQUIRE(row->room_id == room);
                REQUIRE(row->sender == "@alice:example.org");
                REQUIRE(row->received_at_ms == received_ms);
                REQUIRE(row->expires_at_ms == 24'000);
            }
        }

        WHEN("a PDU dated in the future asks for two hours under the unstable name")
        {
            auto const recorded = record(store, R"({"msc4354_sticky":{"duration_ms":7200000},)"
                                                R"("origin_server_ts":99000000,"room_id":"!room:example.org",)"
                                                R"("sender":"@alice:example.org","type":"m.room.message"})");
            auto const* row = store.sticky_events.find(event_id, now_ms);

            THEN("the expiry counts from receipt and the duration is capped at one hour")
            {
                REQUIRE(recorded);
                REQUIRE(row != nullptr);
                REQUIRE(row->expires_at_ms == received_ms + 3'600'000);
            }
        }
    }
}

SCENARIO("a PDU that is not sticky, or cannot be read, is skipped without a write", "[homeserver][sticky-events]")
{
    GIVEN("PDUs that are malformed, ordinary, or lack or mistype the fields a row needs")
    {
        auto const pdus = std::vector<std::string>{
            R"({"sticky":)",
            R"([1,2,3])",
            R"({"origin_server_ts":19000,"room_id":"!room:example.org","sender":"@alice:example.org"})",
            R"({"origin_server_ts":19000,"sender":"@alice:example.org","sticky":{"duration_ms":5000}})",
            R"({"origin_server_ts":19000,"room_id":"!room:example.org","sticky":{"duration_ms":5000}})",
            R"({"room_id":"!room:example.org","sender":"@alice:example.org","sticky":{"duration_ms":5000}})",
            R"({"origin_server_ts":19000,"room_id":7,"sender":"@alice:example.org","sticky":{"duration_ms":5000}})",
            R"({"origin_server_ts":19000,"room_id":"!room:example.org","sender":["@alice:example.org"],)"
            R"("sticky":{"duration_ms":5000}})",
            R"({"origin_server_ts":"19000","room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("sticky":{"duration_ms":5000}})",
            R"({"origin_server_ts":1.5,"room_id":"!room:example.org","sender":"@alice:example.org",)"
            R"("sticky":{"duration_ms":5000}})",
        };

        WHEN("each is recorded into its own store")
        {
            auto results = std::vector<bool>{};
            auto sizes = std::vector<std::size_t>{};
            for (auto const& pdu : pdus)
            {
                auto opened = opened_store();
                results.push_back(record(opened.store, pdu));
                sizes.push_back(opened.store.sticky_events.size());
            }

            THEN("each reports success with nothing to record and holds no row")
            {
                for (auto index = std::size_t{0U}; index < pdus.size(); ++index)
                {
                    INFO(pdus[index]);
                    REQUIRE(results[index]);
                    REQUIRE(sizes[index] == 0U);
                }
            }
        }
    }
}

SCENARIO("a sticky PDU the store refuses reports failure", "[homeserver][sticky-events][security]")
{
    GIVEN("a well-formed sticky PDU and a per-sender cap of 0")
    {
        auto opened = opened_store();
        auto const pdu = std::string{R"({"origin_server_ts":19000,"room_id":"!room:example.org",)"
                                     R"("sender":"@alice:example.org","sticky":{"duration_ms":5000}})"};

        WHEN("it is recorded")
        {
            auto const recorded = record(opened.store, pdu, {0U, 1000U});

            THEN("the result is false and no row is held")
            {
                REQUIRE_FALSE(recorded);
                REQUIRE(opened.store.sticky_events.size() == 0U);
            }
        }
    }

    GIVEN("a sticky PDU whose expiry has already passed when it is recorded")
    {
        auto opened = opened_store();
        auto const pdu = std::string{R"({"origin_server_ts":1000,"room_id":"!room:example.org",)"
                                     R"("sender":"@alice:example.org","sticky":{"duration_ms":5000}})"};

        WHEN("it is recorded")
        {
            auto const recorded = record(opened.store, pdu);

            THEN("there is nothing to record: the result is true and no row is held")
            {
                REQUIRE(recorded);
                REQUIRE(opened.store.sticky_events.size() == 0U);
            }
        }
    }
}
