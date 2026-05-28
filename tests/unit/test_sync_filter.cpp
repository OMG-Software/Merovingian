// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX SYNC FILTER CONFORMANCE TESTS                       |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18, Sec. 8.4.2 Filtering                 |
// |  URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering       |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  filtering specification. If a test fails:                               |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/sync/sync_filter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// --- filter parsing -----------------------------------------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 8.4.2 Filtering
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// A client may pass an inline JSON filter object as the `filter` query
// parameter on /sync. The server MUST parse it and apply each sub-filter
// (room.timeline, room.rooms, presence, account_data) independently.
// A non-JSON value is treated as a stored filter ID and MUST be tolerated
// (falling back to default/unfiltered behaviour when the ID is unknown).
SCENARIO("Sync filter parser accepts JSON filters and tolerates filter ids", "[sync][filter]")
{
    GIVEN("an inline JSON filter selecting specific room types and senders")
    {
        auto const json = std::string{
            R"({"room":{"timeline":{"types":["m.room.message"],"not_senders":["@bot:example.org"],"limit":3},)"
            R"("rooms":["!keep:example.org"],"include_leave":true},)"
            R"("presence":{"senders":["@alice:example.org"]},)"
            R"("account_data":{"types":["m.tag"]}})"};

        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument(json);

            THEN("each nested structure is populated and present is true")
            {
                // Spec MUST: all filter sub-objects must be parsed correctly.
                // Do NOT remove or weaken these - an incorrectly parsed filter
                // leaks events the client explicitly asked to suppress.
                REQUIRE(filter.present);
                REQUIRE(filter.room.timeline.types == std::vector<std::string>{"m.room.message"});
                REQUIRE(filter.room.timeline.not_senders == std::vector<std::string>{"@bot:example.org"});
                REQUIRE(filter.room.timeline.limit == 3U);
                REQUIRE(filter.room.rooms == std::vector<std::string>{"!keep:example.org"});
                REQUIRE(filter.room.include_leave);
                REQUIRE(filter.presence.senders == std::vector<std::string>{"@alice:example.org"});
                REQUIRE(filter.account_data.types == std::vector<std::string>{"m.tag"});
            }
        }
    }

    GIVEN("a non-JSON filter argument (presumably a filter id)")
    {
        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument("0");

            THEN("the result is non-present so the handler falls back to defaults")
            {
                // Spec: stored filter IDs are valid; when the ID is not resolved
                // the server MUST fall back to unfiltered behaviour rather than
                // returning an error.
                REQUIRE_FALSE(filter.present);
                REQUIRE(filter.room.rooms.empty());
                REQUIRE(filter.room.timeline.types.empty());
            }
        }
    }

    GIVEN("an empty filter argument")
    {
        WHEN("the filter is parsed")
        {
            auto const filter = merovingian::sync::parse_filter_argument("");

            THEN("the result is non-present")
            {
                REQUIRE_FALSE(filter.present);
            }
        }
    }
}

// --- event filtering ----------------------------------------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 8.4.2 EventFilter
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "types"     - include only events whose type matches (MUST be respected).
// "not_senders" - exclude events from these senders (MUST be respected).
// An empty filter MUST pass all events. Both conditions are AND-combined.
SCENARIO("Event passes filter respects include and exclude lists for types and senders", "[sync][filter]")
{
    GIVEN("a filter with types=[m.room.message] and not_senders=[@bot:example.org]")
    {
        auto filter = merovingian::sync::EventTypeFilter{};
        filter.types = {"m.room.message"};
        filter.not_senders = {"@bot:example.org"};

        WHEN("events with different types and senders are checked")
        {
            auto const allowed = merovingian::sync::event_passes_filter(filter, "m.room.message", "@alice:example.org");
            auto const wrong_type =
                merovingian::sync::event_passes_filter(filter, "m.room.member", "@alice:example.org");
            auto const blocked_sender =
                merovingian::sync::event_passes_filter(filter, "m.room.message", "@bot:example.org");
            auto const empty_filter_match =
                merovingian::sync::event_passes_filter(merovingian::sync::EventTypeFilter{}, "anything", "anyone");

            THEN("only events matching both the type and sender rules are kept")
            {
                // Spec MUST: matching type + allowed sender passes.
                REQUIRE(allowed);
                // Spec MUST: non-matching type is excluded even with an allowed sender.
                // Do NOT change to REQUIRE - type filtering is a client privacy control.
                REQUIRE_FALSE(wrong_type);
                // Spec MUST: not_senders exclusion applies even when the type matches.
                // Do NOT change to REQUIRE - sender filtering is a client privacy control.
                REQUIRE_FALSE(blocked_sender);
                // Spec: empty filter passes all events.
                REQUIRE(empty_filter_match);
            }
        }
    }
}

// --- room filtering -----------------------------------------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 8.4.2 RoomFilter
// URL:  https://spec.matrix.org/v1.18/client-server-api/#filtering
//
// "rooms"     - include only these room IDs (MUST be respected when non-empty).
// "not_rooms" - exclude these room IDs (MUST be respected when non-empty).
// Exclusion takes precedence over inclusion.
SCENARIO("Room passes filter honours include and exclude room lists", "[sync][filter][room]")
{
    GIVEN("a room filter with rooms=[!keep] and not_rooms=[!drop]")
    {
        auto filter = merovingian::sync::RoomFilter{};
        filter.rooms = {"!keep:example.org"};
        filter.not_rooms = {"!drop:example.org"};

        WHEN("rooms are checked")
        {
            auto const kept = merovingian::sync::room_passes_filter(filter, "!keep:example.org");
            auto const not_included = merovingian::sync::room_passes_filter(filter, "!other:example.org");
            auto const dropped = merovingian::sync::room_passes_filter(filter, "!drop:example.org");

            THEN("only rooms in the include list and absent from the exclude list pass")
            {
                // Spec MUST: room in the include list passes.
                REQUIRE(kept);
                // Spec MUST: room absent from the include list is excluded.
                // Do NOT change - rooms filter is a client privacy/bandwidth control.
                REQUIRE_FALSE(not_included);
                // Spec MUST: room in the not_rooms list is excluded.
                REQUIRE_FALSE(dropped);
            }
        }
    }
}
