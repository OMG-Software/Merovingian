// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_parser.hpp"

#include <catch2/catch_test_macros.hpp>

namespace
{

using namespace merovingian::sync;

} // namespace

// ── parse_sliding_sync_request ────────────────────────────────────────────────

SCENARIO("Sliding sync parser accepts an empty body as a valid empty request", "[sync][sliding-sync]")
{
    GIVEN("an empty request body")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request({});

            THEN("the result is a valid empty request")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->lists.empty());
                REQUIRE(result->room_subscriptions.empty());
                REQUIRE_FALSE(result->extensions.has_value());
                REQUIRE_FALSE(result->conn_id.has_value());
            }
        }
    }
}

SCENARIO("Sliding sync parser rejects invalid JSON bodies", "[sync][sliding-sync]")
{
    GIVEN("a body that is not a JSON object")
    {
        WHEN("an array is parsed")
        {
            auto const result = parse_sliding_sync_request("[1,2,3]");
            THEN("the result is nullopt") { REQUIRE_FALSE(result.has_value()); }
        }

        WHEN("a plain string is parsed")
        {
            auto const result = parse_sliding_sync_request("\"hello\"");
            THEN("the result is nullopt") { REQUIRE_FALSE(result.has_value()); }
        }

        WHEN("truncated JSON is parsed")
        {
            auto const result = parse_sliding_sync_request("{\"lists\":");
            THEN("the result is nullopt") { REQUIRE_FALSE(result.has_value()); }
        }
    }
}

SCENARIO("Sliding sync parser extracts conn_id from the request body", "[sync][sliding-sync]")
{
    GIVEN("a body with a conn_id field")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request(R"({"conn_id":"main"})");

            THEN("the conn_id is extracted")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->conn_id.has_value());
                REQUIRE(*result->conn_id == "main");
            }
        }
    }
}

SCENARIO("Sliding sync parser extracts named lists with ranges", "[sync][sliding-sync]")
{
    GIVEN("a body with one list containing a single range")
    {
        auto const body = R"({
            "lists": {
                "slide": {
                    "ranges": [[0, 19]],
                    "timeline_limit": 10
                }
            }
        })";

        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request(body);

            THEN("the list is present with the expected range")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->lists.size() == 1U);
                auto const it = result->lists.find("slide");
                REQUIRE(it != result->lists.end());
                REQUIRE(it->second.ranges.size() == 1U);
                REQUIRE(it->second.ranges[0].start == 0U);
                REQUIRE(it->second.ranges[0].end   == 19U);
                REQUIRE(it->second.timeline_limit == 10U);
            }
        }
    }
}

SCENARIO("Sliding sync parser rejects lists with overlapping ranges", "[sync][sliding-sync]")
{
    GIVEN("a list whose ranges overlap")
    {
        auto const body = R"({"lists":{"x":{"ranges":[[0,10],[5,20]]}}})";

        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request(body);

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("Sliding sync parser extracts required_state wildcard pairs", "[sync][sliding-sync]")
{
    GIVEN("a list with a wildcard required_state entry")
    {
        auto const body = R"({
            "lists": {
                "x": {
                    "ranges": [[0, 9]],
                    "required_state": [["*", "*"], ["m.room.name", ""]]
                }
            }
        })";

        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request(body);

            THEN("the required_state pairs are extracted")
            {
                REQUIRE(result.has_value());
                auto const it = result->lists.find("x");
                REQUIRE(it != result->lists.end());
                auto const& rs = it->second.required_state;
                REQUIRE(rs.size() == 2U);
                REQUIRE(rs[0].first  == "*");
                REQUIRE(rs[0].second == "*");
                REQUIRE(rs[1].first  == "m.room.name");
                REQUIRE(rs[1].second == "");
            }
        }
    }
}

SCENARIO("Sliding sync parser extracts extension requests", "[sync][sliding-sync]")
{
    GIVEN("a body with all five extensions enabled")
    {
        auto const body = R"({
            "extensions": {
                "to_device": {"enabled": true, "limit": 50, "since": "42"},
                "e2ee": {"enabled": true},
                "account_data": {"enabled": true},
                "receipts": {"enabled": true, "rooms": ["!r1:example.com"]},
                "typing": {"enabled": true, "rooms": ["!r2:example.com"]}
            }
        })";

        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_request(body);

            THEN("all extensions are parsed correctly")
            {
                REQUIRE(result.has_value());
                auto const& ext = result->extensions;
                REQUIRE(ext.has_value());
                REQUIRE(ext->to_device.has_value());
                REQUIRE(ext->to_device->enabled);
                REQUIRE(ext->to_device->limit == 50U);
                REQUIRE(ext->to_device->since.has_value());
                REQUIRE(*ext->to_device->since == "42");
                REQUIRE(ext->e2ee.has_value());
                REQUIRE(ext->e2ee->enabled);
                REQUIRE(ext->account_data.has_value());
                REQUIRE(ext->account_data->enabled);
                REQUIRE(ext->receipts.has_value());
                REQUIRE(ext->receipts->enabled);
                REQUIRE(ext->receipts->rooms.size() == 1U);
                REQUIRE(ext->receipts->rooms[0] == "!r1:example.com");
                REQUIRE(ext->typing.has_value());
                REQUIRE(ext->typing->enabled);
                REQUIRE(ext->typing->rooms[0] == "!r2:example.com");
            }
        }
    }
}

// ── sliding_sync_ranges_valid ─────────────────────────────────────────────────

SCENARIO("sliding_sync_ranges_valid accepts well-ordered non-overlapping ranges", "[sync][sliding-sync]")
{
    GIVEN("a single range with start <= end")
    {
        WHEN("validated")
        {
            THEN("it is valid")
            {
                REQUIRE(sliding_sync_ranges_valid({{0U, 19U}}));
                REQUIRE(sliding_sync_ranges_valid({{5U, 5U}}));
            }
        }
    }

    GIVEN("two non-overlapping ranges")
    {
        WHEN("validated")
        {
            THEN("they are valid")
            {
                REQUIRE(sliding_sync_ranges_valid({{0U, 19U}, {20U, 39U}}));
            }
        }
    }

    GIVEN("an empty ranges list")
    {
        WHEN("validated")
        {
            THEN("it is valid")
            {
                REQUIRE(sliding_sync_ranges_valid({}));
            }
        }
    }
}

SCENARIO("sliding_sync_ranges_valid rejects invalid range configurations", "[sync][sliding-sync]")
{
    GIVEN("a range where start exceeds end")
    {
        WHEN("validated")
        {
            THEN("it is rejected")
            {
                REQUIRE_FALSE(sliding_sync_ranges_valid({{10U, 5U}}));
            }
        }
    }

    GIVEN("two ranges whose first ends on the second's start")
    {
        WHEN("validated")
        {
            THEN("they are rejected as overlapping")
            {
                REQUIRE_FALSE(sliding_sync_ranges_valid({{0U, 10U}, {10U, 20U}}));
            }
        }
    }
}

// ── parse_sliding_sync_pos ────────────────────────────────────────────────────

SCENARIO("parse_sliding_sync_pos extracts and decodes the pos query parameter", "[sync][sliding-sync]")
{
    GIVEN("a target with a valid pos parameter")
    {
        auto const token = merovingian::sync::StreamToken{42U, 7U, 3U};
        auto const encoded = merovingian::sync::encode_stream_token(token);
        auto const target = "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + encoded;

        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_pos(target);

            THEN("the token is decoded correctly")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->event_ordering == 42U);
                REQUIRE(result->sync_stream_id == 3U);
            }
        }
    }

    GIVEN("a target with no pos parameter")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_pos("/_matrix/client/unstable/org.matrix.msc4186/sync");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("a target with an invalid pos value")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_pos("/_matrix/.../sync?pos=not-a-token");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

// ── parse_sliding_sync_timeout ────────────────────────────────────────────────

SCENARIO("parse_sliding_sync_timeout extracts the timeout query parameter", "[sync][sliding-sync]")
{
    GIVEN("a target with a valid timeout")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_timeout("/_matrix/.../sync?timeout=30000");

            THEN("the timeout in milliseconds is returned")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == 30000U);
            }
        }
    }

    GIVEN("a target with no timeout parameter")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_timeout("/_matrix/.../sync");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("a target with a non-numeric timeout")
    {
        WHEN("parsed")
        {
            auto const result = parse_sliding_sync_timeout("/_matrix/.../sync?timeout=abc");

            THEN("the result is nullopt")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}
