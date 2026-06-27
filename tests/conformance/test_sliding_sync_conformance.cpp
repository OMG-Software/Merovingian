// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MSC4186 SIMPLIFIED SLIDING SYNC CONFORMANCE TESTS               |
// |                                                                         |
// |  Spec: MSC4186 Simplified Sliding Sync (proposal, not in v1.18 stable)  |
// |  URL:  https://github.com/matrix-org/matrix-spec-proposals/blob/main/   |
// |          proposals/4186-simplified-sliding-sync.md                       |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the MSC4186 proposal.   |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the proposal.                |
// |    -> Do NOT weaken, comment out, or remove assertions.                 |
// |    -> Do NOT change expected values without citing the proposal.        |
// |                                                                         |
// |  Served at: POST /_matrix/client/unstable/org.matrix.msc4186/sync      |
// |  Advertised via: unstable_features["org.matrix.msc4186"] = true        |
// |                  unstable_features["org.matrix.simplified_msc3575"]    |
// |                  = true for matrix-rust-sdk compatibility              |
// +-------------------------------------------------------------------------+

#include "merovingian/sync/sliding_sync.hpp"
#include "merovingian/sync/sliding_sync_parser.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

// Spec: MSC4186 §3 — The `lists` property
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// Each list MUST have at least one range. Ranges MUST NOT overlap.
// A range is a pair [start, end] where start MUST be <= end.
SCENARIO("MSC4186 list ranges MUST be non-overlapping and start <= end", "[sync][sliding-sync][conformance]")
{
    GIVEN("a list with a valid single range [0, 19]")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(R"({"lists":{"x":{"ranges":[[0,19]]}}})");

            THEN("the request is accepted")
            {
                // Spec MUST: non-overlapping ranges with start <= end are valid.
                REQUIRE(result.has_value());
            }
        }
    }

    GIVEN("a list with overlapping ranges [0,10] and [5,20]")
    {
        WHEN("the request is parsed")
        {
            auto const result =
                merovingian::sync::parse_sliding_sync_request(R"({"lists":{"x":{"ranges":[[0,10],[5,20]]}}})");

            THEN("the request is rejected")
            {
                // Spec MUST: overlapping ranges are invalid per MSC4186 §3.
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("a range where start exceeds end [10, 5]")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(R"({"lists":{"x":{"ranges":[[10,5]]}}})");

            THEN("the request is rejected")
            {
                // Spec MUST: start MUST be <= end.
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("two adjacent non-overlapping ranges [0,9] and [10,19]")
    {
        WHEN("the request is parsed")
        {
            auto const result =
                merovingian::sync::parse_sliding_sync_request(R"({"lists":{"x":{"ranges":[[0,9],[10,19]]}}})");

            THEN("the request is accepted")
            {
                // Spec MUST: adjacent ranges are valid as long as they do not share an index.
                REQUIRE(result.has_value());
                REQUIRE(result->lists.at("x").ranges.size() == 2U);
            }
        }
    }
}

// Spec: MSC4186 §4 — required_state wildcards
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// required_state entries are [type, state_key] pairs. Both type and state_key
// MAY be "*" as a wildcard to match all values.
SCENARIO("MSC4186 required_state MUST accept wildcard entries", "[sync][sliding-sync][conformance]")
{
    GIVEN("a list with a global wildcard required_state [\"*\",\"*\"]")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(
                R"({"lists":{"x":{"ranges":[[0,9]],"required_state":[["*","*"]]}}})");

            THEN("the wildcard pair is accepted")
            {
                // Spec MUST: "*" wildcard is valid in both positions.
                REQUIRE(result.has_value());
                auto const& rs = result->lists.at("x").required_state;
                REQUIRE(rs.size() == 1U);
                REQUIRE(rs[0].first == "*");
                REQUIRE(rs[0].second == "*");
            }
        }
    }

    GIVEN("a list with a type wildcard [\"*\",\"\"]")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(
                R"({"lists":{"x":{"ranges":[[0,9]],"required_state":[["*",""]]}}})");

            THEN("the wildcard type pair is accepted")
            {
                // Spec MUST: "*" wildcard in type position is valid.
                REQUIRE(result.has_value());
            }
        }
    }
}

// Spec: MSC4186 §5 — extensions
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// The `extensions` property is optional. Each extension has an `enabled` field.
// Disabled extensions (enabled: false or absent) MUST NOT appear in the response.
SCENARIO("MSC4186 extension requests parse the enabled field", "[sync][sliding-sync][conformance]")
{
    GIVEN("a request with to_device extension enabled and e2ee extension disabled")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(
                R"({"extensions":{"to_device":{"enabled":true},"e2ee":{"enabled":false}}})");

            THEN("to_device is enabled and e2ee is disabled")
            {
                // Spec MUST: the enabled flag controls whether the extension is active.
                REQUIRE(result.has_value());
                auto const& ext = result->extensions;
                REQUIRE(ext.has_value());
                REQUIRE(ext->to_device.has_value());
                REQUIRE(ext->to_device->enabled); // Spec MUST: enabled = true → active
                REQUIRE(ext->e2ee.has_value());
                REQUIRE_FALSE(ext->e2ee->enabled); // Spec MUST: enabled = false → inactive
            }
        }
    }
}

// Spec: MSC4186 §2 — the pos parameter
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// On the first request there is no pos. On subsequent requests the client
// MUST send the pos from the last response. The server MUST include pos in
// every response.
SCENARIO("MSC4186 pos token encodes and decodes round-trip", "[sync][sliding-sync][conformance]")
{
    GIVEN("a pos value included in a target URL")
    {
        auto const token = merovingian::sync::StreamToken{100U, 100U, 50U};
        auto const encoded = merovingian::sync::encode_stream_token(token);
        auto const target = "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + encoded;

        WHEN("the pos is parsed from the URL")
        {
            auto const result = merovingian::sync::parse_sliding_sync_pos(target);

            THEN("it decodes to the original token")
            {
                // Spec MUST: pos MUST be opaque and round-trip via query parameter.
                REQUIRE(result.has_value());
                REQUIRE(result->event_ordering == 100U);
                REQUIRE(result->sync_stream_id == 50U);
            }
        }
    }

    GIVEN("a first request with no pos")
    {
        WHEN("the URL is parsed")
        {
            auto const result =
                merovingian::sync::parse_sliding_sync_pos("/_matrix/client/unstable/org.matrix.msc4186/sync");

            THEN("no pos is returned, indicating an initial sync")
            {
                // Spec MUST: absence of pos means initial sync; the server starts fresh.
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

// Spec: MSC4186 §2 — timeout parameter
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// The timeout query parameter is in milliseconds. A missing timeout means
// respond immediately. A timeout of 0 also means respond immediately.
SCENARIO("MSC4186 timeout parameter is parsed in milliseconds", "[sync][sliding-sync][conformance]")
{
    GIVEN("a URL with timeout=30000")
    {
        WHEN("the timeout is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_timeout(
                "/_matrix/client/unstable/org.matrix.msc4186/sync?timeout=30000");

            THEN("the value 30000 ms is returned")
            {
                // Spec MUST: timeout is expressed in milliseconds.
                REQUIRE(result.has_value());
                REQUIRE(*result == 30000U);
            }
        }
    }

    GIVEN("a URL with no timeout")
    {
        WHEN("the timeout is parsed")
        {
            auto const result =
                merovingian::sync::parse_sliding_sync_timeout("/_matrix/client/unstable/org.matrix.msc4186/sync");

            THEN("nullopt is returned, meaning respond immediately")
            {
                // Spec MUST: absent timeout = respond immediately.
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

// Spec: MSC4186 §2 — compatibility alias URL format
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// The server MUST also serve the endpoint at the org.matrix.simplified_msc3575
// path for matrix-rust-sdk compatibility. The pos and timeout query parameters
// MUST be parsed identically from this path.
SCENARIO("MSC4186 pos token is parsed identically from the simplified_msc3575 URL", "[sync][sliding-sync][conformance]")
{
    GIVEN("a pos value appended to the simplified_msc3575 target URL")
    {
        auto const token = merovingian::sync::StreamToken{200U, 200U, 75U};
        auto const encoded = merovingian::sync::encode_stream_token(token);
        auto const target = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos=" + encoded;

        WHEN("the pos is parsed from the URL")
        {
            auto const result = merovingian::sync::parse_sliding_sync_pos(target);

            THEN("it decodes to the original token — path prefix is irrelevant to pos parsing")
            {
                // Spec MUST: pos is an opaque query-parameter; its value is path-independent.
                REQUIRE(result.has_value());
                REQUIRE(result->event_ordering == 200U);
                REQUIRE(result->sync_stream_id == 75U);
            }
        }
    }

    GIVEN("a simplified_msc3575 URL with no pos")
    {
        WHEN("the URL is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_pos(
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync");

            THEN("no pos is returned, indicating an initial sync")
            {
                // Spec MUST: absence of pos means initial sync regardless of which path is used.
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

// Spec: MSC4186 §2 — compatibility alias URL format (timeout)
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// timeout MUST be parsed from the simplified_msc3575 path identically to the msc4186 path.
SCENARIO("MSC4186 timeout is parsed identically from the simplified_msc3575 URL", "[sync][sliding-sync][conformance]")
{
    GIVEN("a simplified_msc3575 URL with timeout=0")
    {
        WHEN("the timeout is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_timeout(
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?timeout=0");

            THEN("zero is returned — respond immediately")
            {
                // Spec MUST: timeout=0 means respond immediately; value is path-independent.
                REQUIRE(result.has_value());
                REQUIRE(*result == 0U);
            }
        }
    }

    GIVEN("a simplified_msc3575 URL with timeout=30000")
    {
        WHEN("the timeout is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_timeout(
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?timeout=30000");

            THEN("30000 ms is returned")
            {
                // Spec MUST: timeout in milliseconds; value is path-independent.
                REQUIRE(result.has_value());
                REQUIRE(*result == 30000U);
            }
        }
    }
}

// Spec: MSC4186 §3 — sort order
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// The sort field is an ordered array of sort keys. The server MUST apply them
// left-to-right as a stable sort (ties broken by the next key).
SCENARIO("MSC4186 list sort keys are parsed in order", "[sync][sliding-sync][conformance]")
{
    GIVEN("a list with sort keys [by_recency, by_notification_count]")
    {
        WHEN("the request is parsed")
        {
            auto const result = merovingian::sync::parse_sliding_sync_request(
                R"({"lists":{"x":{"ranges":[[0,9]],"sort":["by_recency","by_notification_count"]}}})");

            THEN("sort keys are preserved in the specified order")
            {
                // Spec MUST: sort keys applied left-to-right; order is significant.
                REQUIRE(result.has_value());
                auto const& sort = result->lists.at("x").sort;
                REQUIRE(sort.size() == 2U);
                REQUIRE(sort[0] == "by_recency");
                REQUIRE(sort[1] == "by_notification_count");
            }
        }
    }
}
