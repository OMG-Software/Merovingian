// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/query_params.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Query parameter parser extracts key-value pairs from URL query strings", "[core][http][query]")
{
    GIVEN("a URL with query parameters")
    {
        WHEN("the query string contains since and timeout")
        {
            auto const params =
                merovingian::core::parse_query_params("/_matrix/client/v3/sync?since=s1_2a&timeout=30000");

            THEN("the parameters are extracted correctly")
            {
                REQUIRE(params.since.has_value());
                REQUIRE(params.since.value() == "s1_2a");
                REQUIRE(params.timeout.has_value());
                REQUIRE(params.timeout.value() == 30000U);
                REQUIRE_FALSE(params.full_state.has_value());
                REQUIRE_FALSE(params.filter.has_value());
            }
        }
    }

    GIVEN("a URL with only a path and no query string")
    {
        WHEN("parsed")
        {
            auto const params = merovingian::core::parse_query_params("/_matrix/client/v3/sync");

            THEN("all optional parameters are empty")
            {
                REQUIRE_FALSE(params.since.has_value());
                REQUIRE_FALSE(params.timeout.has_value());
                REQUIRE_FALSE(params.full_state.has_value());
                REQUIRE_FALSE(params.filter.has_value());
            }
        }
    }

    GIVEN("a URL with full_state=true")
    {
        WHEN("parsed")
        {
            auto const params = merovingian::core::parse_query_params("/_matrix/client/v3/sync?full_state=true");

            THEN("full_state is present and true")
            {
                REQUIRE(params.full_state.has_value());
                REQUIRE(params.full_state.value());
            }
        }
    }

    GIVEN("a URL with filter parameter")
    {
        WHEN("parsed")
        {
            auto const params =
                merovingian::core::parse_query_params("/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%7D%7D");

            THEN("filter is extracted")
            {
                REQUIRE(params.filter.has_value());
                REQUIRE(params.filter.value() == "{\"room\":{}}");
            }
        }
    }

    GIVEN("a URL with all sync parameters")
    {
        WHEN("parsed")
        {
            auto const params = merovingian::core::parse_query_params(
                "/_matrix/client/v3/sync?since=1a_0&timeout=10000&full_state=false&filter=myfilter");

            THEN("all parameters are present")
            {
                REQUIRE(params.since.has_value());
                REQUIRE(params.since.value() == "1a_0");
                REQUIRE(params.timeout.has_value());
                REQUIRE(params.timeout.value() == 10000U);
                REQUIRE(params.full_state.has_value());
                REQUIRE_FALSE(params.full_state.value());
                REQUIRE(params.filter.has_value());
                REQUIRE(params.filter.value() == "myfilter");
            }
        }
    }

    GIVEN("a URL with an invalid timeout value")
    {
        WHEN("parsed")
        {
            auto const params = merovingian::core::parse_query_params("/_matrix/client/v3/sync?timeout=notanumber");

            THEN("timeout is absent")
            {
                REQUIRE_FALSE(params.timeout.has_value());
            }
        }
    }

    GIVEN("a URL with repeated parameters")
    {
        WHEN("parsed")
        {
            auto const params =
                merovingian::core::parse_query_params("/_matrix/client/v3/sync?since=first&since=second");

            THEN("the last value wins")
            {
                REQUIRE(params.since.has_value());
                REQUIRE(params.since.value() == "second");
            }
        }
    }
}

SCENARIO("URL percent-decoding handles reserved characters", "[core][http][query]")
{
    GIVEN("a percent-encoded string")
    {
        WHEN("decoded")
        {
            THEN("spaces are decoded from plus signs")
            {
                REQUIRE(merovingian::core::percent_decode("hello+world") == "hello world");
            }

            THEN("hex-encoded characters are decoded")
            {
                REQUIRE(merovingian::core::percent_decode("%7B%22room%22%3A%7B%7D%7D") == "{\"room\":{}}");
            }

            THEN("plain strings pass through")
            {
                REQUIRE(merovingian::core::percent_decode("plain_text-123") == "plain_text-123");
            }

            THEN("mixed encoding is decoded")
            {
                REQUIRE(merovingian::core::percent_decode("name+is+%41lice") == "name is Alice");
            }
        }
    }
}

SCENARIO("URL path component decoding preserves path literal characters", "[core][http][routing]")
{
    GIVEN("a Matrix path segment containing percent-encoded reserved characters")
    {
        WHEN("the segment is decoded as a path component")
        {
            auto const decoded = merovingian::core::percent_decode_path_component("!room2%3Amatrix.example.org+mobile");

            THEN("encoded delimiters are restored and plus remains literal")
            {
                REQUIRE(decoded == "!room2:matrix.example.org+mobile");
            }
        }
    }
}

SCENARIO("URL path component encoding escapes Matrix identifiers for outbound routing", "[core][http][routing]")
{
    GIVEN("a Matrix identifier containing reserved path characters")
    {
        WHEN("the identifier is encoded as a path component")
        {
            auto const encoded =
                merovingian::core::percent_encode_path_component("!room2:matrix.example.org+$event@alice");

            THEN("reserved delimiters are percent-encoded while unreserved bytes pass through")
            {
                REQUIRE(encoded == "%21room2%3Amatrix.example.org%2B%24event%40alice");
            }
        }
    }
}

// Regression for #440: from_hex silently mapped non-hex characters to 0, so
// malformed sequences like "%ZZ" decoded to NUL bytes that propagated into
// filter ids and downstream C-string handling.
SCENARIO("Percent decoding keeps malformed escapes literal instead of injecting NUL", "[core][query][security]")
{
    GIVEN("query values with malformed percent escapes")
    {
        WHEN("the values are decoded")
        {
            auto const bad_hex = merovingian::core::percent_decode("%ZZ");
            auto const half_bad = merovingian::core::percent_decode("%2G");
            auto const valid = merovingian::core::percent_decode("%2F");
            auto const path_bad = merovingian::core::percent_decode_path_component("%ZZtail");

            THEN("malformed escapes pass through literally and contain no NUL bytes")
            {
                REQUIRE(bad_hex == "%ZZ");
                REQUIRE(half_bad == "%2G");
                REQUIRE(bad_hex.find('\0') == std::string::npos);
                REQUIRE(half_bad.find('\0') == std::string::npos);
                REQUIRE(path_bad == "%ZZtail");
            }

            THEN("well-formed escapes still decode")
            {
                REQUIRE(valid == "/");
            }
        }
    }
}

// Regression for #426: the timeout parser accumulated digits with no overflow
// guard, so an overlong decimal wrapped modulo 2^64 into an attacker-chosen
// effective timeout for the sync long-poll pool.
SCENARIO("Sync timeout query parameter rejects overflowing values", "[core][query][security]")
{
    GIVEN("sync targets with overflowing and maximal timeout values")
    {
        auto const overflowing = std::string{"/_matrix/client/v3/sync?timeout=99999999999999999999999999"};
        auto const max_valid = std::string{"/_matrix/client/v3/sync?timeout=18446744073709551615"};

        WHEN("the query parameters are parsed")
        {
            auto const wrapped = merovingian::core::parse_query_params(overflowing);
            auto const maximal = merovingian::core::parse_query_params(max_valid);

            THEN("the overflowing value is discarded rather than wrapped")
            {
                REQUIRE(wrapped.timeout == merovingian::core::SyncRequest{}.timeout);
            }

            THEN("the largest representable value still parses")
            {
                REQUIRE(maximal.timeout == 18446744073709551615ULL);
            }
        }
    }
}
