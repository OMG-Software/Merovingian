// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/query_params.hpp"

#include <catch2/catch_test_macros.hpp>

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