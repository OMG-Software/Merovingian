// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_transaction.hpp"

#include <catch2/catch_test_macros.hpp>

SCENARIO("Outbound transaction creation captures destination and method", "[federation][outbound]")
{
    GIVEN("a destination server name and request parameters")
    {
        WHEN("an outbound transaction is created")
        {
            auto const txn = merovingian::federation::make_outbound_transaction("remote.example.org", "PUT",
                                                                                "/_matrix/federation/v1/send/txn123",
                                                                                "origin.example.org", R"({"pdus":[]})");

            THEN("the transaction fields are populated correctly")
            {
                REQUIRE(txn.destination == "remote.example.org");
                REQUIRE(txn.method == "PUT");
                REQUIRE(txn.target == "/_matrix/federation/v1/send/txn123");
                REQUIRE(txn.origin == "origin.example.org");
                REQUIRE(txn.body == R"({"pdus":[]})");
                REQUIRE(txn.retry_count == 0U);
            }
        }
    }
}

SCENARIO("Backoff computation increases exponentially with a cap", "[federation][outbound][backoff]")
{
    GIVEN("consecutive failure counts")
    {
        WHEN("backoff is computed for zero retries")
        {
            auto const backoff = merovingian::federation::compute_backoff(0U);

            THEN("the initial backoff is the base interval")
            {
                REQUIRE(backoff == 2000U);
            }
        }

        WHEN("backoff is computed for one retry")
        {
            auto const backoff = merovingian::federation::compute_backoff(1U);

            THEN("the backoff doubles")
            {
                REQUIRE(backoff == 4000U);
            }
        }

        WHEN("backoff is computed for many retries")
        {
            auto const backoff = merovingian::federation::compute_backoff(10U);

            THEN("the backoff is capped at the maximum")
            {
                REQUIRE(backoff == 300000U);
            }
        }
    }
}

SCENARIO("Destination retry policy respects circuit breaker and backoff", "[federation][outbound][backoff]")
{
    GIVEN("a destination with consecutive failures below the circuit breaker threshold")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 1U;
        destination.retry_after_ts = 5000U;

        WHEN("the current time is before the retry-after timestamp")
        {
            THEN("the destination should not be retried")
            {
                REQUIRE_FALSE(merovingian::federation::destination_should_retry(destination, 4000U));
            }
        }

        WHEN("the current time is after the retry-after timestamp")
        {
            THEN("the destination should be retried")
            {
                REQUIRE(merovingian::federation::destination_should_retry(destination, 6000U));
            }
        }
    }

    GIVEN("a destination with consecutive failures exceeding the circuit breaker threshold")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 3U;
        destination.retry_after_ts = 50000U;

        WHEN("the current time is before the backoff expiry")
        {
            THEN("circuit breaker prevents retry")
            {
                REQUIRE_FALSE(merovingian::federation::destination_should_retry(destination, 10000U));
            }
        }

        WHEN("the current time is after the backoff expiry")
        {
            THEN("circuit breaker allows retry")
            {
                REQUIRE(merovingian::federation::destination_should_retry(destination, 60000U));
            }
        }
    }

    GIVEN("a healthy destination with no failures")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 0U;
        destination.retry_after_ts = 0U;

        THEN("the destination should always be retried")
        {
            REQUIRE(merovingian::federation::destination_should_retry(destination, 0U));
            REQUIRE(merovingian::federation::destination_should_retry(destination, 1000000U));
        }
    }
}