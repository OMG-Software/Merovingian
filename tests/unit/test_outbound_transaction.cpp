// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

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

namespace
{

[[nodiscard]] auto make_sample_call() -> merovingian::federation::OutboundCall
{
    auto call = merovingian::federation::OutboundCall{};
    call.transaction = merovingian::federation::make_outbound_transaction(
        "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn123", "origin.example.org", R"({"pdus":[]})");
    call.resolved_host = "remote.example.org";
    call.resolved_port = 8448U;
    call.pinned_addresses = {"203.0.113.10"};
    call.key_id = "ed25519:auto";
    call.verify_token = "deterministic-test-token";
    call.origin_server_ts = 1700000000000ULL;
    return call;
}

} // namespace

SCENARIO("Outbound request builder produces a federation HTTPS request shape", "[federation][outbound][builder]")
{
    GIVEN("a federation call composed from a transaction, resolution, and signing identity")
    {
        auto const call = make_sample_call();

        WHEN("the outbound HTTP request is built")
        {
            auto const request = merovingian::federation::build_outbound_request(call);

            THEN("the URL targets the resolved host and port over https")
            {
                REQUIRE(request.url == "https://remote.example.org:8448/_matrix/federation/v1/send/txn123");
            }

            THEN("the method, body, and pinned addresses are carried through")
            {
                REQUIRE(request.method == "PUT");
                REQUIRE(request.body == R"({"pdus":[]})");
                REQUIRE(request.pinned_addresses == std::vector<std::string>{"203.0.113.10"});
            }

            THEN("the request carries an X-Matrix Authorization header and a JSON content type")
            {
                auto found_authorization = false;
                auto found_content_type = false;
                for (auto const& header : request.headers)
                {
                    if (header.name == "Authorization")
                    {
                        REQUIRE(header.value.starts_with("X-Matrix origin=\"origin.example.org\""));
                        REQUIRE(header.value.find("key=\"ed25519:auto\"") != std::string::npos);
                        REQUIRE(header.value.find("sig=\"") != std::string::npos);
                        found_authorization = true;
                    }
                    if (header.name == "Content-Type")
                    {
                        REQUIRE(header.value == "application/json");
                        found_content_type = true;
                    }
                }
                REQUIRE(found_authorization);
                REQUIRE(found_content_type);
            }
        }
    }
}

SCENARIO("Outbound result application updates the federation destination retry state",
         "[federation][outbound][backoff]")
{
    GIVEN("a destination with a prior failure")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 2U;
        destination.retry_after_ts = 1000U;
        destination.state = "backoff";

        WHEN("a successful 2xx result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = true;
            result.http_status = 200U;
            merovingian::federation::apply_outbound_result(destination, result, 5000U);

            THEN("the failure counter resets and last_success_ts is recorded")
            {
                REQUIRE(destination.consecutive_failures == 0U);
                REQUIRE(destination.last_success_ts == 5000U);
                REQUIRE(destination.retry_after_ts == 0U);
                REQUIRE(destination.state == "ok");
            }
        }
    }

    GIVEN("a healthy destination")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 0U;

        WHEN("a transport failure result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = false;
            result.error = "connection_failed";
            merovingian::federation::apply_outbound_result(destination, result, 10000U);

            THEN("the failure counter increments and retry_after_ts moves into the future")
            {
                REQUIRE(destination.consecutive_failures == 1U);
                REQUIRE(destination.retry_after_ts > 10000U);
                REQUIRE(destination.state == "backoff");
            }
        }
    }

    GIVEN("a successful HTTP exchange that returned a non-2xx status")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 1U;

        WHEN("a 500 result is applied")
        {
            auto result = merovingian::federation::OutboundTransactionResult{};
            result.sent = true;
            result.http_status = 500U;
            merovingian::federation::apply_outbound_result(destination, result, 20000U);

            THEN("the destination is still treated as a failure for retry purposes")
            {
                REQUIRE(destination.consecutive_failures == 2U);
                REQUIRE(destination.retry_after_ts > 20000U);
                REQUIRE(destination.state == "backoff");
            }
        }
    }
}

SCENARIO("Outbound request builder brackets IPv6 literals in the URL", "[federation][outbound][builder][ipv6]")
{
    GIVEN("a federation call whose resolved host is an IPv6 literal")
    {
        auto call = make_sample_call();
        call.resolved_host = "2001:db8::1";

        WHEN("the outbound HTTP request is built")
        {
            auto const request = merovingian::federation::build_outbound_request(call);

            THEN("the URL brackets the IPv6 literal so the port separator is unambiguous")
            {
                REQUIRE(request.url == "https://[2001:db8::1]:8448/_matrix/federation/v1/send/txn123");
            }
        }
    }

    GIVEN("a federation call whose resolved host is an IPv4 literal")
    {
        auto call = make_sample_call();
        call.resolved_host = "203.0.113.10";

        WHEN("the outbound HTTP request is built")
        {
            auto const request = merovingian::federation::build_outbound_request(call);

            THEN("the URL does not bracket the IPv4 literal")
            {
                REQUIRE(request.url == "https://203.0.113.10:8448/_matrix/federation/v1/send/txn123");
            }
        }
    }
}

SCENARIO("Outbound transaction respects the circuit breaker without any network attempt",
         "[federation][outbound][circuitbreaker]")
{
    GIVEN("a destination in cooldown and an OutboundClient")
    {
        auto client = merovingian::http::OutboundClient{};
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.consecutive_failures = 5U;
        destination.retry_after_ts = 1000000ULL;
        destination.state = "backoff";

        auto const call = make_sample_call();
        auto const before_failures = destination.consecutive_failures;
        auto const before_retry_after = destination.retry_after_ts;

        WHEN("perform_outbound_transaction is invoked before the cooldown elapses")
        {
            auto const result = merovingian::federation::perform_outbound_transaction(client, call, destination, 1000U);

            THEN("the call returns circuit_open without network I/O and without mutating the destination")
            {
                REQUIRE_FALSE(result.sent);
                REQUIRE(result.error == "circuit_open");
                REQUIRE(result.http_status == 0U);
                REQUIRE(result.response_body.empty());
                REQUIRE(destination.consecutive_failures == before_failures);
                REQUIRE(destination.retry_after_ts == before_retry_after);
                REQUIRE(destination.state == "backoff");
            }
        }
    }
}