// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
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

SCENARIO("EDU transaction bodies key each EDU by edu_type so Synapse accepts them", "[federation][outbound][edu]")
{
    GIVEN("an EDU type and its content JSON")
    {
        WHEN("a typing EDU transaction body is built")
        {
            auto const body = merovingian::federation::build_edu_transaction_body(
                "origin.example.org", "m.typing", R"({"room_id":"!r:home","typing":true})");

            THEN("the body carries the EDU under the spec-required edu_type key, never a bare type key")
            {
                REQUIRE(body.has_value());
                // The federation spec (and Synapse) read edu["edu_type"]; a bare "type" key makes
                // the receiver raise KeyError and 500 the whole transaction.
                REQUIRE(body->find(R"("edu_type":"m.typing")") != std::string::npos);
                REQUIRE(body->find(R"("type":"m.typing")") == std::string::npos);
            }

            AND_THEN("the EDU content is preserved and no PDUs are included")
            {
                REQUIRE(body->find(R"("typing":true)") != std::string::npos);
                REQUIRE(body->find(R"("origin":"origin.example.org")") != std::string::npos);
                REQUIRE(body->find(R"("origin_server_ts":)") != std::string::npos);
                REQUIRE(body->find(R"("room_id":"!r:home")") != std::string::npos);
                REQUIRE(body->find(R"("pdus":[])") != std::string::npos);
            }
        }

        WHEN("the EDU content JSON is malformed")
        {
            auto const body =
                merovingian::federation::build_edu_transaction_body("origin.example.org", "m.receipt", "{not json");

            THEN("no transaction body is produced")
            {
                REQUIRE_FALSE(body.has_value());
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#receipts
// Required shape: { roomId: { receiptType: { userId: { event_ids: [eventId], data: { ts: N } } } } }
SCENARIO("receipt EDU content follows Matrix spec nested structure", "[federation][outbound][edu][spec][receipt]")
{
    GIVEN("a room ID, receipt type, user ID, event ID and timestamp")
    {
        WHEN("build_receipt_edu_content is called with m.read")
        {
            auto const content = merovingian::federation::build_receipt_edu_content(
                "!room:server", "m.read", "@user:server", "$event:server", std::int64_t{1234567890});

            // canonicaljson sorts keys alphabetically and produces a single deterministic form,
            // so we can assert the exact output. Any structural regression (missing nesting level,
            // ts outside data, event_ids not an array, etc.) will break this assertion directly.
            THEN("content matches the exact canonical JSON the spec requires")
            {
                REQUIRE(content.has_value());
                REQUIRE(
                    *content ==
                    R"({"!room:server":{"m.read":{"@user:server":{"data":{"ts":1234567890},"event_ids":["$event:server"]}}}})");
            }

            AND_THEN("the content wraps into a valid m.receipt EDU transaction body with edu_type key")
            {
                REQUIRE(content.has_value());
                auto const tx =
                    merovingian::federation::build_edu_transaction_body("origin.example.org", "m.receipt", *content);
                REQUIRE(tx.has_value());
                REQUIRE(tx->find(R"("edu_type":"m.receipt")") != std::string::npos);
                REQUIRE(tx->find(R"("type":"m.receipt")") == std::string::npos);
            }
        }

        WHEN("build_receipt_edu_content is called with m.read.private")
        {
            auto const content = merovingian::federation::build_receipt_edu_content(
                "!room:server", "m.read.private", "@user:server", "$event:server", std::int64_t{9000});

            THEN("the receipt type key is preserved verbatim in the canonical output")
            {
                REQUIRE(content.has_value());
                REQUIRE(
                    *content ==
                    R"({"!room:server":{"m.read.private":{"@user:server":{"data":{"ts":9000},"event_ids":["$event:server"]}}}})");
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

[[nodiscard]] auto make_sample_call(merovingian::federation::test::SigningKeypair const& kp)
    -> merovingian::federation::OutboundCall
{
    auto call = merovingian::federation::OutboundCall{};
    call.transaction = merovingian::federation::make_outbound_transaction(
        "remote.example.org", "PUT", "/_matrix/federation/v1/send/txn123", "origin.example.org", R"({"pdus":[]})");
    call.resolved_host = "remote.example.org";
    call.resolved_port = 8448U;
    call.pinned_addresses = {"203.0.113.10"};
    call.key_id = "ed25519:auto";
    // Borrow the keypair's secret key as a span — kp must outlive the call, which
    // each scenario guarantees by holding kp in the enclosing GIVEN scope.
    call.secret_key = merovingian::federation::test::secret_key_span(kp);
    return call;
}

[[nodiscard]] auto sample_keypair() -> merovingian::federation::test::SigningKeypair
{
    return merovingian::federation::test::keypair_from_seed("deterministic-test-token");
}

} // namespace

SCENARIO("Outbound request builder produces a federation HTTPS request shape", "[federation][outbound][builder]")
{
    GIVEN("a federation call composed from a transaction, resolution, and signing identity")
    {
        auto const kp = sample_keypair();
        auto const call = make_sample_call(kp);

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
        auto const kp = sample_keypair();
        auto call = make_sample_call(kp);
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
        auto const kp = sample_keypair();
        auto call = make_sample_call(kp);
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

        auto const kp = sample_keypair();
        auto const call = make_sample_call(kp);
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
