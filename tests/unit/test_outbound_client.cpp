// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Outbound HTTP request validation enforces method, scheme, host, and address binding",
         "[http][outbound][validation]")
{
    GIVEN("a well-formed request with all required fields")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "PUT";
        request.url = "https://matrix.example.org/_matrix/federation/v1/send/txn123";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation passes")
            {
                REQUIRE(error == merovingian::http::OutboundError::none);
            }
        }
    }

    GIVEN("a request with an unknown HTTP method")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "TRACE";
        request.url = "https://matrix.example.org/_matrix/key/v2/server";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation rejects the method")
            {
                REQUIRE(error == merovingian::http::OutboundError::invalid_method);
            }
        }
    }

    GIVEN("a request whose URL uses cleartext http")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "http://matrix.example.org/_matrix/key/v2/server";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation refuses to send over cleartext")
            {
                REQUIRE(error == merovingian::http::OutboundError::https_required);
            }
        }
    }

    GIVEN("a request whose URL is missing the host segment")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "https:///path/only";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation rejects the malformed URL")
            {
                REQUIRE(error == merovingian::http::OutboundError::invalid_url);
            }
        }
    }

    GIVEN("a request whose URL is empty")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation rejects the empty URL")
            {
                REQUIRE(error == merovingian::http::OutboundError::invalid_url);
            }
        }
    }

    GIVEN("a request with no pinned addresses")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "https://matrix.example.org/_matrix/key/v2/server";

        WHEN("the request is validated")
        {
            auto const error = merovingian::http::validate_outbound_request(request);

            THEN("validation refuses to resolve the host on the caller's behalf")
            {
                REQUIRE(error == merovingian::http::OutboundError::unresolved_host);
            }
        }
    }
}

SCENARIO("Outbound HTTP client rejects unsafe requests before any network I/O", "[http][outbound][prenetwork]")
{
    GIVEN("an OutboundClient instance and a request with a cleartext URL")
    {
        auto client = merovingian::http::OutboundClient{};
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "http://matrix.example.org/_matrix/key/v2/server";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("perform is invoked")
        {
            auto const result = client.perform(request);

            THEN("the call fails closed with https_required before any network I/O is attempted")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::https_required);
                REQUIRE(result.response.status == 0U);
                REQUIRE(result.response.body.empty());
            }
        }
    }

    GIVEN("an OutboundClient instance and a request with no pinned addresses")
    {
        auto client = merovingian::http::OutboundClient{};
        auto request = merovingian::http::OutboundRequest{};
        request.method = "GET";
        request.url = "https://matrix.example.org/_matrix/key/v2/server";

        WHEN("perform is invoked")
        {
            auto const result = client.perform(request);

            THEN("the call fails closed with unresolved_host without attempting DNS")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::unresolved_host);
                REQUIRE(result.response.status == 0U);
                REQUIRE(result.response.body.empty());
            }
        }
    }

    GIVEN("an OutboundClient instance and a request with an unknown method")
    {
        auto client = merovingian::http::OutboundClient{};
        auto request = merovingian::http::OutboundRequest{};
        request.method = "TRACE";
        request.url = "https://matrix.example.org/_matrix/key/v2/server";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("perform is invoked")
        {
            auto const result = client.perform(request);

            THEN("the call fails closed with invalid_method before any network I/O is attempted")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::invalid_method);
                REQUIRE(result.response.status == 0U);
            }
        }
    }
}

SCENARIO("Outbound error names are stable, lowercase identifiers for audit logs", "[http][outbound][naming]")
{
    GIVEN("each outbound error value")
    {
        WHEN("the name is requested")
        {
            THEN("the name matches the documented audit-friendly identifier")
            {
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::none) == "none");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::invalid_url) ==
                        "invalid_url");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::invalid_method) ==
                        "invalid_method");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::https_required) ==
                        "https_required");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::unresolved_host) ==
                        "unresolved_host");
                REQUIRE(merovingian::http::outbound_error_name(
                            merovingian::http::OutboundError::tls_verification_failed) == "tls_verification_failed");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::connection_failed) ==
                        "connection_failed");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::redirect_rejected) ==
                        "redirect_rejected");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::response_too_large) ==
                        "response_too_large");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::timeout) == "timeout");
                REQUIRE(merovingian::http::outbound_error_name(merovingian::http::OutboundError::network_error) ==
                        "network_error");
            }
        }
    }
}
