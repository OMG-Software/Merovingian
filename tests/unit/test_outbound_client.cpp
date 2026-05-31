// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

SCENARIO("System CA trust detection locates the host trust store", "[http][outbound][tls]")
{
    GIVEN("a host that ships a standard system CA trust store")
    {
        WHEN("the system CA trust is detected")
        {
            auto const trust = merovingian::http::detect_system_ca_trust();

            THEN("at least one trust store location resolves to a real path")
            {
                auto const has_file = !trust.bundle_file.empty();
                auto const has_dir = !trust.bundle_dir.empty();
                REQUIRE((has_file || has_dir));
                if (has_file)
                {
                    REQUIRE(std::filesystem::is_regular_file(trust.bundle_file));
                }
                if (has_dir)
                {
                    REQUIRE(std::filesystem::is_directory(trust.bundle_dir));
                }
            }
        }
    }
}

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

SCENARIO("A single OutboundClient serves concurrent perform() calls without cross-thread corruption",
         "[http][outbound][concurrency]")
{
    // The runtime shares one OutboundClient across the federation dispatch
    // worker thread and the HTTP request-handler thread pool. perform() must
    // therefore tolerate concurrent invocation on the same instance: each call
    // owns its own transport state so no caller can corrupt another's request.
    // This is the regression guard for the shared-curl-handle data race that
    // surfaced as spurious network_error failures on federation key queries.
    GIVEN("one OutboundClient shared by many threads")
    {
        auto client = merovingian::http::OutboundClient{};

        // A request that passes pre-network validation and therefore drives the
        // underlying transport handle. The pinned address points the URL host
        // at a closed local port so each call returns quickly with a transport
        // failure instead of touching any real federation peer.
        auto make_request = []() {
            auto request = merovingian::http::OutboundRequest{};
            request.method = "GET";
            request.url = "https://concurrency.test.invalid:1/_matrix/key/v2/server";
            request.pinned_addresses = {"127.0.0.1"};
            request.connect_timeout_seconds = 2U;
            request.total_timeout_seconds = 2U;
            return request;
        };

        WHEN("many threads each call perform() repeatedly on the shared instance")
        {
            constexpr auto thread_count = std::size_t{8U};
            constexpr auto calls_per_thread = std::size_t{16U};

            auto start = std::atomic<bool>{false};
            auto well_formed_results = std::atomic<std::size_t>{0U};
            auto threads = std::vector<std::thread>{};
            threads.reserve(thread_count);

            for (auto t = std::size_t{0U}; t < thread_count; ++t)
            {
                threads.emplace_back([&] {
                    // Spin until released so the calls overlap as much as
                    // possible, maximising the chance of catching a race.
                    while (!start.load(std::memory_order_acquire))
                    {
                    }
                    for (auto c = std::size_t{0U}; c < calls_per_thread; ++c)
                    {
                        auto const result = client.perform(make_request());
                        // A fail-closed result with no status and no body is the
                        // only correct outcome for a refused connection. Any
                        // bleed-over from another thread's request would show up
                        // as a success, a populated body, or a non-zero status.
                        if (!result.ok && result.response.status == 0U && result.response.body.empty())
                        {
                            well_formed_results.fetch_add(1U, std::memory_order_relaxed);
                        }
                    }
                });
            }

            start.store(true, std::memory_order_release);
            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("every concurrent call returns its own well-formed, fail-closed result")
            {
                REQUIRE(well_formed_results.load() == thread_count * calls_per_thread);
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
