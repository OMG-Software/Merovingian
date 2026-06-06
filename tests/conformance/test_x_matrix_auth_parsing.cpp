// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include "federation_signing_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 4096U;
    config.remote_timeout_seconds = 30U;
    return config;
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 2000U, merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_request(std::string const& origin, std::string const& key_id,
                                  std::string const& key_seed,
                                  std::string const& body) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/txn-tls-test";
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        request.origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

} // namespace

SCENARIO("X-Matrix Authorization header is parsed into credentials", "[federation][x-matrix][parsing]")
{
    GIVEN("a valid full X-Matrix header with all fields")
    {
        auto const header =
            std::string_view{"X-Matrix origin=\"matrix.example.org\",key=\"ed25519:auto\","
                             "sig=\"abc123==\",destination=\"local.example.org\""};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("all fields are extracted correctly")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "abc123==");
                REQUIRE(result->destination == "local.example.org");
            }
        }
    }

    GIVEN("a valid minimal X-Matrix header with only required fields")
    {
        auto const header =
            std::string_view{R"(X-Matrix origin="matrix.example.org",key="ed25519:key1",sig="sig+val==")"};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(header);

            THEN("required fields are extracted and destination is empty")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.example.org");
                REQUIRE(result->key_id == "ed25519:key1");
                REQUIRE(result->signature == "sig+val==");
                REQUIRE(result->destination.empty());
            }
        }
    }

    GIVEN("X-Matrix headers with missing required fields")
    {
        auto const missing_origin = std::string_view{R"(X-Matrix key="ed25519:auto",sig="abc==")"};
        auto const missing_key = std::string_view{R"(X-Matrix origin="matrix.org",sig="abc==")"};
        auto const missing_sig = std::string_view{"X-Matrix origin=\"matrix.org\",key=\"ed25519:auto\""};

        WHEN("each header is parsed")
        {
            auto const no_origin = merovingian::federation::parse_x_matrix_authorization_header(missing_origin);
            auto const no_key = merovingian::federation::parse_x_matrix_authorization_header(missing_key);
            auto const no_sig = merovingian::federation::parse_x_matrix_authorization_header(missing_sig);

            THEN("all three return nullopt")
            {
                REQUIRE_FALSE(no_origin.has_value());
                REQUIRE_FALSE(no_key.has_value());
                REQUIRE_FALSE(no_sig.has_value());
            }
        }
    }

    GIVEN("malformed or wrong-scheme Authorization header values")
    {
        auto const empty_value = std::string_view{""};
        auto const bearer = std::string_view{"Bearer token123"};
        auto const wrong_case = std::string_view{"x-matrix origin=\"a.org\",key=\"ed25519:k\",sig=\"s\""};
        auto const unquoted = std::string_view{"X-Matrix origin=matrix.org,key=ed25519:auto,sig=abc"};
        auto const unclosed_quote = std::string_view{"X-Matrix origin=\"matrix.org,key=\"ed25519:auto\",sig=\"abc\""};

        WHEN("each value is parsed")
        {
            auto const r_empty = merovingian::federation::parse_x_matrix_authorization_header(empty_value);
            auto const r_bearer = merovingian::federation::parse_x_matrix_authorization_header(bearer);
            auto const r_case = merovingian::federation::parse_x_matrix_authorization_header(wrong_case);
            auto const r_unquoted = merovingian::federation::parse_x_matrix_authorization_header(unquoted);
            auto const r_unclosed = merovingian::federation::parse_x_matrix_authorization_header(unclosed_quote);

            THEN("all return nullopt")
            {
                REQUIRE_FALSE(r_empty.has_value());
                REQUIRE_FALSE(r_bearer.has_value());
                REQUIRE_FALSE(r_case.has_value());
                REQUIRE_FALSE(r_unquoted.has_value());
                REQUIRE_FALSE(r_unclosed.has_value());
            }
        }
    }

    GIVEN("an X-Matrix header with extra whitespace around delimiters")
    {
        auto const spaced =
            std::string_view{"X-Matrix origin=\"matrix.org\" , key=\"ed25519:auto\" , sig=\"abc==\""};

        WHEN("the header is parsed")
        {
            auto const result = merovingian::federation::parse_x_matrix_authorization_header(spaced);

            THEN("fields are trimmed and extracted correctly")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->origin == "matrix.org");
                REQUIRE(result->key_id == "ed25519:auto");
                REQUIRE(result->signature == "abc==");
            }
        }
    }
}

SCENARIO("TLS-bound origin validation gates inbound federation requests", "[federation][inbound][tls]")
{
    GIVEN("a runtime with a known remote and a valid signed request")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"tls-test-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto base_request = signed_request(origin, key_id, token, "{}");

        WHEN("tls_peer_server_name matches origin exactly")
        {
            auto request = base_request;
            request.tls_peer_server_name = origin;
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the request is accepted past the TLS gate")
            {
                REQUIRE(response.status != 403U);
            }
        }

        WHEN("tls_peer_server_name is empty")
        {
            auto request = base_request;
            request.tls_peer_server_name = "";
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("no TLS validation is applied and the request proceeds normally")
            {
                REQUIRE(response.status != 403U);
            }
        }

        WHEN("tls_peer_server_name differs from the X-Matrix origin")
        {
            auto request = base_request;
            request.tls_peer_server_name = "attacker.example.com";
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the request is rejected with 403 and an origin-mismatch reason")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body == "TLS peer name does not match request origin");
            }
        }

        WHEN("tls_peer_server_name is a prefix of origin (not a full match)")
        {
            auto request = base_request;
            request.tls_peer_server_name = "matrix.example";
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the request is rejected because a prefix is not a match")
            {
                REQUIRE(response.status == 403U);
            }
        }
    }
}
