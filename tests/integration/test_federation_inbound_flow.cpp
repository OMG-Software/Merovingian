// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/federation/inbound_request.hpp>
#include <merovingian/homeserver/vertical_slice.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto federation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& verify_token)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, verify_token, 2000U};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto pdu_for(std::string const& origin) -> std::string
{
    return "$event1:example.org,!room1:example.org,m.room.message,@alice:" + origin + ',' + origin + ",ed25519:auto,signature";
}

[[nodiscard]] auto federation_authorization(
    std::string const& origin,
    std::string const& key_id,
    std::string const& verify_token,
    std::string const& method,
    std::string const& target,
    std::string const& body
) -> std::string
{
    auto constexpr timestamp = std::uint64_t{1000U};
    auto const signature = merovingian::federation::make_federation_signature(
        origin,
        key_id,
        verify_token,
        method,
        target,
        timestamp,
        body
    );
    return origin + '|' + key_id + '|' + signature + '|' + std::to_string(timestamp) + '|' + std::to_string(timestamp) + "|signed";
}

} // namespace

SCENARIO("Homeserver routes signed inbound federation transactions through runtime policy", "[integration][federation]")
{
    GIVEN("a started runtime with a known remote server")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, token));
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = pdu_for(origin);
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);

        WHEN("a signed federation request reaches the local router")
        {
            auto const response = merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("the transaction is accepted and recorded")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == "accepted pdus=1");
                REQUIRE(runtime.federation.accepted_transactions.size() == 1U);
                REQUIRE(runtime.federation.accepted_transactions.front().origin == origin);
                REQUIRE(runtime.federation.audit_events.size() == 1U);
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime.federation));
            }
        }
    }
}

SCENARIO("Homeserver rejects malformed and private-address federation requests", "[integration][federation][security]")
{
    GIVEN("a started runtime with one private-address remote")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto remote = remote_for(origin, key_id, token);
        remote.discovery.resolved_addresses = {"127.0.0.1"};
        merovingian::federation::upsert_remote(runtime.federation, remote);
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = pdu_for(origin);
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);

        WHEN("malformed and private-address requests are routed")
        {
            auto const malformed = merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, "not-enough-fields", body});
            auto const private_remote = merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("both fail closed")
            {
                REQUIRE(malformed.status == 401U);
                REQUIRE(malformed.body == "malformed federation authorization");
                REQUIRE(private_remote.status == 403U);
                REQUIRE(private_remote.body == "remote address is private or loopback");
                REQUIRE(runtime.federation.accepted_transactions.empty());
            }
        }
    }
}
