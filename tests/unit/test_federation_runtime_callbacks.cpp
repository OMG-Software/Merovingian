// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
    config.max_transaction_bytes = 65536U;
    config.remote_timeout_seconds = 30U;
    config.server_name = "local.example.org";
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

[[nodiscard]] auto sodium_is_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

auto derive_test_keypair(std::string_view key_material,
                         std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& public_key,
                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secret_key) noexcept -> bool
{
    if (!sodium_is_ready())
    {
        return false;
    }
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    if (crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(key_material.data()),
                           key_material.size(), nullptr, 0U) != 0)
    {
        return false;
    }
    return crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data()) == 0;
}

class TestSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit TestSigningStore(merovingian::crypto::SigningKeyRecord key)
        : key_{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != key_.server_name)
        {
            return {{}, "signing key not found"};
        }
        return {key_, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord key_{};
};

class TestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit TestEd25519Provider(std::string key_material)
        : key_material_{std::move(key_material)}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (!derive_test_keypair(key_material_, public_key, secret_key))
        {
            return {{}, "unable to derive signing key"};
        }
        auto signature = std::string(crypto_sign_BYTES, '\0');
        if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                 secret_key.data()) != 0)
        {
            return {{}, "signing failed"};
        }
        return {merovingian::crypto::Ed25519Signature{std::move(signature)}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const&, std::string_view,
                              merovingian::crypto::Ed25519Signature const&)
        -> merovingian::crypto::VerificationResult override
    {
        return {false, "test provider does not verify"};
    }

private:
    std::string key_material_{};
};

[[nodiscard]] auto signed_json_pdu(std::string const& origin, std::string const& key_id, std::string const& token)
    -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(token, public_key, secret_key));
    auto const event_json =
        "{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"depth\":1,\"hashes\":{\"sha256\":"
        "\"hash\"},\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
        origin + "\",\"type\":\"m.room.message\"}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    auto store = TestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = TestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

[[nodiscard]] auto signed_get_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "GET";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = "";
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto signed_put_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                      std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto signed_post_request(std::string const& origin, std::string const& key_id,
                                       std::string const& key_seed, std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "POST";
    request.target = target;
    request.origin = origin;
    request.destination = "local.example.org";
    request.key_id = key_id;
    request.now_ts = 1000U;
    request.canonical_json_verified = true;
    request.body = body;
    request.signature = merovingian::federation::make_federation_signature(
        origin, request.destination, request.method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto transaction_body(std::string const& origin, std::string const& pdu_json) -> std::string
{
    return std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[)" + pdu_json + "]}";
}

[[nodiscard]] auto empty_transaction_body(std::string const& origin) -> std::string
{
    return std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[]})";
}

} // namespace

SCENARIO("PDU sink is invoked when a valid inbound federation transaction is accepted",
         "[federation][callbacks][pdu_sink]")
{
    GIVEN("a runtime with pdu_sink wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"callback-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto sink_invoked = std::make_shared<bool>(false);
        auto sink_room_id = std::make_shared<std::string>();
        runtime.pdu_sink = [sink_invoked, sink_room_id](merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::PduIngestionResult {
            *sink_invoked = true;
            *sink_room_id = envelope.room_id;
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto request = merovingian::federation::SignedFederationRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-cb-001";
        request.origin = origin;
        request.key_id = key_id;
        request.destination = "local.example.org";
        request.now_ts = 1000U;
        request.canonical_json_verified = true;
        request.body = transaction_body(origin, json_pdu);
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the pdu_sink callback is invoked with the parsed envelope and the transaction is accepted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*sink_invoked);
                REQUIRE(*sink_room_id == "!room:example.org");
            }
        }
    }

    GIVEN("a runtime where pdu_sink rejects a PDU as a state conflict")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"conflict-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto conflict_seen = std::make_shared<bool>(false);
        runtime.pdu_sink =
            [conflict_seen](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            *conflict_seen = true;
            return {merovingian::federation::PduIngestionStatus::rejected_state_conflict, "fork detected"};
        };

        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto request = merovingian::federation::SignedFederationRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-conflict-001";
        request.origin = origin;
        request.key_id = key_id;
        request.destination = "local.example.org";
        request.now_ts = 1000U;
        request.canonical_json_verified = true;
        request.body = transaction_body(origin, json_pdu);
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the pdu_sink is invoked, the conflict is audited, and the transaction still returns 200")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*conflict_seen);
                auto const has_conflict_audit = [&runtime] {
                    for (auto const& ev : runtime.audit_events)
                    {
                        if (ev.event_type == "federation.pdu_state_conflict")
                        {
                            return true;
                        }
                    }
                    return false;
                }();
                REQUIRE(has_conflict_audit);
            }
        }
    }
}

SCENARIO("Membership template provider is invoked for make_join and make_leave", "[federation][callbacks][membership]")
{
    GIVEN("a runtime with membership_template_provider wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"membership-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto provider_invoked = std::make_shared<bool>(false);
        auto captured_room_id = std::make_shared<std::string>();
        auto captured_user_id = std::make_shared<std::string>();
        runtime.membership_template_provider = [provider_invoked, captured_room_id, captured_user_id](
                                                   merovingian::federation::FederationEndpoint /*endpoint*/,
                                                   std::string_view room_id, std::string_view user_id,
                                                   std::vector<std::string> const& /*versions*/)
            -> std::optional<merovingian::federation::MembershipEventTemplate> {
            *provider_invoked = true;
            *captured_room_id = std::string{room_id};
            *captured_user_id = std::string{user_id};
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.membership = "join";
            tmpl.room_version = "12";
            tmpl.content_json = "{\"membership\":\"join\"}";
            return tmpl;
        };

        auto const target =
            std::string{"/_matrix/federation/v1/make_join/!room:example.org/@alice:matrix.example.org?ver=12"};
        auto const request = signed_get_request(origin, key_id, token, target);

        WHEN("the make_join request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the template provider is invoked with the correct room and user IDs")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*provider_invoked);
                REQUIRE(*captured_room_id == "!room:example.org");
                REQUIRE(*captured_user_id == "@alice:matrix.example.org");
            }
        }
    }

    GIVEN("a runtime where membership_template_provider returns nullopt")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"membership-missing-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        runtime.membership_template_provider =
            [](merovingian::federation::FederationEndpoint, std::string_view, std::string_view,
               std::vector<std::string> const&) -> std::optional<merovingian::federation::MembershipEventTemplate> {
            return std::nullopt;
        };

        auto const target =
            std::string{"/_matrix/federation/v1/make_join/!unknown:example.org/@alice:matrix.example.org?ver=12"};
        auto const request = signed_get_request(origin, key_id, token, target);

        WHEN("the make_join request is handled for an unknown room")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 404 not found")
            {
                REQUIRE(response.status == 404U);
            }
        }
    }
}

SCENARIO("Membership acceptor is invoked for send_join", "[federation][callbacks][membership]")
{
    GIVEN("a runtime with membership_acceptor wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"send-join-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto acceptor_invoked = std::make_shared<bool>(false);
        auto captured_event_id = std::make_shared<std::string>();
        runtime.membership_acceptor =
            [acceptor_invoked, captured_event_id](merovingian::federation::FederationEndpoint /*endpoint*/,
                                                  std::string_view /*room_id*/, std::string_view event_id,
                                                  merovingian::federation::InboundPduEnvelope const& /*envelope*/)
            -> merovingian::federation::MembershipAcceptResult {
            *acceptor_invoked = true;
            *captured_event_id = std::string{event_id};
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.auth_chain_json = {};
            result.state_json = {};
            return result;
        };

        auto const join_event_json = signed_json_pdu(origin, key_id, token);
        auto const target = std::string{"/_matrix/federation/v2/send_join/!room:example.org/$ev1:example.org"};
        auto const request = signed_put_request(origin, key_id, token, target, join_event_json);

        WHEN("the send_join request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the membership acceptor is invoked and the join is accepted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*acceptor_invoked);
                REQUIRE(*captured_event_id == "$ev1:example.org");
            }
        }
    }
}

SCENARIO("make_join version negotiation rejects incompatible room versions",
         "[federation][callbacks][membership][version-negotiation]")
{
    GIVEN("a runtime with a v12 room and a template provider that negotiates versions")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"version-negotiation-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        // Simulate a server hosting a v12 room. If the remote does not support
        // v12, the provider signals M_INCOMPATIBLE_ROOM_VERSION via tmpl.reason.
        runtime.membership_template_provider = [](merovingian::federation::FederationEndpoint, std::string_view room_id,
                                                  std::string_view user_id,
                                                  std::vector<std::string> const& supported_versions)
            -> std::optional<merovingian::federation::MembershipEventTemplate> {
            auto const room_version = std::string{"12"};
            if (!supported_versions.empty() &&
                std::ranges::find(supported_versions, room_version) == supported_versions.end())
            {
                auto tmpl = merovingian::federation::MembershipEventTemplate{};
                tmpl.room_version = room_version;
                tmpl.reason =
                    R"({"errcode":"M_INCOMPATIBLE_ROOM_VERSION","error":"Your homeserver does not support the features required to join this room","room_version":"12"})";
                return tmpl;
            }
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = std::string{room_id};
            tmpl.user_id = std::string{user_id};
            tmpl.membership = "join";
            tmpl.room_version = room_version;
            tmpl.content_json = R"({"membership":"join"})";
            return tmpl;
        };

        WHEN("make_join is called with only ver=10 (remote does not support v12)")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/make_join/!room:example.org/@alice:matrix.example.org?ver=10"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("the response is 400 with M_INCOMPATIBLE_ROOM_VERSION in the body")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INCOMPATIBLE_ROOM_VERSION") != std::string::npos);
            }
        }

        WHEN("make_join is called with ver=10 and ver=12 (remote supports v12)")
        {
            auto const target = std::string{
                "/_matrix/federation/v1/make_join/!room:example.org/@alice:matrix.example.org?ver=10&ver=12"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("the response is 200 with room_version 12 in the template")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("room_version":"12")") != std::string::npos);
            }
        }
    }
}

SCENARIO("send_join response carries the room_version from the membership acceptor",
         "[federation][callbacks][membership][version-negotiation]")
{
    GIVEN("a runtime where the membership acceptor reports room_version 11")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"send-join-version-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        runtime.membership_acceptor =
            [](merovingian::federation::FederationEndpoint, std::string_view, std::string_view,
               merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::MembershipAcceptResult {
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "11";
            return result;
        };

        WHEN("the send_join request is handled")
        {
            auto const join_event_json = signed_json_pdu(origin, key_id, token);
            auto const target = std::string{"/_matrix/federation/v2/send_join/!room:example.org/$ev1:example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, token, target, join_event_json));

            THEN("the response body carries room_version 11, not the hardcoded default")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("room_version":"11")") != std::string::npos);
                REQUIRE(response.body.find(R"("room_version":"12")") == std::string::npos);
            }
        }
    }

    GIVEN("a runtime where the membership acceptor omits room_version")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"send-join-default-version-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        runtime.membership_acceptor =
            [](merovingian::federation::FederationEndpoint, std::string_view, std::string_view,
               merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::MembershipAcceptResult {
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            // room_version intentionally left empty to exercise the fallback path
            return result;
        };

        WHEN("the send_join request is handled")
        {
            auto const join_event_json = signed_json_pdu(origin, key_id, token);
            auto const target = std::string{"/_matrix/federation/v2/send_join/!room:example.org/$ev2:example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_put_request(origin, key_id, token, target, join_event_json));

            THEN("the response body falls back to room_version 12")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("room_version":"12")") != std::string::npos);
            }
        }
    }
}

SCENARIO("Backfill provider is invoked for backfill requests", "[federation][callbacks][backfill]")
{
    GIVEN("a runtime with backfill_provider wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"backfill-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto provider_invoked = std::make_shared<bool>(false);
        auto captured_limit = std::make_shared<std::size_t>(0U);
        auto captured_event_ids = std::make_shared<std::vector<std::string>>();
        runtime.backfill_provider =
            [provider_invoked, captured_limit, captured_event_ids](
                merovingian::federation::BackfillRequest const& req) -> merovingian::federation::BackfillResult {
            *provider_invoked = true;
            *captured_limit = req.limit;
            *captured_event_ids = req.event_ids;
            auto result = merovingian::federation::BackfillResult{};
            result.accepted = true;
            result.status = 200U;
            result.pdus_json = {"{\"type\":\"m.room.message\"}"};
            return result;
        };

        auto const target =
            std::string{"/_matrix/federation/v1/backfill/!room:example.org?v=$event1:example.org&limit=5"};
        auto const request = signed_get_request(origin, key_id, token, target);

        WHEN("the backfill request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the backfill provider is invoked with the correct limit and event IDs")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*provider_invoked);
                REQUIRE(*captured_limit == 5U);
                REQUIRE(captured_event_ids->size() == 1U);
                REQUIRE(captured_event_ids->front() == "$event1:example.org");
            }
        }
    }

    GIVEN("a runtime without a backfill_provider wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"backfill-no-cb-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto const target =
            std::string{"/_matrix/federation/v1/backfill/!room:example.org?v=$event1:example.org&limit=5"};
        auto const request = signed_get_request(origin, key_id, token, target);

        WHEN("the backfill request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

SCENARIO("Profile query provider answers inbound federation query/profile", "[federation][callbacks][query-profile]")
{
    GIVEN("a runtime with profile_query_provider wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"profile-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        runtime.profile_query_provider = [](std::string_view user_id) -> merovingian::federation::FederationProfile {
            if (user_id == "@alice:local.example.org")
            {
                return {true, "Alice", "mxc://local.example.org/avatar"};
            }
            return {};
        };

        WHEN("a query/profile request for a known user is handled")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/query/profile?user_id=%40alice%3Alocal.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("the response carries the user's displayname and avatar_url")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("Alice") != std::string::npos);
                REQUIRE(response.body.find("mxc://local.example.org/avatar") != std::string::npos);
            }
        }

        WHEN("a query/profile request restricted to the displayname field is handled")
        {
            auto const target = std::string{
                "/_matrix/federation/v1/query/profile?user_id=%40alice%3Alocal.example.org&field=displayname"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("only the displayname is returned")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("Alice") != std::string::npos);
                REQUIRE(response.body.find("avatar_url") == std::string::npos);
            }
        }

        WHEN("a query/profile request for an unknown user is handled")
        {
            auto const target =
                std::string{"/_matrix/federation/v1/query/profile?user_id=%40nobody%3Alocal.example.org"};
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("the response is 404 M_NOT_FOUND")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime without a profile_query_provider wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"profile-no-cb-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto const target = std::string{"/_matrix/federation/v1/query/profile?user_id=%40alice%3Alocal.example.org"};

        WHEN("the query/profile request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token, target));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

SCENARIO("E2EE federation key routes dispatch through their runtime hooks", "[federation][callbacks][e2ee-keys]")
{
    GIVEN("a runtime with the E2EE key hooks wired and a known remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"e2ee-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        runtime.device_keys_query_provider = [](std::string_view) {
            return std::string{R"({"device_keys":{}})"};
        };
        runtime.one_time_keys_claim_provider = [](std::string_view) {
            return std::string{R"({"one_time_keys":{}})"};
        };
        runtime.user_devices_provider = [](std::string_view) {
            return std::string{R"({"user_id":"@a:x","devices":[]})"};
        };

        WHEN("a user/keys/query request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_post_request(origin, key_id, token, "/_matrix/federation/v1/user/keys/query",
                                             R"({"device_keys":{}})"));

            THEN("the device-keys hook answers with 200")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("device_keys") != std::string::npos);
            }
        }

        WHEN("a user/keys/claim request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_post_request(origin, key_id, token, "/_matrix/federation/v1/user/keys/claim",
                                             R"({"one_time_keys":{}})"));

            THEN("the claim hook answers with 200")
            {
                REQUIRE(response.status == 200U);
            }
        }

        WHEN("a user/devices request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_get_request(origin, key_id, token,
                                            "/_matrix/federation/v1/user/devices/%40alice%3Alocal.example.org"));

            THEN("the user-devices hook answers with 200")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }

    GIVEN("a runtime with no E2EE key hooks wired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"e2ee-no-cb-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        WHEN("a user/keys/query request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime, signed_post_request(origin, key_id, token, "/_matrix/federation/v1/user/keys/query",
                                             R"({"device_keys":{}})"));

            THEN("the response is 501 Not Implemented")
            {
                REQUIRE(response.status == 501U);
            }
        }
    }
}

SCENARIO("Remote key rotation triggers resolver when cached key is stale", "[federation][callbacks][key_rotation]")
{
    GIVEN("a runtime with a known remote whose signing key has expired")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const old_key_id = std::string{"ed25519:old"};
        auto const new_key_id = std::string{"ed25519:new"};
        auto const old_token = std::string{"old-key-token"};
        auto const new_token = std::string{"new-key-token"};

        // Stale key: valid_until_ts=500, but request.now_ts=1000 -> expired
        auto stale_remote = remote_for(origin, old_key_id, old_token);
        stale_remote.signing_key.valid_until_ts = 500U;
        merovingian::federation::upsert_remote(runtime, stale_remote);

        auto resolver_invoked = std::make_shared<bool>(false);
        runtime.remote_key_resolver =
            [resolver_invoked, origin, new_key_id, new_token](
                std::string_view server_name,
                std::string_view /*key_id*/) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != origin)
            {
                return std::nullopt;
            }
            *resolver_invoked = true;
            return remote_for(std::string{origin}, new_key_id, new_token);
        };

        // Build a request signed with the NEW key
        auto request = merovingian::federation::SignedFederationRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-rotation-001";
        request.origin = origin;
        request.key_id = new_key_id;
        request.destination = "local.example.org";
        request.now_ts = 1000U;
        request.canonical_json_verified = true;
        request.body = empty_transaction_body(origin);
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(new_token).secret_key);

        WHEN("the request is handled with the new key")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolver is invoked to fetch the rotated key and the request is accepted")
            {
                REQUIRE(*resolver_invoked);
                // Request uses new signing key that the resolver provides
                REQUIRE(response.status != 401U);
            }
        }
    }

    GIVEN("a runtime with a remote whose key_id changed since last cached")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const cached_key_id = std::string{"ed25519:v1"};
        auto const new_key_id = std::string{"ed25519:v2"};
        auto const cached_token = std::string{"v1-token"};
        auto const new_token = std::string{"v2-token"};

        merovingian::federation::upsert_remote(runtime, remote_for(origin, cached_key_id, cached_token));

        auto resolver_called = std::make_shared<bool>(false);
        runtime.remote_key_resolver =
            [resolver_called, origin, new_key_id, new_token](
                std::string_view server_name,
                std::string_view req_key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != origin || req_key_id != new_key_id)
            {
                return std::nullopt;
            }
            *resolver_called = true;
            return remote_for(std::string{origin}, new_key_id, new_token);
        };

        // Request signed with the NEW key_id (not in cache)
        auto request = merovingian::federation::SignedFederationRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-keyid-change";
        request.origin = origin;
        request.key_id = new_key_id;
        request.destination = "local.example.org";
        request.now_ts = 1000U;
        request.canonical_json_verified = true;
        request.body = empty_transaction_body(origin);
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(new_token).secret_key);

        WHEN("the request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolver is invoked because the key_id differs from cache")
            {
                REQUIRE(*resolver_called);
                REQUIRE(response.status != 401U);
            }
        }
    }
}

SCENARIO("A transaction with a bad-signature PDU returns 200 with a per-PDU error, not 403",
         "[federation][send][pdu-sig]")
{
    GIVEN("a remote registered under one keypair and a PDU signed with a different keypair")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const reg_seed = std::string{"registered-seed"};
        auto const bad_seed = std::string{"unregistered-seed"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, reg_seed));

        auto sink_invoked = std::make_shared<bool>(false);
        runtime.pdu_sink =
            [sink_invoked](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            *sink_invoked = true;
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        // PDU whose signature won't verify against the registered key
        auto const bad_pdu = signed_json_pdu(origin, key_id, bad_seed);
        auto const request = signed_put_request(origin, key_id, reg_seed, "/_matrix/federation/v1/send/txn-bad-sig-001",
                                                transaction_body(origin, bad_pdu));

        WHEN("the transaction containing the bad PDU is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200, not 403 - the whole transaction is not rejected")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("the response body reports a per-PDU error inside the pdus map")
            {
                REQUIRE(response.body.find("\"pdus\"") != std::string::npos);
                REQUIRE(response.body.find("\"error\"") != std::string::npos);
            }

            THEN("the pdu_sink is not invoked for the rejected PDU")
            {
                REQUIRE_FALSE(*sink_invoked);
            }
        }
    }

    GIVEN("a transaction mixing one valid PDU and one bad-signature PDU")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const good_seed = std::string{"mixed-good-seed"};
        auto const bad_seed = std::string{"mixed-bad-seed"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, good_seed));

        auto sink_calls = std::make_shared<std::size_t>(0U);
        runtime.pdu_sink =
            [sink_calls](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            ++(*sink_calls);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto const good_pdu = signed_json_pdu(origin, key_id, good_seed);
        auto const bad_pdu = signed_json_pdu(origin, key_id, bad_seed);
        // Wrap both PDUs in a proper transaction body
        auto const body = std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[)" + good_pdu +
                          "," + bad_pdu + "]}";
        auto const request =
            signed_put_request(origin, key_id, good_seed, "/_matrix/federation/v1/send/txn-mixed-001", body);

        WHEN("the mixed transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200 and the valid PDU still reaches the sink")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*sink_calls == 1U);
            }

            THEN("the response body contains a per-PDU error for the rejected PDU")
            {
                REQUIRE(response.body.find("\"error\"") != std::string::npos);
            }
        }
    }
}

// --- send_join / send_leave response shape -----------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 10 Joining Rooms
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#put_matrixfederationv2send_leaveroomideventid
//
// The resident server MUST echo the accepted join event back under "event" for
// v2 send_join responses. send_leave does not define that field. If this test
// fails, fix the implementation. Do NOT weaken the assertions unless the Matrix
// spec itself changes and the new section is cited here.
SCENARIO("send_join v2 response echoes the signed join event in the 'event' field",
         "[federation][callbacks][membership][spec]")
{
    GIVEN("a runtime with a membership acceptor that returns the signed join event JSON")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"send-join-event-echo-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto const join_event_json = signed_json_pdu(origin, key_id, token);

        runtime.membership_acceptor = [join_event_json](merovingian::federation::FederationEndpoint /*endpoint*/,
                                                        std::string_view /*room_id*/, std::string_view /*event_id*/,
                                                        merovingian::federation::InboundPduEnvelope const& /*envelope*/)
            -> merovingian::federation::MembershipAcceptResult {
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            result.signed_event_json = join_event_json;
            return result;
        };

        auto const target = std::string{"/_matrix/federation/v2/send_join/!room:example.org/$ev1:example.org"};
        auto const request = signed_put_request(origin, key_id, token, target, join_event_json);

        WHEN("the send_join request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200 and the body contains the 'event' field with the signed PDU")
            {
                // Spec MUST: send_join v2 returns HTTP 200 with an "event" field
                // containing the accepted join PDU.
                // Do NOT remove/change - a missing field breaks remote join
                // completion against conformant homeservers.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("event")") != std::string::npos);
                // auth_chain and state are empty in this stub, so "sender" can only
                // appear inside the echoed event - proves it is the actual PDU.
                // Do NOT remove/change - this guards against implementations
                // that emit an empty placeholder object instead of the join PDU.
                REQUIRE(response.body.find(R"("sender")") != std::string::npos);
            }
        }
    }

    GIVEN("a runtime with a membership acceptor for send_leave")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"send-leave-no-event-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto const leave_event_json = signed_json_pdu(origin, key_id, token);

        runtime.membership_acceptor =
            [leave_event_json](merovingian::federation::FederationEndpoint /*endpoint*/, std::string_view /*room_id*/,
                               std::string_view /*event_id*/,
                               merovingian::federation::InboundPduEnvelope const& /*envelope*/)
            -> merovingian::federation::MembershipAcceptResult {
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            // signed_event_json is populated but must be ignored for send_leave
            result.signed_event_json = leave_event_json;
            return result;
        };

        auto const target = std::string{"/_matrix/federation/v2/send_leave/!room:example.org/$ev2:example.org"};
        auto const request = signed_put_request(origin, key_id, token, target, leave_event_json);

        WHEN("the send_leave request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the response is 200 and the body does not contain an 'event' field")
            {
                // Spec MUST NOT: send_leave v2 does not define an "event" field.
                // Do NOT remove/change - accepting or advertising that field here
                // would be a protocol-shape regression.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(R"("event")") == std::string::npos);
            }
        }
    }
}
