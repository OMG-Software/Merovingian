// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/trust_safety/policy_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
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

// Injects the real computed content hash into an event value so that
// verify_pdu_content_hash accepts the PDU. sign_event_for_server does not
// compute or inject hashes, so callers must do it before signing.
[[nodiscard]] auto with_correct_content_hash(merovingian::canonicaljson::Value event)
    -> merovingian::canonicaljson::Value
{
    auto const hash = merovingian::events::make_content_hash(event);
    if (!hash.error.empty())
    {
        return event;
    }
    auto const* root = std::get_if<merovingian::canonicaljson::Object>(&event.storage());
    if (root == nullptr)
    {
        return event;
    }
    auto new_root = merovingian::canonicaljson::Object{};
    new_root.reserve(root->size());
    for (auto const& member : *root)
    {
        if (member.key != "hashes")
        {
            new_root.push_back(merovingian::canonicaljson::make_member(member.key, *member.value));
        }
    }
    auto hashes = merovingian::canonicaljson::Object{};
    hashes.push_back(merovingian::canonicaljson::make_member("sha256", merovingian::canonicaljson::Value{hash.sha256}));
    new_root.push_back(
        merovingian::canonicaljson::make_member("hashes", merovingian::canonicaljson::Value{std::move(hashes)}));
    return merovingian::canonicaljson::Value{std::move(new_root)};
}

[[nodiscard]] auto signed_json_pdu(std::string const& origin, std::string const& key_id, std::string const& token)
    -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(token, public_key, secret_key));
    // No hashes field: make_content_hash strips it anyway before computing, so
    // omitting it here gives the same result as including a placeholder.
    auto const event_json =
        "{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"depth\":1,"
        "\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
        origin + "\",\"type\":\"m.room.message\"}";
    auto const base_parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(base_parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    // Inject real content hash before signing so inbound hash verification passes.
    auto const event_with_hash = with_correct_content_hash(base_parsed.value);
    auto store = TestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = TestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(event_with_hash, *policy, store, provider, origin);
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

SCENARIO("Federation dispatch does not hold the global runtime mutex while transaction sinks run",
         "[homeserver][federation][concurrency]")
{
    GIVEN("a homeserver runtime with a blocking federation EDU sink")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.started = true;
        runtime.federation = merovingian::federation::make_federation_runtime_state(runtime_config());

        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, "dispatch-lock-seed"));

        // Prevent production callback auto-wiring; the test needs a controlled
        // sink that blocks inside the federation transaction path.
        runtime.federation.pdu_sink =
            [](merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto sink_entered = false;
        auto release_sink = false;
        auto gate_mutex = std::mutex{};
        auto gate_cv = std::condition_variable{};
        runtime.federation.edu_sink =
            [&](merovingian::federation::InboundEduEnvelope const&) -> merovingian::federation::EduDispositionResult {
            {
                auto const lock = std::lock_guard{gate_mutex};
                sink_entered = true;
            }
            gate_cv.notify_all();
            auto lock = std::unique_lock{gate_mutex};
            gate_cv.wait(lock, [&release_sink] {
                return release_sink;
            });
            return {merovingian::federation::EduDispositionStatus::accepted, {}};
        };

        auto request = merovingian::homeserver::LocalHttpRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-dispatch-lock";
        request.sig_verified = true;
        request.verified_origin = origin;
        request.verified_key_id = key_id;
        request.body =
            R"({"origin":"matrix.example.org","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.direct_to_device","content":{"sender":"@bob:matrix.example.org","type":"m.room_key","messages":{}}}]})";

        auto response = merovingian::homeserver::LocalHttpResponse{};

        WHEN("a federation transaction is blocked inside the sink")
        {
            auto worker = std::thread{[&] {
                response = merovingian::homeserver::handle_federation_http_request(runtime, request);
            }};

            auto sink_started = false;
            {
                auto lock = std::unique_lock{gate_mutex};
                sink_started = gate_cv.wait_for(lock, std::chrono::seconds{2}, [&sink_entered] {
                    return sink_entered;
                });
            }
            if (!sink_started)
            {
                {
                    auto const lock = std::lock_guard{gate_mutex};
                    release_sink = true;
                }
                gate_cv.notify_all();
                worker.join();
            }
            REQUIRE(sink_started);

            auto const runtime_mutex_available = runtime.mutex.try_lock();
            if (runtime_mutex_available)
            {
                runtime.mutex.unlock();
            }

            {
                auto const lock = std::lock_guard{gate_mutex};
                release_sink = true;
            }
            gate_cv.notify_all();
            worker.join();

            THEN("other runtime work can still acquire the global mutex")
            {
                REQUIRE(runtime_mutex_available);
                REQUIRE(response.status == 200U);
            }
        }
    }
}

// Regression test for #415: resolve_policy_server_hook() performs a
// synchronous outbound call (here, the injectable trust_safety_policy_server
// test hook standing in for the real policy-server HTTP request) and MUST run
// outside runtime.mutex. Before the fix, the hook was invoked while
// handle_federation_http_request still held the guard, so a slow or
// unreachable policy server froze every other runtime.mutex consumer
// (server-name lookup, most client-server dispatch) for up to
// policy_server_timeout.
SCENARIO("Federation dispatch does not hold the global runtime mutex while the policy-server hook runs",
         "[homeserver][federation][concurrency][trust-safety]")
{
    GIVEN("a homeserver runtime with trust-safety enabled and a blocking policy-server hook")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.started = true;
        runtime.federation = merovingian::federation::make_federation_runtime_state(runtime_config());
        runtime.config.security().trust_safety.enabled = true;
        runtime.config.security().trust_safety.policy_server_url = "https://policy.example.org/check";
        runtime.config.security().trust_safety.policy_server_timeout = "5s";

        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, "policy-lock-seed"));
        runtime.federation.pdu_sink =
            [](merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto hook_entered = false;
        auto release_hook = false;
        auto gate_mutex = std::mutex{};
        auto gate_cv = std::condition_variable{};
        runtime.trust_safety_policy_server = [&](merovingian::trust_safety::PolicySurface,
                                                 std::string_view) -> merovingian::trust_safety::PolicyServerHook {
            {
                auto const lock = std::lock_guard{gate_mutex};
                hook_entered = true;
            }
            gate_cv.notify_all();
            auto lock = std::unique_lock{gate_mutex};
            gate_cv.wait(lock, [&release_hook] {
                return release_hook;
            });
            auto hook = merovingian::trust_safety::PolicyServerHook{};
            hook.enabled = true;
            hook.reachable = true;
            // No explicit decision from the (simulated) policy server;
            // allow_without_result opts into the permissive default so this
            // test's assertion is about mutex availability, not about
            // trust_safety's fail-closed-on-no-decision policy (which is
            // exercised elsewhere).
            hook.allow_without_result = true;
            return hook;
        };

        auto request = merovingian::homeserver::LocalHttpRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-policy-lock";
        request.sig_verified = true;
        request.verified_origin = origin;
        request.verified_key_id = key_id;
        request.body = R"({"origin":"matrix.example.org","origin_server_ts":1000,"pdus":[],"edus":[]})";

        auto response = merovingian::homeserver::LocalHttpResponse{};

        WHEN("a federation transaction is blocked inside the policy-server hook")
        {
            auto worker = std::thread{[&] {
                response = merovingian::homeserver::handle_federation_http_request(runtime, request);
            }};

            auto hook_started = false;
            {
                auto lock = std::unique_lock{gate_mutex};
                hook_started = gate_cv.wait_for(lock, std::chrono::seconds{2}, [&hook_entered] {
                    return hook_entered;
                });
            }
            if (!hook_started)
            {
                {
                    auto const lock = std::lock_guard{gate_mutex};
                    release_hook = true;
                }
                gate_cv.notify_all();
                worker.join();
            }
            REQUIRE(hook_started);

            auto const runtime_mutex_available = runtime.mutex.try_lock();
            if (runtime_mutex_available)
            {
                runtime.mutex.unlock();
            }

            {
                auto const lock = std::lock_guard{gate_mutex};
                release_hook = true;
            }
            gate_cv.notify_all();
            worker.join();

            THEN("other runtime work can still acquire the global mutex while the hook blocks")
            {
                REQUIRE(runtime_mutex_available);
                REQUIRE(response.status == 200U);
            }
        }
    }
}

// Regression test for #425: the typing EDU handler never checked that
// content.user_id's domain matched the verified envelope origin, so a
// federated server could report typing state for a user on a completely
// different domain. Spec: SS API #edus — the EDU sender's own homeserver
// must be the one reporting the user's typing state.
SCENARIO("Typing EDU is rejected when content.user_id's domain does not match the envelope origin",
         "[homeserver][federation][typing][security]")
{
    GIVEN("evil.example sends an m.typing EDU claiming a user_id on a different domain")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.started = true;
        runtime.federation = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"evil.example"};
        auto const key_id = std::string{"ed25519:auto"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, "typing-spoof-seed"));

        auto request = merovingian::homeserver::LocalHttpRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-typing-spoof";
        request.sig_verified = true;
        request.verified_origin = origin;
        request.verified_key_id = key_id;
        request.body =
            R"({"origin":"evil.example","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.typing","content":{"room_id":"!room:good.example","user_id":"@alice:good.example","typing":true}}]})";

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(runtime, request);

            THEN("the spoofed typing state is not recorded")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.typing_users.empty());
            }
        }
    }
}

// Regression test for #425: room_id/user_id were extracted by scanning the
// raw content JSON for the next '"' rather than parsing it, so a user_id
// containing an escaped quote stopped the scan early and yielded a
// truncated/arbitrary value injected into typing_users.
SCENARIO("Typing EDU parses a user_id containing an escaped quote correctly instead of truncating it",
         "[homeserver][federation][typing][security]")
{
    GIVEN("matrix.example.org sends an m.typing EDU whose user_id contains an escaped quote")
    {
        auto runtime = merovingian::homeserver::HomeserverRuntime{};
        runtime.started = true;
        runtime.federation = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, "typing-quote-seed"));

        auto request = merovingian::homeserver::LocalHttpRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/txn-typing-quote";
        request.sig_verified = true;
        request.verified_origin = origin;
        request.verified_key_id = key_id;
        request.body =
            R"({"origin":"matrix.example.org","origin_server_ts":1000,"pdus":[],"edus":[{"edu_type":"m.typing","content":{"room_id":"!room:matrix.example.org","user_id":"@a\"b:matrix.example.org","typing":true}}]})";

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::homeserver::handle_federation_http_request(runtime, request);

            THEN("the full user_id is recorded, not a truncated prefix")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.typing_users.size() == 1U);
                REQUIRE(runtime.typing_users.front().user_id == R"(@a"b:matrix.example.org)");
                REQUIRE(runtime.typing_users.front().room_id == "!room:matrix.example.org");
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
