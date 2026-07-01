// SPDX-License-Identifier: GPL-3.0-or-later

#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
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

[[nodiscard]] auto signed_request(std::string const& origin, std::string const& key_id, std::string const& key_seed,
                                  std::string const& body) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/txn123";
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

[[nodiscard]] auto pdu_for(std::string const& origin) -> std::string
{
    // A minimal valid JSON request body. The Matrix request-signing scheme
    // embeds the body as a parsed JSON object, so test bodies must be JSON.
    return R"({"origin":")" + origin + R"("})";
}

[[nodiscard]] auto transaction_body(std::string const& origin, std::string const& pdu_json) -> std::string
{
    return std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[)" + pdu_json + "]}";
}

// Builds a transaction body carrying several PDUs, used to exercise the
// parallel inbound sender-key resolution path (multiple relayed senders
// inside one /send transaction).
[[nodiscard]] auto transaction_body_pdus(std::string const& origin, std::vector<std::string> const& pdus) -> std::string
{
    auto joined = std::string{};
    for (auto i = std::size_t{0U}; i < pdus.size(); ++i)
    {
        if (i != 0U)
        {
            joined += ",";
        }
        joined += pdus[i];
    }
    return std::string{"{\"origin\":\""} + origin + R"(","origin_server_ts":1000,"pdus":[)" + joined + "]}";
}

// Shared state for a counting fake RemoteKeyResolver. Tracks how many times
// the resolver was invoked, the peak number of concurrent invocations, and
// optionally stalls each call for `delay` so a parallel fan-out is
// distinguishable from a serial one by wall time. `keys` holds the
// FederationRemoteRuntime to return per (server_name, key_id); a missing
// entry models resolution failure (returns nullopt). `keys` is populated
// before the resolver is ever invoked, so concurrent reads are race-free.
struct CountingResolverState final
{
    std::atomic<std::size_t> calls{0U};
    std::atomic<std::size_t> in_flight{0U};
    std::atomic<std::size_t> peak{0U};
    std::chrono::milliseconds delay{};
    std::map<std::pair<std::string, std::string>, merovingian::federation::FederationRemoteRuntime> keys{};

    // Updates `peak` to track the high-water mark of concurrent invocations.
    auto record_concurrency() -> void
    {
        auto const current = in_flight.fetch_add(1U) + 1U;
        auto prev_peak = peak.load();
        while (current > prev_peak && !peak.compare_exchange_weak(prev_peak, current))
        {
        }
    }
};

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

class FederationTestSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit FederationTestSigningStore(merovingian::crypto::SigningKeyRecord key)
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

class FederationTestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit FederationTestEd25519Provider(std::string key_material)
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

// Injects the real computed content hash so that verify_pdu_content_hash accepts
// the PDU. sign_event_for_server does not compute or inject hashes.
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
    auto const event_json =
        "{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"depth\":1,"
        "\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
        origin + "\",\"type\":\"m.room.message\"}";
    auto const base_parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(base_parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    auto const event_with_hash = with_correct_content_hash(base_parsed.value);
    auto store = FederationTestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = FederationTestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(event_with_hash, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

// Produces a v10 PDU with "origin" as a top-level field, signed with v10
// redaction rules.  v10 preserves "origin" in the signing payload; v11+ strips
// it.  A PDU signed here will only verify correctly when the authorising side
// uses a v10 (or earlier) room-version policy.
[[nodiscard]] auto signed_v10_pdu(std::string const& origin, std::string const& key_id, std::string const& token)
    -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(token, public_key, secret_key));
    // "origin" sits between "hashes" and "origin_server_ts" in canonical order.
    auto const event_json = std::string{"{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},"
                                        "\"depth\":1,\"hashes\":{\"sha256\":\"hash\"},\"origin\":\""} +
                            origin +
                            "\",\"origin_server_ts\":1,\"prev_events\":[],"
                            "\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
                            origin + "\",\"type\":\"m.room.message\"}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("10");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    auto store = FederationTestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = FederationTestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

// ---- auth-event builder helpers (reusable for full-auth scenarios) -----------

[[nodiscard]] auto auth_create_event(std::string_view creator) -> std::string
{
    // v12 create event: no room_id field; room_id is derived from the event hash.
    return "{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\"" + std::string{creator} +
           "\",\"content\":{\"creator\":\"" + std::string{creator} +
           "\",\"room_version\":\"12\"},\"origin_server_ts\":1,\"depth\":0,"
           "\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto auth_power_levels_event(std::string_view sender, std::int64_t users_default,
                                           std::int64_t state_default, std::string_view admin_user,
                                           std::int64_t admin_level) -> std::string
{
    return "{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{"
           "\"ban\":50,\"invite\":50,\"kick\":50,\"redact\":50,"
           "\"users_default\":" +
           std::to_string(users_default) + ",\"state_default\":" + std::to_string(state_default) +
           ",\"events_default\":0,\"users\":{\"" + std::string{admin_user} + "\":" + std::to_string(admin_level) +
           "}},\"origin_server_ts\":2,\"depth\":1,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto auth_member_event(std::string_view sender, std::string_view state_key, std::string_view membership)
    -> std::string
{
    return "{\"type\":\"m.room.member\",\"state_key\":\"" + std::string{state_key} + "\",\"sender\":\"" +
           std::string{sender} + "\",\"room_id\":\"!room:example.org\",\"content\":{\"membership\":\"" +
           std::string{membership} +
           "\"},\"origin_server_ts\":3,\"depth\":2,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto auth_message_event(std::string_view sender) -> std::string
{
    return "{\"type\":\"m.room.message\",\"sender\":\"" + std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{\"body\":\"hello\",\"msgtype\":\"m.text\"},"
           "\"origin_server_ts\":4,\"depth\":3,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto auth_state_event(std::string_view sender, std::string_view type, std::string_view state_key)
    -> std::string
{
    return "{\"type\":\"" + std::string{type} + "\",\"state_key\":\"" + std::string{state_key} + "\",\"sender\":\"" +
           std::string{sender} +
           "\",\"room_id\":\"!room:example.org\",\"content\":{},"
           "\"origin_server_ts\":5,\"depth\":4,\"prev_events\":[],\"auth_events\":[],"
           "\"hashes\":{\"sha256\":\"hash\"}}";
}

[[nodiscard]] auto parse_auth_json(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto const result = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(result.error == merovingian::canonicaljson::ParseError::none);
    return result.value;
}

} // namespace

SCENARIO("Federation signing key summaries never disclose verification material", "[federation][inbound][security]")
{
    GIVEN("loaded key material")
    {
        WHEN("the signing boundary is created and summarized")
        {
            auto const key = merovingian::federation::load_server_signing_key("matrix.example.org", "ed25519:auto",
                                                                              "local-signing-material");
            auto const summary = merovingian::federation::signing_key_summary(key);

            THEN("the key is usable and the summary is redacted")
            {
                REQUIRE(key.loaded);
                REQUIRE(key.server_name == "matrix.example.org");
                REQUIRE(key.key_id == "ed25519:auto");
                REQUIRE_FALSE(key.verify_token.empty());
                REQUIRE(summary.find("matrix.example.org") != std::string::npos);
                REQUIRE(summary.find(key.verify_token) == std::string::npos);
                REQUIRE(summary.find("local-signing-material") == std::string::npos);
            }
        }
    }
}

SCENARIO("Signed federation request verification rejects stale bad mismatched and uncanonical requests",
         "[federation][inbound][security]")
{
    GIVEN("a key record and signed request")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;
        auto expired_key = key;
        expired_key.valid_until_ts = 500U;
        auto valid = signed_request(origin, key_id, token, pdu_for(origin));
        auto mismatched = valid;
        mismatched.origin = "elsewhere.example.org";
        auto bad_signature = valid;
        bad_signature.signature = "sig:v1:wrong";
        auto uncanonical = valid;
        uncanonical.canonical_json_verified = false;

        WHEN("requests are verified against the remote signing key")
        {
            auto const accepted = merovingian::federation::verify_signed_federation_request(valid, key);
            auto const rejected_expired = merovingian::federation::verify_signed_federation_request(valid, expired_key);
            auto const rejected_mismatch = merovingian::federation::verify_signed_federation_request(mismatched, key);
            auto const rejected_bad_signature =
                merovingian::federation::verify_signed_federation_request(bad_signature, key);
            auto const rejected_uncanonical =
                merovingian::federation::verify_signed_federation_request(uncanonical, key);

            THEN("only the valid matching canonical signature from a live key is accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_expired.accepted);
                REQUIRE(rejected_expired.status == 403U);
                REQUIRE(rejected_expired.reason == "request signing key has expired");
                REQUIRE_FALSE(rejected_mismatch.accepted);
                REQUIRE(rejected_mismatch.status == 403U);
                REQUIRE(rejected_mismatch.reason == "request signing key does not match origin");
                REQUIRE_FALSE(rejected_bad_signature.accepted);
                REQUIRE(rejected_bad_signature.status == 403U);
                REQUIRE(rejected_bad_signature.reason == "request signature verification failed");
                REQUIRE_FALSE(rejected_uncanonical.accepted);
                REQUIRE(rejected_uncanonical.reason == "canonical JSON signature verification required");
            }
        }
    }
}

SCENARIO("Inbound federation transaction accepts signed public trusted remotes", "[federation][inbound][transaction]")
{
    GIVEN("a runtime with a known public remote")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto const request = signed_request(origin, key_id, token, transaction_body(origin, json_pdu));

        WHEN("the signed transaction is handled twice")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);
            auto const duplicate = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction is accepted once and retries are idempotent")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
                REQUIRE(duplicate.status == 200U);
                REQUIRE(duplicate.body == R"({"pdus":{}})");
                REQUIRE(runtime.accepted_transactions.size() == 1U);
                REQUIRE(runtime.accepted_transactions.front().transaction_id == "txn123");
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 0U);
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime));
            }
        }
    }
}

SCENARIO("Inbound federation seeds discovery state for remotes resolved on demand",
         "[federation][inbound][transaction]")
{
    GIVEN("an unknown remote with an on-demand resolver that returns a full runtime record")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        runtime.remote_key_resolver =
            [origin, key_id, token](
                std::string_view server_name,
                std::string_view request_key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != origin || request_key_id != key_id)
            {
                return std::nullopt;
            }
            return remote_for(origin, key_id, token);
        };
        auto const json_pdu = signed_json_pdu(origin, key_id, token);
        auto const request = signed_request(origin, key_id, token, transaction_body(origin, json_pdu));

        WHEN("the first signed request from that remote is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolved discovery and signing state allow the transaction")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
                REQUIRE(runtime.remotes.size() == 1U);
                REQUIRE(runtime.remotes.front().discovery.resolved_addresses ==
                        std::vector<std::string>{"203.0.113.10"});
                REQUIRE(runtime.remotes.front().trust.reputation_score == 100U);
            }
        }
    }
}

SCENARIO("Inbound federation handles non-transaction endpoints without PDU validation", "[federation][inbound][routes]")
{
    GIVEN("a runtime with a signed v1 invite request and an invite handler")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        // v1 invite body IS the bare signed event — the handler echoes it
        // back as the response payload. The shape is valid canonical JSON
        // so parse_invite_body succeeds without a v2 envelope.
        auto const invite_event_json = std::string{
            R"({"type":"m.room.member","state_key":"@alice:matrix.example.org","sender":"@alice:matrix.example.org",)"
            R"("room_id":"!room1:example.org","content":{"membership":"invite"}})"};
        auto invite_seen = std::make_shared<bool>(false);
        runtime.invite_handler = [invite_seen](merovingian::federation::InviteRequest const& request) {
            *invite_seen = true;
            auto result = merovingian::federation::InviteAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.signed_event_json = request.invite_event_json;
            return result;
        };
        auto request = signed_request(origin, key_id, token, invite_event_json);
        request.target = "/_matrix/federation/v1/invite/!room1:example.org/$event1:example.org";
        request.signature = merovingian::federation::make_federation_signature(
            origin, request.destination, request.method, request.target, request.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);

        WHEN("the request is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the invite handler runs and produces a 200 response without transaction-validating the body")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*invite_seen);
                REQUIRE(runtime.accepted_transactions.empty());
            }
        }
    }
}

SCENARIO("Inbound federation rejects malformed send targets and unsigned PDUs", "[federation][inbound][security]")
{
    GIVEN("a runtime with malformed transaction requests")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto extra_segment = signed_request(origin, key_id, token, pdu_for(origin));
        extra_segment.target = "/_matrix/federation/v1/send/txn123/extra";
        extra_segment.signature = merovingian::federation::make_federation_signature(
            origin, extra_segment.destination, extra_segment.method, extra_segment.target, extra_segment.body,
            merovingian::federation::test::keypair_from_seed(token).secret_key);
        auto missing_signature =
            signed_request(origin, key_id, token, transaction_body(origin, R"({"type":"m.room.message"})"));

        WHEN("the requests are handled")
        {
            auto const bad_route = merovingian::federation::handle_inbound_federation_request(runtime, extra_segment);
            auto const bad_pdu = merovingian::federation::handle_inbound_federation_request(runtime, missing_signature);

            THEN("extra path segments fail closed with 404")
            {
                REQUIRE(bad_route.status == 404U);
                REQUIRE(bad_route.body == "federation route not found");
            }

            THEN("a PDU with missing required fields returns 200 with a per-PDU error — not 400 for the transaction")
            {
                // Per Matrix federation spec, individual PDU failures must be
                // reported inside {"pdus": {"$id": {"error": "..."}}} at HTTP 200.
                // Returning a non-200 causes the remote to back off all federation.
                REQUIRE(bad_pdu.status == 200U);
                REQUIRE(bad_pdu.body.find("\"pdus\"") != std::string::npos);
                REQUIRE(bad_pdu.body.find("\"error\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Inbound federation fails closed for unknown private denied and quarantined remotes",
         "[federation][inbound][security]")
{
    GIVEN("validly signed requests with failing remote controls")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto const request = signed_request(origin, key_id, token, pdu_for(origin));

        auto unknown_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());

        auto private_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto private_remote = remote_for(origin, key_id, token);
        private_remote.discovery.resolved_addresses = {"127.0.0.1"};
        merovingian::federation::upsert_remote(private_runtime, private_remote);

        auto denied_config = runtime_config();
        denied_config.denied_servers = {origin};
        auto denied_runtime = merovingian::federation::make_federation_runtime_state(denied_config);
        merovingian::federation::upsert_remote(denied_runtime, remote_for(origin, key_id, token));

        auto quarantined_runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto quarantined_remote = remote_for(origin, key_id, token);
        quarantined_remote.trust.quarantined = true;
        merovingian::federation::upsert_remote(quarantined_runtime, quarantined_remote);

        WHEN("each request is handled")
        {
            auto const unknown_response =
                merovingian::federation::handle_inbound_federation_request(unknown_runtime, request);
            auto const private_response =
                merovingian::federation::handle_inbound_federation_request(private_runtime, request);
            auto const denied_response =
                merovingian::federation::handle_inbound_federation_request(denied_runtime, request);
            auto const quarantined_response =
                merovingian::federation::handle_inbound_federation_request(quarantined_runtime, request);

            THEN("all failing controls reject the request")
            {
                REQUIRE(unknown_response.status == 403U);
                REQUIRE(unknown_response.body == "remote is unknown");
                REQUIRE(private_response.status == 403U);
                REQUIRE(private_response.body == "remote address is private or loopback");
                REQUIRE(denied_response.status == 403U);
                REQUIRE(denied_response.body == "remote server is denied");
                REQUIRE(quarantined_response.status == 403U);
                REQUIRE(quarantined_response.body == "remote server is quarantined");
            }
        }
    }
}

SCENARIO("Inbound federation applies backoff and increments failure count", "[federation][inbound][trust]")
{
    GIVEN("a remote with a bad signature and then a backoff state")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto bad_request = signed_request(origin, key_id, token, pdu_for(origin));
        bad_request.signature = "sig:v1:bad";

        WHEN("bad signatures accumulate")
        {
            auto const first = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const second = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const third = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);
            auto const backoff = merovingian::federation::handle_inbound_federation_request(runtime, bad_request);

            THEN("failures are counted and backoff returns 429")
            {
                REQUIRE(first.status == 403U);
                REQUIRE(second.status == 403U);
                REQUIRE(third.status == 403U);
                REQUIRE(runtime.remotes.front().trust.consecutive_failures == 3U);
                REQUIRE(backoff.status == 429U);
                REQUIRE(backoff.body == "remote backoff required");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Section: Signing Events (per-PDU signing)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#signing-events
//
// The sender's homeserver MUST sign every PDU it creates. The transport origin
// (the server making the HTTPS request) MAY be a relay that forwards PDUs on
// behalf of another server. Authorization checks MUST verify that the PDU
// carries a signature from sender_domain(pdu.sender) — not from the transport
// origin — so that relayed/backfilled PDUs are not incorrectly rejected.
SCENARIO("Federation PDU authorization validates the sender server's signature, not the transport origin's",
         "[federation][inbound][pdu][conformance]")
{
    GIVEN("a signed JSON PDU from matrix.example.org and variants that lack a sender-server signature")
    {
        // valid: a real Ed25519-signed PDU authored by matrix.example.org.
        // bad_sender: sender changed to @alice:elsewhere — the PDU still only
        //   carries a signature from matrix.example.org, not elsewhere.example.org.
        // spoofed_sender: sender changed to @alice:matrix.example.org.evil — no
        //   signature from matrix.example.org.evil in the PDU.
        // bad_signature: signature entry changed to elsewhere.example.org — sender
        //   @alice:matrix.example.org now has no signature from matrix.example.org.
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto valid = merovingian::federation::parse_federation_pdu(signed_json_pdu(origin, key_id, token));
        auto bad_sender = valid;
        bad_sender.sender = "@alice:elsewhere.example.org";
        auto spoofed_sender = valid;
        spoofed_sender.sender = "@alice:matrix.example.org.evil";
        auto bad_signature = valid;
        bad_signature.signatures.front().server_name = "elsewhere.example.org";

        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;

        WHEN("the PDUs are authorized with the matrix.example.org signing key")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(valid, origin, key);
            auto const rejected_sender = merovingian::federation::authorize_federation_pdu(bad_sender, origin, key);
            auto const rejected_spoofed_sender =
                merovingian::federation::authorize_federation_pdu(spoofed_sender, origin, key);
            auto const rejected_signature =
                merovingian::federation::authorize_federation_pdu(bad_signature, origin, key);

            THEN("only a PDU whose sender server has signed the event is accepted")
            {
                // Spec MUST: signature from sender_domain(pdu.sender) is required.
                // bad_sender/spoofed_sender/bad_signature: sender domain has no
                // matching signature entry → rejected at the structural signature check.
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected_sender.accepted);
                REQUIRE(rejected_sender.reason == "missing event signature for expected server");
                REQUIRE_FALSE(rejected_spoofed_sender.accepted);
                REQUIRE(rejected_spoofed_sender.reason == "missing event signature for expected server");
                // Spec MUST: missing sender-server signature MUST be rejected.
                REQUIRE_FALSE(rejected_signature.accepted);
                REQUIRE(rejected_signature.reason == "missing event signature for expected server");
            }
        }
    }
}

SCENARIO("Federation PDU authorization fail-closes relayed PDUs whose sender-domain key is unavailable",
         "[federation][inbound][pdu][conformance]")
{
    GIVEN("a JSON PDU authored and signed by alice.example.org but delivered by relay.example.org")
    {
        // The spec allows any server to be the transport origin for a PDU. The event
        // was authored by alice.example.org; relay.example.org is forwarding it. The
        // PDU carries a real Ed25519 signature from alice.example.org.
        auto const event_server = std::string{"alice.example.org"};
        auto const relay_origin = std::string{"relay.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"alice-server-key"};
        auto const pdu = merovingian::federation::parse_federation_pdu(signed_json_pdu(event_server, key_id, token));
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = event_server;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;

        WHEN("the PDU is authorized with the sender domain's signing key")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(pdu, relay_origin, key);

            THEN("the PDU is accepted because alice.example.org's signature verifies")
            {
                // Spec conformance: transport origin != sender_domain is permitted
                // when the sender domain's signature cryptographically verifies.
                REQUIRE(accepted.accepted);
            }
        }

        WHEN("the PDU is authorized with no sender-domain signing key available")
        {
            // Fail-closed (#270): a relayed PDU whose sender-domain key was not
            // resolved MUST be rejected — the signature cannot be verified.
            auto const rejected = merovingian::federation::authorize_federation_pdu(pdu, relay_origin);

            THEN("the PDU is rejected because the sender domain key is unavailable")
            {
                REQUIRE_FALSE(rejected.accepted);
                REQUIRE(rejected.reason == "sender domain signing key unavailable");
            }
        }
    }
}

SCENARIO("Federation transaction handler uses room_version_resolver for PDU authorization",
         "[federation][inbound][pdu][room-version]")
{
    GIVEN("a runtime with a known remote and a room version resolver that returns '12'")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        WHEN("the resolver is set and a valid signed PDU is delivered")
        {
            runtime.room_version_resolver = [](std::string_view) -> std::string {
                return "12";
            };
            auto const json_pdu = signed_json_pdu(origin, key_id, token);
            auto const request = signed_request(origin, key_id, token, transaction_body(origin, json_pdu));
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction is accepted using the resolver-provided room version")
            {
                REQUIRE(response.status == 200U);
            }
        }

        WHEN("the resolver is unset and a valid signed PDU is delivered")
        {
            // No resolver set: fallback to room version "12"
            auto const json_pdu = signed_json_pdu(origin, key_id, token);
            auto const request = signed_request(origin, key_id, token, transaction_body(origin, json_pdu));
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction is accepted using the default room version '12' fallback")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Room Version 10 redactions
// URL:  ../../docs/matrix-v1.18-spec/rooms/v10.md#redactions
//
// Room v1–v10 preserves "origin" as an allowed top-level key in the signing
// payload.  Room v11+ removes it.  When a homeserver uses the wrong (later)
// room-version policy to verify an inbound PDU from an old room, it strips
// "origin" from the canonical signing payload, producing a different hash and
// causing a false-negative signature rejection.  The room_version_resolver MUST
// return the room's actual version so that verification uses matching rules.
SCENARIO("Inbound v10 room PDU with 'origin' field fails verification when room version resolver defaults to v12",
         "[federation][inbound][pdu][room-version]")
{
    GIVEN("a v10 room PDU carrying 'origin', signed with v10 redaction rules")
    {
        auto const origin = std::string{"synapse.example.org"};
        auto const key_id = std::string{"ed25519:a_RXGa"};
        auto const token = std::string{"v10-test-token"};
        auto const pdu_json = signed_v10_pdu(origin, key_id, token);
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;

        WHEN("the PDU is parsed with a resolver returning '10' and then authorized")
        {
            auto const pdu =
                merovingian::federation::parse_federation_pdu(pdu_json, [](std::string_view) -> std::string {
                    return "10";
                });
            auto const decision = merovingian::federation::authorize_federation_pdu(pdu, origin, key);

            THEN("the PDU is accepted because v10 redaction keeps 'origin' in the signing payload")
            {
                REQUIRE(decision.accepted);
            }
        }

        WHEN("the PDU is parsed without a resolver (falls back to '12') and then authorized")
        {
            auto const pdu = merovingian::federation::parse_federation_pdu(pdu_json);
            auto const decision = merovingian::federation::authorize_federation_pdu(pdu, origin, key);

            THEN("the PDU is rejected because v12 redaction strips 'origin', changing the signing hash")
            {
                REQUIRE_FALSE(decision.accepted);
            }
        }
    }
}

SCENARIO("Federation PDU authorization verifies JSON event signatures with the remote signing key",
         "[federation][inbound][pdu][signing]")
{
    GIVEN("a JSON PDU signed with the expected remote key material")
    {
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto const pdu = merovingian::federation::parse_federation_pdu(signed_json_pdu(origin, key_id, token));
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = origin;
        key.key_id = key_id;
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed(token).public_key;
        auto wrong_key = key;
        wrong_key.public_key_bytes = merovingian::federation::test::keypair_from_seed("wrong-token").public_key;

        WHEN("the PDU is authorized with matching and mismatching key material")
        {
            auto const accepted = merovingian::federation::authorize_federation_pdu(pdu, origin, key);
            auto const rejected = merovingian::federation::authorize_federation_pdu(pdu, origin, wrong_key);

            THEN("only the cryptographically verified event is accepted")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected.accepted);
                REQUIRE(rejected.reason == "signature verification failed");
            }
        }
    }
}

SCENARIO("Federation PDU authorization rejects comma-delimited PDUs when a signing key is available",
         "[federation][inbound][pdu][security]")
{
    GIVEN("a comma-delimited PDU without JSON and a signing key record")
    {
        auto const pdu_text =
            std::string{"$event1:example.org,!room1:example.org,m.room.message,@alice:matrix.example.org,"
                        "matrix.example.org,ed25519:auto,c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nz"
                        "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw=="};
        auto const pdu = merovingian::federation::parse_federation_pdu(pdu_text);
        auto key = merovingian::federation::FederationKeyRecord{};
        key.server_name = "matrix.example.org";
        key.key_id = "ed25519:auto";
        key.valid_until_ts = 2000U;
        key.public_key_bytes = merovingian::federation::test::keypair_from_seed("verify-token").public_key;

        WHEN("the comma-delimited PDU is authorized with a key record")
        {
            auto const decision = merovingian::federation::authorize_federation_pdu(pdu, "matrix.example.org", key);

            THEN("the PDU is rejected because legacy format cannot be cryptographically verified")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "comma-delimited PDUs require JSON for cryptographic verification");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Section: Authorization Rules
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#authorization-rules
//
// The old pdu_is_authorized() used a hardcoded room version "12" and a synthetic
// power level {sender=50, required=0}, meaning every PDU with a non-empty type
// passed the check regardless of the room's actual auth state. These scenarios
// exercise authorize_event_against_auth_events() — the correct full Matrix
// event-auth function — to demonstrate that transport-level clearance is
// insufficient and that full event auth against actual room state is required
// before a federated PDU may be persisted.
SCENARIO("Full Matrix event auth rejects PDUs that pass transport checks but violate auth rules",
         "[federation][inbound][security][auth]")
{
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);

    // Common auth-state fixture: @alice:example.org created the room.
    auto base_auth = merovingian::events::AuthEventMap{};
    base_auth.create = parse_auth_json(auth_create_event("@alice:example.org"));
    // Alice is admin (level 100); users_default=0; state_default=50.
    base_auth.power_levels =
        parse_auth_json(auth_power_levels_event("@alice:example.org", 0, 50, "@alice:example.org", 100));
    // Alice is joined.
    base_auth.sender_member = parse_auth_json(auth_member_event("@alice:example.org", "@alice:example.org", "join"));

    GIVEN("a room with alice as admin (power=100) and bob banned")
    {
        auto const bob_ban = parse_auth_json(auth_member_event("@alice:example.org", "@bob:remote.org", "ban"));

        WHEN("alice (power=100) sends a message in a room with events_default=0")
        {
            auto const event = parse_auth_json(auth_message_event("@alice:example.org"));
            auto const decision = merovingian::events::authorize_event_against_auth_events(event, *policy, base_auth);

            THEN("alice's message is allowed because she has sufficient power")
            {
                // Spec MUST: a joined member with power >= events_default MUST be allowed to
                // send message events. Do NOT remove — denying valid events breaks interoperability.
                REQUIRE(decision.allowed);
            }
        }

        WHEN("a banned sender (@bob) attempts to send a state event")
        {
            auto const state_event = parse_auth_json(auth_state_event("@bob:remote.org", "m.room.topic", ""));
            auto auth_for_bob = base_auth;
            // Replace sender_member with bob's ban event.
            auth_for_bob.sender_member = bob_ban;
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(state_event, *policy, auth_for_bob);

            THEN("the event is rejected because banned members cannot send any events")
            {
                // Spec MUST: a banned member MUST NOT be permitted to send any room event.
                // Spec ref: step 4.2.2 of the authorization rules.
                // Do NOT remove — accepting events from banned users is a security bypass.
                REQUIRE_FALSE(decision.allowed);
            }
        }

        WHEN("a message event arrives with no create event in the auth state")
        {
            auto const event = parse_auth_json(auth_message_event("@alice:example.org"));
            auto empty_auth = merovingian::events::AuthEventMap{};
            auto const decision = merovingian::events::authorize_event_against_auth_events(event, *policy, empty_auth);

            THEN("the event is rejected because no create event exists for the room")
            {
                // Spec MUST: all non-create events MUST be rejected when the room has no
                // create event in the auth state. Spec ref: authorization rules step 2.
                // Do NOT remove — this guards against events injected before room genesis.
                REQUIRE_FALSE(decision.allowed);
            }
        }

        WHEN("a non-member (@eve) attempts to invite someone into a non-public room")
        {
            auto const invite = parse_auth_json(auth_member_event("@eve:evil.org", "@carol:example.org", "invite"));
            auto auth_for_eve = base_auth;
            // Eve has no membership entry — she is effectively in state=leave.
            auth_for_eve.sender_member = {};
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(invite, *policy, auth_for_eve);

            THEN("the invite is rejected because only joined members may invite others")
            {
                // Spec MUST: only joined members MUST be allowed to send invite membership
                // events. Spec ref: authorization rules step 4.3.
                // Do NOT remove — allowing invites from non-members is an access control bypass.
                REQUIRE_FALSE(decision.allowed);
            }
        }

        WHEN("a sender with power=0 (users_default) attempts to send a state event with state_default=50")
        {
            // Mallory is joined but has default power (0).
            auto auth_for_mallory = base_auth;
            auth_for_mallory.sender_member =
                parse_auth_json(auth_member_event("@mallory:remote.org", "@mallory:remote.org", "join"));
            auto const state_event = parse_auth_json(auth_state_event("@mallory:remote.org", "m.room.topic", ""));
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(state_event, *policy, auth_for_mallory);

            THEN("the state event is rejected because the sender has insufficient power")
            {
                // Spec MUST: a sender with power < state_default MUST NOT be allowed to send
                // state events. Spec ref: authorization rules step 6 (power level check).
                // Do NOT remove — allowing under-powered state changes breaks room governance.
                REQUIRE_FALSE(decision.allowed);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Signing Events (per-PDU signing)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#signing-events
//
// For relayed PDUs (TLS peer is a relay forwarding on behalf of the true author)
// the verifying server MUST resolve the sender domain's signing key and verify the
// PDU signature against it — not the relay's key, which does not cover the sender's
// signature. If the resolver is wired but fails to produce a key the PDU MUST be
// rejected (fail-closed). If no resolver is wired the behaviour is unchanged
// (structural presence-check only — a known TODO).
SCENARIO("Relayed PDU signature is verified against the sender domain key via the resolver",
         "[federation][inbound][pdu][relay][conformance]")
{
    GIVEN("a PDU authored by alice.example.org but delivered by relay.example.org")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        auto const event_server = std::string{"alice.example.org"};
        auto const event_key_id = std::string{"ed25519:auto"};
        auto const event_token = std::string{"alice-server-key"};
        // relay.example.org is a known trusted remote (provides X-Matrix auth).
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const alice_pdu_json = signed_json_pdu(event_server, event_key_id, event_token);
        // Transaction is signed by relay.example.org; the PDU within was authored
        // and cryptographically signed by alice.example.org.
        auto const request =
            signed_request(relay_origin, relay_key_id, relay_token, transaction_body(relay_origin, alice_pdu_json));

        WHEN("a resolver that successfully resolves alice.example.org's key is wired")
        {
            auto accepted_event_id = std::string{};
            runtime.pdu_sink = [&accepted_event_id](merovingian::federation::InboundPduEnvelope const& env)
                -> merovingian::federation::PduIngestionResult {
                accepted_event_id = env.event_id;
                return {merovingian::federation::PduIngestionStatus::accepted, {}};
            };
            runtime.remote_key_resolver =
                [event_server, event_key_id, event_token](
                    std::string_view server_name,
                    std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != event_server || key_id != event_key_id)
                {
                    return std::nullopt;
                }
                return remote_for(event_server, event_key_id, event_token);
            };

            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the relay's transaction is accepted and the PDU passes sender signature verification")
            {
                // Spec MUST: signature from sender_domain(pdu.sender) MUST be verified.
                // The resolver is called for alice.example.org and the returned key is
                // used to verify alice's PDU signature — not the relay's key.
                REQUIRE(response.status == 200U);
                REQUIRE_FALSE(accepted_event_id.empty());
            }
        }

        WHEN("a resolver that returns the wrong public key for alice.example.org is wired")
        {
            auto sink_called = bool{false};
            runtime.pdu_sink =
                [&sink_called](
                    merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
                sink_called = true;
                return {merovingian::federation::PduIngestionStatus::accepted, {}};
            };
            runtime.remote_key_resolver =
                [event_server, event_key_id](
                    std::string_view server_name,
                    std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                if (server_name != event_server || key_id != event_key_id)
                {
                    return std::nullopt;
                }
                // Return a remote with different key material — wrong public key.
                return remote_for(event_server, event_key_id, "wrong-key-material");
            };

            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the PDU is rejected with a per-PDU error and the sink is never reached")
            {
                // Spec MUST: a PDU whose signature fails Ed25519 verification MUST be rejected.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"error\"") != std::string::npos);
                REQUIRE_FALSE(sink_called);
            }
        }

        WHEN("a resolver that cannot resolve alice.example.org's key is wired")
        {
            auto sink_called = bool{false};
            runtime.pdu_sink =
                [&sink_called](
                    merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
                sink_called = true;
                return {merovingian::federation::PduIngestionStatus::accepted, {}};
            };
            runtime.remote_key_resolver =
                [](std::string_view,
                   std::string_view) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                return std::nullopt; // resolution always fails
            };

            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the PDU is rejected fail-closed and the sink is never reached")
            {
                // Fail-closed: resolver is wired but returned no key → cannot verify
                // sender signature → PDU MUST be rejected, not persisted unverified.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"error\"") != std::string::npos);
                REQUIRE_FALSE(sink_called);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Authorization Rules
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#authorization-rules
//
// The server MUST run event-authorization rules before persisting any inbound PDU.
// A PDU that fails auth MUST NOT be persisted; the pdu_sink MUST return rejected_auth
// so the federation handler audits the rejection without producing a non-200 HTTP
// status that would cause the remote to back off all federation.
SCENARIO("Inbound pdu_sink enforces Matrix event-authorization rules before persisting",
         "[federation][inbound][pdu][auth][conformance]")
{
    GIVEN("a runtime with an auth-enforcing pdu_sink and @alice:remote.org banned in the room")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"remote.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        // Auth state: @admin:example.org created the room; @alice:remote.org is banned.
        auto auth_map = merovingian::events::AuthEventMap{};
        auth_map.create = parse_auth_json(auth_create_event("@admin:example.org"));
        auth_map.power_levels =
            parse_auth_json(auth_power_levels_event("@admin:example.org", 0, 50, "@admin:example.org", 100));
        auth_map.sender_member = parse_auth_json(auth_member_event("@admin:example.org", "@alice:remote.org", "ban"));

        // Mimics the production pdu_sink contract: MUST run authorize_event_against_auth_events
        // before persisting. Banned members MUST be rejected with rejected_auth.
        auto rejection_count = std::size_t{0U};
        auto acceptance_count = std::size_t{0U};
        runtime.pdu_sink =
            [policy, auth_map, &rejection_count, &acceptance_count](
                merovingian::federation::InboundPduEnvelope const& env) -> merovingian::federation::PduIngestionResult {
            auto const pdu_val = merovingian::canonicaljson::parse_lossless(env.json);
            if (pdu_val.error != merovingian::canonicaljson::ParseError::none)
            {
                return {merovingian::federation::PduIngestionStatus::rejected_invalid, "unparseable pdu"};
            }
            auto const decision =
                merovingian::events::authorize_event_against_auth_events(pdu_val.value, *policy, auth_map);
            if (!decision.allowed)
            {
                ++rejection_count;
                return {merovingian::federation::PduIngestionStatus::rejected_auth,
                        "event auth denied: " + decision.reason};
            }
            ++acceptance_count;
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        WHEN("a message PDU from banned @alice:remote.org passes transport-level signature checks")
        {
            // signed_json_pdu("remote.org", ...) creates sender=@alice:remote.org whose
            // transport signature is valid — the PDU passes authorize_federation_pdu.
            auto const pdu_json = signed_json_pdu(origin, key_id, token);
            auto const request = signed_request(origin, key_id, token, transaction_body(origin, pdu_json));
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the transaction returns 200 but the pdu_sink rejects the event as auth-denied")
            {
                // Spec MUST: banned members MUST NOT be permitted to send any room event.
                // The pdu_sink MUST return rejected_auth — this causes the federation handler
                // to audit the rejection without changing the HTTP 200 status, per Matrix /send
                // spec (non-200 causes the remote to back off all federation for that server).
                REQUIRE(response.status == 200U);
                REQUIRE(rejection_count == 1U);
                REQUIRE(acceptance_count == 0U);
            }
        }
    }
}

SCENARIO("Inbound transaction with an unknown EDU type does not invoke the edu_sink", "[federation][inbound][edu]")
{
    GIVEN("a runtime with a known remote and an edu_sink that counts invocations")
    {
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));

        auto edu_count = std::make_shared<std::size_t>(0U);
        runtime.edu_sink = [edu_count]([[maybe_unused]] merovingian::federation::InboundEduEnvelope const& env)
            -> merovingian::federation::EduDispositionResult {
            ++(*edu_count);
            return {merovingian::federation::EduDispositionStatus::accepted, {}};
        };

        WHEN("a transaction containing an unrecognized EDU type is delivered")
        {
            // "org.example.unknown" is not a registered Matrix EDU type; the
            // implementation discards it before forwarding to the sink.
            auto const body = std::string{"{\"origin\":\"matrix.example.org\","
                                          "\"origin_server_ts\":1000,"
                                          "\"pdus\":[],"
                                          "\"edus\":[{\"edu_type\":\"org.example.unknown\","
                                          "\"content\":{\"k\":\"v\"}}]}"};
            auto const request = signed_request(origin, key_id, token, body);
            [[maybe_unused]] auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the edu_sink is never invoked — unknown EDU types are filtered before dispatch")
            {
                REQUIRE(*edu_count == 0U);
            }
        }
    }
}

// #323: the main process verifies the inbound X-Matrix signature itself and
// forwards only the verified identity to the federation worker over the
// authenticated IPC channel. verify_inbound_federation_signature is the
// main-side entry point; handle_inbound_federation_request honours
// signature_verified=true (set by the worker on the trusted path) by skipping
// the crypto check. These scenarios pin both halves of the split.

SCENARIO("verify_inbound_federation_signature accepts a validly signed request and returns the identity",
         "[federation][inbound][security]")
{
    GIVEN("a runtime with a known remote and a validly signed request")
    {
        REQUIRE(sodium_is_ready());
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        auto const request = signed_request(origin, key_id, token, transaction_body(origin, pdu_for(origin)));

        WHEN("the main process verifies the signature before forwarding to the worker")
        {
            auto const result = merovingian::federation::verify_inbound_federation_signature(runtime, request);

            THEN("verification is accepted and the verified peer identity is returned")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.identity.origin == origin);
                REQUIRE(result.identity.key_id == key_id);
            }
        }
    }
}

SCENARIO("verify_inbound_federation_signature rejects a request with a bad signature",
         "[federation][inbound][security]")
{
    GIVEN("a runtime with a known remote and a request signed with the wrong key")
    {
        REQUIRE(sodium_is_ready());
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, "real-key"));
        // Sign with a different key than the one the remote published.
        auto request = signed_request(origin, key_id, "wrong-key", transaction_body(origin, pdu_for(origin)));

        WHEN("the main process verifies the signature")
        {
            auto const result = merovingian::federation::verify_inbound_federation_signature(runtime, request);

            THEN("verification is rejected and an error response is returned (not forwarded to the worker)")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.error.status == 403U);
                REQUIRE(result.identity.origin.empty());
            }
        }
    }
}

SCENARIO("verify_inbound_federation_signature rejects an unknown remote", "[federation][inbound][security]")
{
    GIVEN("a runtime with no resolver and a request from an unknown remote")
    {
        REQUIRE(sodium_is_ready());
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        // No upsert_remote and no remote_key_resolver: the remote is unknown.
        auto const request = signed_request(origin, key_id, token, transaction_body(origin, pdu_for(origin)));

        WHEN("the main process verifies the signature")
        {
            auto const result = merovingian::federation::verify_inbound_federation_signature(runtime, request);

            THEN("verification is rejected with 403 remote-unknown (not forwarded to the worker)")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.error.status == 403U);
            }
        }
    }
}

SCENARIO("A signature_verified request is handled without re-checking the raw signature",
         "[federation][inbound][security]")
{
    // #323 worker-trusted path: when main has already verified and set
    // signature_verified=true, handle_inbound_federation_request skips the
    // crypto check. A request whose raw signature is absent/garbage is still
    // accepted because the verified identity travels over the authenticated
    // IPC channel, not the raw credential.
    GIVEN("a runtime with a known remote and a request marked signature_verified")
    {
        REQUIRE(sodium_is_ready());
        auto runtime = merovingian::federation::make_federation_runtime_state(runtime_config());
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime, remote_for(origin, key_id, token));
        // Build a request with NO valid raw signature, then mark it verified.
        // The PDU is validly signed so Block C returns cleanly; the point is
        // that the garbage request signature does not cause a 403.
        auto request =
            signed_request(origin, key_id, token, transaction_body(origin, signed_json_pdu(origin, key_id, token)));
        request.signature = "not-a-real-signature";
        request.signature_verified = true;

        WHEN("the worker handles the trusted request")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the request is accepted (the raw signature is not re-verified)")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
            }
        }

        AND_WHEN("the same request is handled WITHOUT the trusted flag")
        {
            auto untrusted =
                signed_request(origin, key_id, token, transaction_body(origin, signed_json_pdu(origin, key_id, token)));
            untrusted.signature = "not-a-real-signature";
            // signature_verified defaults to false.
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, untrusted);

            THEN("the bad raw signature is rejected (proving the trusted flag is what skips the check)")
            {
                REQUIRE(response.status == 403U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18 — Signing Events / Transactions
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#signing-events
//
// A relayed /send transaction may carry PDUs authored by many distinct sender
// servers. Resolving each sender-domain signing key serially pays N
// discovery+fetch round-trips; the inbound handler fans the distinct
// (sender_domain, key_id) resolutions out concurrently, capped by
// `join_parallelism`. These scenarios pin the parallel behaviour, the dedup,
// and the fail-closed HTTP-200-with-per-PDU-errors contract.
SCENARIO("Parallel inbound /send resolves distinct relayed sender keys concurrently",
         "[federation][inbound][pdu][parallel][conformance]")
{
    GIVEN("a relayed transaction with four PDUs authored by distinct sender servers")
    {
        auto config = runtime_config();
        config.join_parallelism = 8U;
        auto runtime = merovingian::federation::make_federation_runtime_state(config);

        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const servers =
            std::vector<std::string>{"s1.example.org", "s2.example.org", "s3.example.org", "s4.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const tokens = std::vector<std::string>{"t1", "t2", "t3", "t4"};

        auto state = std::make_shared<CountingResolverState>();
        state->delay = std::chrono::milliseconds(200);
        for (auto i = std::size_t{0U}; i < servers.size(); ++i)
        {
            state->keys[{servers[i], key_id}] = remote_for(servers[i], key_id, tokens[i]);
        }
        runtime.remote_key_resolver = [state](std::string_view server_name, std::string_view request_key_id)
            -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            state->calls.fetch_add(1U);
            state->record_concurrency();
            std::this_thread::sleep_for(state->delay);
            state->in_flight.fetch_sub(1U);
            auto const it = state->keys.find({std::string{server_name}, std::string{request_key_id}});
            if (it == state->keys.end())
            {
                return std::nullopt;
            }
            return it->second;
        };

        auto sink_count = std::atomic<std::size_t>{0U};
        runtime.pdu_sink =
            [&sink_count](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            sink_count.fetch_add(1U);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto pdus_json = std::vector<std::string>{};
        pdus_json.reserve(servers.size());
        for (auto i = std::size_t{0U}; i < servers.size(); ++i)
        {
            pdus_json.push_back(signed_json_pdu(servers[i], key_id, tokens[i]));
        }
        auto const request =
            signed_request(relay_origin, relay_key_id, relay_token, transaction_body_pdus(relay_origin, pdus_json));

        WHEN("the transaction is handled")
        {
            auto const start = std::chrono::steady_clock::now();
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);
            auto const elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

            THEN("all four PDUs are accepted and distinct sender keys are resolved concurrently")
            {
                // Spec MUST: signature from sender_domain(pdu.sender) is verified.
                // Parallel fan-out resolves the four distinct sender keys at once
                // rather than serially — peak concurrency > 1 and wall time is well
                // under the serial N*delay budget (4 * 200ms = 800ms).
                REQUIRE(response.status == 200U);
                REQUIRE(sink_count.load() == servers.size());
                REQUIRE(state->calls.load() == servers.size());
                REQUIRE(state->peak.load() >= 2U);
                REQUIRE(static_cast<std::int64_t>(elapsed_ms) < static_cast<std::int64_t>(servers.size() * 200));
            }
        }
    }
}

SCENARIO("Parallel inbound /send fail-closes relayed PDUs whose key resolution fails with HTTP 200",
         "[federation][inbound][pdu][parallel][security]")
{
    GIVEN("a relayed transaction with one resolvable PDU and one unresolvable PDU")
    {
        auto config = runtime_config();
        config.join_parallelism = 8U;
        auto runtime = merovingian::federation::make_federation_runtime_state(config);

        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const good_server = std::string{"good.example.org"};
        auto const bad_server = std::string{"bad.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const good_token = std::string{"good-token"};

        auto state = std::make_shared<CountingResolverState>();
        state->keys[{good_server, key_id}] = remote_for(good_server, key_id, good_token);
        // bad_server intentionally absent → resolver returns nullopt → fail-closed.
        runtime.remote_key_resolver = [state](std::string_view server_name, std::string_view request_key_id)
            -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            state->calls.fetch_add(1U);
            state->record_concurrency();
            std::this_thread::sleep_for(state->delay);
            state->in_flight.fetch_sub(1U);
            auto const it = state->keys.find({std::string{server_name}, std::string{request_key_id}});
            if (it == state->keys.end())
            {
                return std::nullopt;
            }
            return it->second;
        };

        auto sink_count = std::atomic<std::size_t>{0U};
        runtime.pdu_sink =
            [&sink_count](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            sink_count.fetch_add(1U);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto const good_pdu = signed_json_pdu(good_server, key_id, good_token);
        auto const bad_pdu = signed_json_pdu(bad_server, key_id, "bad-token");
        auto const request = signed_request(relay_origin, relay_key_id, relay_token,
                                            transaction_body_pdus(relay_origin, {good_pdu, bad_pdu}));

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolvable PDU is accepted and the unresolvable PDU is rejected fail-closed at HTTP 200")
            {
                // Spec: /send returns HTTP 200 with per-PDU errors — never 4xx/5xx,
                // or Synapse backs off the whole destination. Fail-closed: a relayed
                // PDU whose sender-domain key cannot be resolved MUST be rejected,
                // not persisted unverified.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"error\"") != std::string::npos);
                REQUIRE(sink_count.load() == 1U);
                REQUIRE(state->calls.load() == 2U);
            }
        }
    }
}

SCENARIO("Parallel inbound /send resolves each distinct sender key once even with duplicate senders",
         "[federation][inbound][pdu][parallel]")
{
    GIVEN("a relayed transaction with two senders each authoring two PDUs")
    {
        auto config = runtime_config();
        config.join_parallelism = 8U;
        auto runtime = merovingian::federation::make_federation_runtime_state(config);

        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const s1 = std::string{"s1.example.org"};
        auto const s2 = std::string{"s2.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const t1 = std::string{"t1"};
        auto const t2 = std::string{"t2"};

        auto state = std::make_shared<CountingResolverState>();
        state->delay = std::chrono::milliseconds(100);
        state->keys[{s1, key_id}] = remote_for(s1, key_id, t1);
        state->keys[{s2, key_id}] = remote_for(s2, key_id, t2);
        runtime.remote_key_resolver = [state](std::string_view server_name, std::string_view request_key_id)
            -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            state->calls.fetch_add(1U);
            state->record_concurrency();
            std::this_thread::sleep_for(state->delay);
            state->in_flight.fetch_sub(1U);
            auto const it = state->keys.find({std::string{server_name}, std::string{request_key_id}});
            if (it == state->keys.end())
            {
                return std::nullopt;
            }
            return it->second;
        };

        auto sink_count = std::atomic<std::size_t>{0U};
        runtime.pdu_sink =
            [&sink_count](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            sink_count.fetch_add(1U);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        // Four PDUs but only two distinct sender domains.
        auto const request = signed_request(
            relay_origin, relay_key_id, relay_token,
            transaction_body_pdus(relay_origin, {signed_json_pdu(s1, key_id, t1), signed_json_pdu(s1, key_id, t1),
                                                 signed_json_pdu(s2, key_id, t2), signed_json_pdu(s2, key_id, t2)}));

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("the resolver runs once per distinct sender domain and every PDU is accepted")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(sink_count.load() == 4U);
                REQUIRE(state->calls.load() == 2U);
            }
        }
    }
}

SCENARIO("Parallel inbound /send with join_parallelism=1 resolves sender keys serially",
         "[federation][inbound][pdu][parallel]")
{
    GIVEN("a relayed transaction with two distinct sender domains and parallelism capped at 1")
    {
        auto config = runtime_config();
        config.join_parallelism = 1U; // serial: only one resolver call in-flight at a time
        auto runtime = merovingian::federation::make_federation_runtime_state(config);

        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const s1 = std::string{"s1.example.org"};
        auto const s2 = std::string{"s2.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const t1 = std::string{"t1"};
        auto const t2 = std::string{"t2"};

        auto state = std::make_shared<CountingResolverState>();
        state->delay = std::chrono::milliseconds(50);
        state->keys[{s1, key_id}] = remote_for(s1, key_id, t1);
        state->keys[{s2, key_id}] = remote_for(s2, key_id, t2);
        runtime.remote_key_resolver = [state](std::string_view server_name, std::string_view request_key_id)
            -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            state->calls.fetch_add(1U);
            state->record_concurrency();
            std::this_thread::sleep_for(state->delay);
            state->in_flight.fetch_sub(1U);
            auto const it = state->keys.find({std::string{server_name}, std::string{request_key_id}});
            if (it == state->keys.end())
            {
                return std::nullopt;
            }
            return it->second;
        };

        auto sink_count = std::atomic<std::size_t>{0U};
        runtime.pdu_sink =
            [&sink_count](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            sink_count.fetch_add(1U);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto const request = signed_request(
            relay_origin, relay_key_id, relay_token,
            transaction_body_pdus(relay_origin, {signed_json_pdu(s1, key_id, t1), signed_json_pdu(s2, key_id, t2)}));

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("both PDUs are accepted and the resolver never ran more than one call concurrently")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(sink_count.load() == 2U);
                REQUIRE(state->calls.load() == 2U);
                // With parallelism=1 the semaphore ensures at most one in-flight
                // resolver call at any moment — peak concurrency must not exceed 1.
                REQUIRE(state->peak.load() <= 1U);
            }
        }
    }
}

SCENARIO("Parallel inbound /send with join_parallelism=0 clamps to 1 and resolves correctly",
         "[federation][inbound][pdu][parallel]")
{
    GIVEN("a relayed transaction with two distinct sender domains and parallelism set to 0 (clamp to 1)")
    {
        auto config = runtime_config();
        config.join_parallelism = 0U; // zero is clamped to 1 in the inbound resolver
        auto runtime = merovingian::federation::make_federation_runtime_state(config);

        auto const relay_origin = std::string{"relay.example.org"};
        auto const relay_key_id = std::string{"ed25519:relay"};
        auto const relay_token = std::string{"relay-server-key"};
        merovingian::federation::upsert_remote(runtime, remote_for(relay_origin, relay_key_id, relay_token));

        auto const s1 = std::string{"s1.example.org"};
        auto const s2 = std::string{"s2.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const t1 = std::string{"tok1"};
        auto const t2 = std::string{"tok2"};

        auto state = std::make_shared<CountingResolverState>();
        state->keys[{s1, key_id}] = remote_for(s1, key_id, t1);
        state->keys[{s2, key_id}] = remote_for(s2, key_id, t2);
        runtime.remote_key_resolver = [state](std::string_view server_name, std::string_view request_key_id)
            -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            state->calls.fetch_add(1U);
            state->record_concurrency();
            state->in_flight.fetch_sub(1U);
            auto const it = state->keys.find({std::string{server_name}, std::string{request_key_id}});
            if (it == state->keys.end())
            {
                return std::nullopt;
            }
            return it->second;
        };

        auto sink_count = std::atomic<std::size_t>{0U};
        runtime.pdu_sink =
            [&sink_count](
                merovingian::federation::InboundPduEnvelope const&) -> merovingian::federation::PduIngestionResult {
            sink_count.fetch_add(1U);
            return {merovingian::federation::PduIngestionStatus::accepted, {}};
        };

        auto const request = signed_request(
            relay_origin, relay_key_id, relay_token,
            transaction_body_pdus(relay_origin, {signed_json_pdu(s1, key_id, t1), signed_json_pdu(s2, key_id, t2)}));

        WHEN("the transaction is handled")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime, request);

            THEN("both PDUs are accepted — join_parallelism=0 is clamped to 1 and resolves all senders")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(sink_count.load() == 2U);
                REQUIRE(state->calls.load() == 2U);
            }
        }
    }
}
