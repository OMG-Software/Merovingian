// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/inbound_request.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <sodium.h>

namespace merovingian::federation
{
namespace
{

    auto constexpr clock_skew_seconds = std::uint64_t{300U};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    auto derive_federation_keypair(std::string_view key_material,
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

    [[nodiscard]] auto federation_request_payload(std::string_view origin, std::string_view method,
                                                  std::string_view target, std::uint64_t origin_server_ts,
                                                  std::string_view body) -> std::optional<std::string>
    {
        auto object = canonicaljson::Object{};
        object.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{origin}}));
        object.push_back(canonicaljson::make_member("method", canonicaljson::Value{std::string{method}}));
        object.push_back(canonicaljson::make_member("uri", canonicaljson::Value{std::string{target}}));
        object.push_back(canonicaljson::make_member("origin_server_ts",
                                                    canonicaljson::Value{static_cast<std::int64_t>(origin_server_ts)}));
        object.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::string{body}}));
        auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(object)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    [[nodiscard]] auto split_fields(std::string_view input, char separator) -> std::vector<std::string>
    {
        auto fields = std::vector<std::string>{};
        while (!input.empty())
        {
            auto const position = input.find(separator);
            auto const field = input.substr(0U, position);
            fields.emplace_back(field);
            if (position == std::string_view::npos)
            {
                break;
            }
            input = input.substr(position + 1U);
        }
        return fields;
    }

    [[nodiscard]] auto find_remote(FederationRuntimeState& runtime, std::string_view server_name)
        -> FederationRemoteRuntime*
    {
        auto const iterator =
            std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
                return remote.server_name == server_name;
            });
        return iterator == runtime.remotes.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto find_remote(FederationRuntimeState const& runtime, std::string_view server_name)
        -> FederationRemoteRuntime const*
    {
        auto const iterator =
            std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
                return remote.server_name == server_name;
            });
        return iterator == runtime.remotes.end() ? nullptr : &(*iterator);
    }

    [[nodiscard]] auto make_decision(bool accepted, std::uint16_t status, std::string reason) -> FederationDecision
    {
        return {accepted, status, std::move(reason)};
    }

    [[nodiscard]] auto sender_domain(std::string_view sender) noexcept -> std::string_view
    {
        auto const colon = sender.rfind(':');
        if (colon == std::string_view::npos || colon + 1U >= sender.size())
        {
            return {};
        }
        return sender.substr(colon + 1U);
    }

    [[nodiscard]] auto transaction_id_from_send_target(std::string_view target) -> std::string
    {
        auto constexpr prefix = std::string_view{"/_matrix/federation/v1/send/"};
        if (target.size() <= prefix.size() || target.substr(0U, prefix.size()) != prefix)
        {
            return {};
        }
        auto const transaction_id = target.substr(prefix.size());
        return transaction_id.find('/') == std::string_view::npos ? std::string{transaction_id} : std::string{};
    }

    [[nodiscard]] auto transaction_already_accepted(FederationRuntimeState const& runtime, std::string_view origin,
                                                    std::string_view transaction_id) noexcept -> bool
    {
        return std::ranges::any_of(runtime.accepted_transactions,
                                   [origin, transaction_id](FederationAcceptedTransaction const& accepted) {
                                       return accepted.origin == origin && accepted.transaction_id == transaction_id;
                                   });
    }

    auto audit_federation(FederationRuntimeState& runtime, std::string_view event_type, std::string_view origin,
                          std::string_view target, std::string_view reason) -> void
    {
        runtime.audit_events.push_back(observability::make_audit_event(observability::AuditCategory::policy, event_type,
                                                                       origin, target, reason, "federation"));
    }

    struct ParsedTransactionBody final
    {
        std::vector<std::string> pdus{};
        std::vector<std::pair<std::string, std::string>> edus{}; // (edu_type, content_json)
    };

    [[nodiscard]] auto serialize_canonical_value(canonicaljson::Value const& value) -> std::string
    {
        auto const serialized = canonicaljson::serialize_canonical(value);
        return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
    }

    [[nodiscard]] auto find_canonical_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto parse_transaction_body(std::string_view body) -> ParsedTransactionBody
    {
        // JSON-shaped Matrix transaction body: { "pdus": [...], "edus": [...] }.
        // A JSON object without a top-level "pdus" key is treated as a single
        // PDU envelope so existing test fixtures that submit one PDU per
        // request continue to work.
        if (!body.empty() && body.front() == '{')
        {
            auto const parsed = canonicaljson::parse_lossless(body);
            if (parsed.error == canonicaljson::ParseError::none)
            {
                auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
                if (root != nullptr)
                {
                    auto const* pdus_value = find_canonical_member(*root, "pdus");
                    auto const* edus_value = find_canonical_member(*root, "edus");
                    if (pdus_value != nullptr || edus_value != nullptr)
                    {
                        auto parsed_body = ParsedTransactionBody{};
                        if (auto const* pdus_array = pdus_value == nullptr
                                                         ? nullptr
                                                         : std::get_if<canonicaljson::Array>(&pdus_value->storage());
                            pdus_array != nullptr)
                        {
                            for (auto const& pdu_value : *pdus_array)
                            {
                                if (auto serialized = serialize_canonical_value(pdu_value); !serialized.empty())
                                {
                                    parsed_body.pdus.push_back(std::move(serialized));
                                }
                            }
                        }
                        if (auto const* edus_array = edus_value == nullptr
                                                         ? nullptr
                                                         : std::get_if<canonicaljson::Array>(&edus_value->storage());
                            edus_array != nullptr)
                        {
                            for (auto const& edu_value : *edus_array)
                            {
                                auto const* edu_object = std::get_if<canonicaljson::Object>(&edu_value.storage());
                                if (edu_object == nullptr)
                                {
                                    continue;
                                }
                                auto const* type_value = find_canonical_member(*edu_object, "edu_type");
                                auto const* content_value = find_canonical_member(*edu_object, "content");
                                if (type_value == nullptr || content_value == nullptr)
                                {
                                    continue;
                                }
                                auto const* type_text = std::get_if<std::string>(&type_value->storage());
                                if (type_text == nullptr)
                                {
                                    continue;
                                }
                                auto content_canonical = serialize_canonical_value(*content_value);
                                if (content_canonical.empty())
                                {
                                    continue;
                                }
                                parsed_body.edus.emplace_back(*type_text, std::move(content_canonical));
                            }
                        }
                        return parsed_body;
                    }
                    // JSON object without pdus/edus envelope keys: treat as a
                    // single PDU body (one-event-per-request fixture).
                    auto single_pdu = ParsedTransactionBody{};
                    single_pdu.pdus.emplace_back(body);
                    return single_pdu;
                }
            }
        }

        // Legacy split: body is one or more semicolon-delimited PDUs with no
        // EDUs. Kept for compatibility with internal test fixtures and
        // existing inbound handler regression coverage.
        auto legacy = ParsedTransactionBody{};
        for (auto& field : split_fields(body, ';'))
        {
            if (!field.empty())
            {
                legacy.pdus.push_back(std::move(field));
            }
        }
        return legacy;
    }

    [[nodiscard]] auto pdu_is_authorized(FederationPdu const& pdu) -> bool
    {
        auto const* room_version = rooms::find_room_version_policy("12");
        if (room_version == nullptr)
        {
            return false;
        }
        auto request = events::EventAuthorizationRequest{};
        request.room_version = "12";
        request.event_type = pdu.event_type;
        request.sender = pdu.sender;
        request.power_level = {50, 0};
        auto const decision = events::authorize_event(*room_version, request);
        return decision.allowed;
    }

    class FederationEd25519Verifier final : public crypto::Ed25519Provider
    {
    public:
        [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const&, std::string_view)
            -> crypto::SignatureResult override
        {
            return {{}, "federation verifier does not sign"};
        }

        [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                                  crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override
        {
            if (!crypto::ed25519_public_key_shape_is_valid(public_key) ||
                !crypto::ed25519_signature_shape_is_valid(signature))
            {
                return {false, "invalid Ed25519 material"};
            }
            auto const ok =
                crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.bytes.data()),
                                            reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                            reinterpret_cast<unsigned char const*>(public_key.bytes.data())) == 0;
            return {ok, ok ? std::string{} : std::string{"signature verification failed"}};
        }
    };

} // namespace

auto resolve_federation_public_key(FederationKeyRecord const& key) -> std::string
{
    if (!key.public_key_bytes.empty())
    {
        return key.public_key_bytes;
    }
    if (key.verify_token.empty() || sodium_init() < 0)
    {
        return {};
    }
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    if (crypto_generichash(seed.data(), seed.size(),
                           reinterpret_cast<unsigned char const*>(key.verify_token.data()), key.verify_token.size(),
                           nullptr, 0U) != 0)
    {
        return {};
    }
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    if (crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data()) != 0)
    {
        return {};
    }
    return std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()};
}

auto load_server_signing_key(std::string_view server_name, std::string_view key_id, std::string_view key_material)
    -> FederationSigningKey
{
    if (!server_name_is_valid(server_name) || key_id.empty() || key_material.empty())
    {
        return {};
    }
    return {std::string{server_name}, std::string{key_id}, std::string{key_material}, true};
}

auto signing_key_summary(FederationSigningKey const& key) -> std::string
{
    return "server=" + key.server_name + " key_id=" + key.key_id +
           " loaded=" + std::string{key.loaded ? "true" : "false"};
}

auto make_federation_signature(std::string_view origin, std::string_view /*key_id*/, std::string_view verify_token,
                               std::string_view method, std::string_view target, std::uint64_t origin_server_ts,
                               std::string_view body) -> std::string
{
    auto const payload = federation_request_payload(origin, method, target, origin_server_ts, body);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    if (!payload.has_value() || !derive_federation_keypair(verify_token, public_key, secret_key))
    {
        return {};
    }
    auto signature = std::string(crypto_sign_BYTES, '\0');
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                             reinterpret_cast<unsigned char const*>(payload->data()), payload->size(),
                             secret_key.data()) != 0)
    {
        return {};
    }
    return events::matrix_base64_from_bytes(signature);
}

auto verify_signed_federation_request(SignedFederationRequest const& request, FederationKeyRecord const& key,
                                      std::uint64_t max_clock_skew_seconds) -> FederationDecision
{
    if (request.origin != key.server_name || request.key_id != key.key_id)
    {
        return make_decision(false, 401U, "request signing key does not match origin");
    }
    if (request.now_ts > key.valid_until_ts)
    {
        return make_decision(false, 401U, "request signing key has expired");
    }
    auto const lower_bound = request.now_ts > max_clock_skew_seconds ? request.now_ts - max_clock_skew_seconds : 0U;
    auto const upper_bound = request.now_ts + max_clock_skew_seconds;
    if (request.origin_server_ts < lower_bound || request.origin_server_ts > upper_bound)
    {
        return make_decision(false, 401U, "request timestamp outside allowed bounds");
    }
    auto const payload = federation_request_payload(request.origin, request.method, request.target,
                                                    request.origin_server_ts, request.body);
    auto const signature = events::matrix_bytes_from_base64(request.signature);
    auto const public_key = resolve_federation_public_key(key);
    if (!payload.has_value() || !crypto::ed25519_signature_shape_is_valid(crypto::Ed25519Signature{signature}) ||
        !crypto::ed25519_public_key_shape_is_valid(crypto::Ed25519PublicKey{public_key}) ||
        crypto_sign_verify_detached(reinterpret_cast<unsigned char const*>(signature.data()),
                                    reinterpret_cast<unsigned char const*>(payload->data()), payload->size(),
                                    reinterpret_cast<unsigned char const*>(public_key.data())) != 0)
    {
        return make_decision(false, 401U, "request signature verification failed");
    }
    auto const boundary = verify_federation_request_signature(
        {request.origin, request.key_id, request.signature, request.canonical_json_verified});
    if (!boundary.accepted)
    {
        return make_decision(false, 401U, boundary.reason);
    }
    return make_decision(true, 200U, {});
}

auto make_federation_runtime_state(RuntimeFederationConfig config) -> FederationRuntimeState
{
    return {std::move(config), {}, {}, {}};
}

auto upsert_remote(FederationRuntimeState& runtime, FederationRemoteRuntime remote) -> void
{
    auto* existing = find_remote(runtime, remote.server_name);
    if (existing != nullptr)
    {
        *existing = std::move(remote);
        return;
    }
    runtime.remotes.push_back(std::move(remote));
}

auto federation_remote_is_known(FederationRuntimeState const& runtime, std::string_view server_name) noexcept -> bool
{
    return find_remote(runtime, server_name) != nullptr;
}

auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin) -> FederationDecision
{
    return authorize_federation_pdu(pdu, expected_origin, std::nullopt);
}

auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                              std::optional<FederationKeyRecord> const& key) -> FederationDecision
{
    if (pdu.event_id.empty() || pdu.room_id.empty() || pdu.event_type.empty() || pdu.sender.empty())
    {
        return make_decision(false, 400U, "PDU is missing required fields");
    }
    if (sender_domain(pdu.sender) != expected_origin)
    {
        return make_decision(false, 403U, "PDU sender does not match origin");
    }
    auto const signature = verify_federation_event_signatures(pdu.signatures, expected_origin);
    if (!signature.accepted)
    {
        return make_decision(false, 403U, signature.reason);
    }
    if (key.has_value())
    {
        auto const* room_version = rooms::find_room_version_policy("12");
        if (room_version == nullptr)
        {
            return make_decision(false, 500U, "room version policy is unavailable");
        }
        if (!pdu.json.empty())
        {
            auto const parsed = canonicaljson::parse_lossless(pdu.json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return make_decision(false, 400U, "PDU JSON is not canonical-parseable");
            }
            auto const public_key = resolve_federation_public_key(*key);
            auto verifier = FederationEd25519Verifier{};
            auto const verified =
                events::verify_event_signature(parsed.value, *room_version, {std::string{expected_origin}, key->key_id},
                                               crypto::Ed25519PublicKey{public_key}, verifier);
            if (!verified.valid)
            {
                return make_decision(false, 403U, verified.error);
            }
        }
        else
        {
            return make_decision(false, 400U, "comma-delimited PDUs require JSON for cryptographic verification");
        }
    }
    if (!pdu_is_authorized(pdu))
    {
        return make_decision(false, 403U, "PDU failed event authorization");
    }
    return make_decision(true, 200U, {});
}

auto parse_federation_pdu(std::string_view encoded) -> FederationPdu
{
    if (!encoded.empty() && encoded.front() == '{')
    {
        auto const parsed = canonicaljson::parse_lossless(encoded);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto const envelope = events::parse_event_envelope(parsed.value);
        if (!envelope.error.empty())
        {
            return {};
        }
        auto const* room_version = rooms::find_room_version_policy("12");
        if (room_version == nullptr)
        {
            return {};
        }
        auto id = events::make_reference_hash_event_id(parsed.value, *room_version);
        return {id.event_id,           envelope.event.room_id,    envelope.event.event_type,
                envelope.event.sender, envelope.event.signatures, std::string{encoded}};
    }
    auto const fields = split_fields(encoded, ',');
    if (fields.size() != 7U || fields[6].empty())
    {
        return {};
    }
    return {fields[0], fields[1], fields[2], fields[3], {{fields[4], fields[5], fields[6]}}, {}};
}

auto handle_inbound_federation_request(FederationRuntimeState& runtime, SignedFederationRequest const& request)
    -> FederationResponse
{
    auto const route_match = match_federation_route(request.method, request.target);
    if (!route_match.matched)
    {
        return {404U, route_match.reason};
    }
    auto const server_policy = federation_server_policy(runtime.config, request.origin);
    if (!server_policy.allowed)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, server_policy.reason);
        return {403U, server_policy.reason};
    }
    auto* remote = find_remote(runtime, request.origin);
    if (remote == nullptr && runtime.remote_key_resolver)
    {
        // Unknown remote: try the injected resolver to discover, fetch, and
        // verify the remote's published signing keys. The resolver caches
        // through the persistent store, so subsequent requests see the new
        // record without another network round-trip.
        auto resolved = runtime.remote_key_resolver(request.origin, request.key_id);
        if (resolved.has_value())
        {
            auto new_remote = FederationRemoteRuntime{};
            new_remote.server_name = std::string{request.origin};
            new_remote.signing_key = std::move(*resolved);
            upsert_remote(runtime, std::move(new_remote));
            remote = find_remote(runtime, request.origin);
        }
    }
    if (remote == nullptr)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, "remote is unknown");
        return {403U, "remote is unknown"};
    }
    // Known remote, but the cached key doesn't match the request key_id or
    // has expired: try the resolver to refresh before falling back to the
    // stored record. Federation peers rotate keys, so the cache must follow.
    auto const cached_key_id_mismatches = remote->signing_key.key_id != request.key_id;
    auto const cached_key_expired =
        remote->signing_key.valid_until_ts != 0U && request.now_ts >= remote->signing_key.valid_until_ts;
    if (runtime.remote_key_resolver && (cached_key_id_mismatches || cached_key_expired))
    {
        auto refreshed = runtime.remote_key_resolver(request.origin, request.key_id);
        if (refreshed.has_value())
        {
            remote->signing_key = std::move(*refreshed);
        }
    }
    auto const discovery = federation_discovery_policy(remote->discovery);
    if (!discovery.accepted)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, discovery.reason);
        return {403U, discovery.reason};
    }
    auto const trust = remote_trust_policy(remote->trust);
    if (!trust.accepted)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, trust.reason);
        auto const status = static_cast<std::uint16_t>(trust.apply_backoff ? 429U : 403U);
        return {status, trust.reason};
    }
    auto const request_signature = verify_signed_federation_request(request, remote->signing_key, clock_skew_seconds);
    if (!request_signature.accepted)
    {
        ++remote->trust.consecutive_failures;
        audit_federation(runtime, "federation.rejected", request.origin, request.target, request_signature.reason);
        return {request_signature.status, request_signature.reason};
    }
    if (route_match.route.endpoint != FederationEndpoint::transaction)
    {
        remote->trust.consecutive_failures = 0U;
        audit_federation(runtime, "federation.accepted", request.origin, request.target,
                         federation_route_audit_event(route_match.route, request.origin));
        return {200U, "accepted endpoint=" + std::string{federation_endpoint_name(route_match.route.endpoint)}};
    }

    auto const parsed_body = parse_transaction_body(request.body);
    auto transaction = FederationTransaction{};
    transaction.origin = request.origin;
    transaction.transaction_id = transaction_id_from_send_target(request.target);
    transaction.byte_size = request.body.size();
    transaction.pdus = parsed_body.pdus;
    for (auto const& [edu_type, edu_content] : parsed_body.edus)
    {
        transaction.edus.push_back(edu_type);
    }
    auto const transaction_decision =
        validate_federation_transaction(transaction, runtime.config.max_transaction_bytes);
    if (!transaction_decision.accepted)
    {
        ++remote->trust.consecutive_failures;
        audit_federation(runtime, "federation.rejected", request.origin, request.target, transaction_decision.reason);
        return {400U, transaction_decision.reason};
    }
    if (transaction_already_accepted(runtime, request.origin, transaction.transaction_id))
    {
        remote->trust.consecutive_failures = 0U;
        audit_federation(runtime, "federation.duplicate", request.origin, request.target,
                         "transaction already accepted");
        return {200U, "duplicate transaction accepted"};
    }
    auto pdus_appended = std::size_t{0U};
    auto pdus_state_conflict = std::size_t{0U};
    for (auto const& encoded_pdu : transaction.pdus)
    {
        auto const pdu = parse_federation_pdu(encoded_pdu);
        auto const pdu_decision = authorize_federation_pdu(pdu, request.origin, remote->signing_key);
        if (!pdu_decision.accepted)
        {
            ++remote->trust.consecutive_failures;
            audit_federation(runtime, "federation.rejected", request.origin, request.target, pdu_decision.reason);
            return {pdu_decision.status, pdu_decision.reason};
        }
        if (!runtime.pdu_sink)
        {
            continue;
        }
        // PDU passed signature and auth checks; hand it to the ingestion
        // sink for persistence. State-resolution conflicts log a structured
        // warning and DO NOT abort the transaction — the Matrix spec requires
        // that we accept the request and resolve state in a later pass.
        auto envelope = parse_inbound_pdu_envelope(encoded_pdu);
        if (!envelope.has_value())
        {
            audit_federation(runtime, "federation.pdu_envelope_unparseable", request.origin, request.target,
                             "ingestion-skip");
            continue;
        }
        auto const ingestion = runtime.pdu_sink(*envelope);
        switch (ingestion.status)
        {
        case PduIngestionStatus::accepted:
            ++pdus_appended;
            break;
        case PduIngestionStatus::rejected_state_conflict:
            ++pdus_state_conflict;
            audit_federation(runtime, "federation.pdu_state_conflict", request.origin, request.target,
                             ingestion.reason);
            break;
        case PduIngestionStatus::rejected_auth:
            audit_federation(runtime, "federation.pdu_rejected_auth", request.origin, request.target,
                             ingestion.reason);
            break;
        case PduIngestionStatus::rejected_invalid:
            audit_federation(runtime, "federation.pdu_rejected_invalid", request.origin, request.target,
                             ingestion.reason);
            break;
        case PduIngestionStatus::internal_error:
            audit_federation(runtime, "federation.pdu_internal_error", request.origin, request.target,
                             ingestion.reason);
            break;
        }
    }

    auto edus_dispatched = std::size_t{0U};
    auto edus_dropped = std::size_t{0U};
    for (auto const& [edu_type, edu_content] : parsed_body.edus)
    {
        auto envelope = parse_inbound_edu_envelope(edu_type, request.origin, edu_content);
        if (!envelope.has_value())
        {
            ++edus_dropped;
            continue;
        }
        if (!runtime.edu_sink)
        {
            ++edus_dispatched;
            continue;
        }
        auto const disposition = runtime.edu_sink(*envelope);
        if (disposition.status == EduDispositionStatus::accepted)
        {
            ++edus_dispatched;
        }
        else
        {
            ++edus_dropped;
        }
    }

    remote->trust.consecutive_failures = 0U;
    runtime.accepted_transactions.push_back(
        {request.origin, transaction.transaction_id, transaction.pdus.size(), transaction.edus.size()});
    audit_federation(runtime, "federation.accepted", request.origin, request.target,
                     federation_route_audit_event(route_match.route, request.origin));
    if (!runtime.pdu_sink && !runtime.edu_sink && transaction.edus.empty())
    {
        return {200U, "accepted pdus=" + std::to_string(transaction.pdus.size())};
    }
    auto detail = "accepted pdus=" + std::to_string(transaction.pdus.size()) +
                  " appended=" + std::to_string(pdus_appended) +
                  " state_conflicts=" + std::to_string(pdus_state_conflict) +
                  " edus=" + std::to_string(transaction.edus.size()) +
                  " edus_dispatched=" + std::to_string(edus_dispatched) +
                  " edus_dropped=" + std::to_string(edus_dropped);
    return {200U, std::move(detail)};
}

auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string
{
    return "Federation runtime remotes=" + std::to_string(runtime.remotes.size()) +
           " accepted_transactions=" + std::to_string(runtime.accepted_transactions.size()) +
           " audit_events=" + std::to_string(runtime.audit_events.size());
}

auto federation_audit_is_safe(FederationRuntimeState const& runtime) noexcept -> bool
{
    return std::ranges::all_of(runtime.audit_events, [](observability::AuditLogEvent const& event) {
        return event.reason_code.find("sig:v1:") == std::string::npos &&
               event.reason_code.find("verify_token") == std::string::npos;
    });
}

} // namespace merovingian::federation
