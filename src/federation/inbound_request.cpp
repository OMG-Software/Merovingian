// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/federation/inbound_request.hpp>

#include <merovingian/events/authorization.hpp>
#include <merovingian/rooms/room_version_policy.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{
namespace
{

auto constexpr clock_skew_seconds = std::uint64_t{300U};

[[nodiscard]] auto stable_hash(std::string_view value) noexcept -> std::uint64_t
{
    auto hash = std::uint64_t{1469598103934665603ULL};
    for (auto const character : value)
    {
        hash ^= static_cast<unsigned char>(character);
        hash *= std::uint64_t{1099511628211ULL};
    }
    return hash;
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

[[nodiscard]] auto find_remote(FederationRuntimeState& runtime, std::string_view server_name) -> FederationRemoteRuntime*
{
    auto const iterator = std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
        return remote.server_name == server_name;
    });
    return iterator == runtime.remotes.end() ? nullptr : &(*iterator);
}

[[nodiscard]] auto find_remote(FederationRuntimeState const& runtime, std::string_view server_name) -> FederationRemoteRuntime const*
{
    auto const iterator = std::ranges::find_if(runtime.remotes, [server_name](FederationRemoteRuntime const& remote) {
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

[[nodiscard]] auto transaction_already_accepted(
    FederationRuntimeState const& runtime,
    std::string_view origin,
    std::string_view transaction_id
) noexcept -> bool
{
    return std::ranges::any_of(runtime.accepted_transactions, [origin, transaction_id](FederationAcceptedTransaction const& accepted) {
        return accepted.origin == origin && accepted.transaction_id == transaction_id;
    });
}

auto audit_federation(FederationRuntimeState& runtime, std::string_view event_type, std::string_view origin, std::string_view target, std::string_view reason) -> void
{
    runtime.audit_events.push_back(observability::make_audit_event(
        observability::AuditCategory::policy,
        event_type,
        origin,
        target,
        reason,
        "federation"
    ));
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

} // namespace

auto load_server_signing_key(std::string_view server_name, std::string_view key_id, std::string_view key_material)
    -> FederationSigningKey
{
    if (!server_name_is_valid(server_name) || key_id.empty() || key_material.empty())
    {
        return {};
    }
    return {std::string{server_name}, std::string{key_id}, std::to_string(stable_hash(key_material)), true};
}

auto signing_key_summary(FederationSigningKey const& key) -> std::string
{
    return "server=" + key.server_name + " key_id=" + key.key_id + " loaded=" + std::string{key.loaded ? "true" : "false"};
}

auto make_federation_signature(
    std::string_view origin,
    std::string_view key_id,
    std::string_view verify_token,
    std::string_view method,
    std::string_view target,
    std::uint64_t origin_server_ts,
    std::string_view body
) -> std::string
{
    auto const material = std::string{origin} + "|" + std::string{key_id} + "|" + std::string{verify_token} + "|"
        + std::string{method} + "|" + std::string{target} + "|" + std::to_string(origin_server_ts) + "|" + std::string{body};
    return "sig:v1:" + std::to_string(stable_hash(material));
}

auto verify_signed_federation_request(
    SignedFederationRequest const& request,
    FederationKeyRecord const& key,
    std::uint64_t max_clock_skew_seconds
) -> FederationDecision
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
    auto const expected = make_federation_signature(
        request.origin,
        request.key_id,
        key.verify_token,
        request.method,
        request.target,
        request.origin_server_ts,
        request.body
    );
    if (request.signature != expected)
    {
        return make_decision(false, 401U, "request signature verification failed");
    }
    auto const boundary = verify_federation_request_signature({request.origin, request.key_id, request.signature, request.canonical_json_verified});
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
    if (!pdu_is_authorized(pdu))
    {
        return make_decision(false, 403U, "PDU failed event authorization");
    }
    return make_decision(true, 200U, {});
}

auto parse_federation_pdu(std::string_view encoded) -> FederationPdu
{
    auto const fields = split_fields(encoded, ',');
    if (fields.size() != 7U || fields[6].empty())
    {
        return {};
    }
    return {fields[0], fields[1], fields[2], fields[3], {{fields[4], fields[5], fields[6]}}};
}

auto handle_inbound_federation_request(
    FederationRuntimeState& runtime,
    SignedFederationRequest const& request
) -> FederationResponse
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
    if (remote == nullptr)
    {
        audit_federation(runtime, "federation.rejected", request.origin, request.target, "remote is unknown");
        return {403U, "remote is unknown"};
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
        audit_federation(runtime, "federation.accepted", request.origin, request.target, federation_route_audit_event(route_match.route, request.origin));
        return {200U, "accepted endpoint=" + std::string{federation_endpoint_name(route_match.route.endpoint)}};
    }

    auto transaction = FederationTransaction{};
    transaction.origin = request.origin;
    transaction.transaction_id = transaction_id_from_send_target(request.target);
    transaction.byte_size = request.body.size();
    auto const encoded_pdus = split_fields(request.body, ';');
    for (auto const& encoded_pdu : encoded_pdus)
    {
        if (!encoded_pdu.empty())
        {
            transaction.pdus.push_back(encoded_pdu);
        }
    }
    auto const transaction_decision = validate_federation_transaction(transaction, runtime.config.max_transaction_bytes);
    if (!transaction_decision.accepted)
    {
        ++remote->trust.consecutive_failures;
        audit_federation(runtime, "federation.rejected", request.origin, request.target, transaction_decision.reason);
        return {400U, transaction_decision.reason};
    }
    if (transaction_already_accepted(runtime, request.origin, transaction.transaction_id))
    {
        remote->trust.consecutive_failures = 0U;
        audit_federation(runtime, "federation.duplicate", request.origin, request.target, "transaction already accepted");
        return {200U, "duplicate transaction accepted"};
    }
    for (auto const& encoded_pdu : transaction.pdus)
    {
        auto const pdu = parse_federation_pdu(encoded_pdu);
        auto const pdu_decision = authorize_federation_pdu(pdu, request.origin);
        if (!pdu_decision.accepted)
        {
            ++remote->trust.consecutive_failures;
            audit_federation(runtime, "federation.rejected", request.origin, request.target, pdu_decision.reason);
            return {pdu_decision.status, pdu_decision.reason};
        }
    }
    remote->trust.consecutive_failures = 0U;
    runtime.accepted_transactions.push_back({request.origin, transaction.transaction_id, transaction.pdus.size(), transaction.edus.size()});
    audit_federation(runtime, "federation.accepted", request.origin, request.target, federation_route_audit_event(route_match.route, request.origin));
    return {200U, "accepted pdus=" + std::to_string(transaction.pdus.size())};
}

auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string
{
    return "Federation runtime remotes=" + std::to_string(runtime.remotes.size())
        + " accepted_transactions=" + std::to_string(runtime.accepted_transactions.size())
        + " audit_events=" + std::to_string(runtime.audit_events.size());
}

auto federation_audit_is_safe(FederationRuntimeState const& runtime) noexcept -> bool
{
    return std::ranges::all_of(runtime.audit_events, [](observability::AuditLogEvent const& event) {
        return event.reason_code.find("sig:v1:") == std::string::npos && event.reason_code.find("verify_token") == std::string::npos;
    });
}

} // namespace merovingian::federation
