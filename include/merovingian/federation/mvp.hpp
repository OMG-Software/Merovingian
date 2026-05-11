// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/events/event.hpp>
#include <merovingian/federation/runtime_federation.hpp>
#include <merovingian/federation/security.hpp>
#include <merovingian/federation/transactions.hpp>
#include <merovingian/observability/observability.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct FederationSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string verify_token{};
    bool loaded{false};
};

struct FederationKeyRecord final
{
    std::string server_name{};
    std::string key_id{};
    std::string verify_token{};
    std::uint64_t valid_until_ts{0U};
};

struct SignedFederationRequest final
{
    std::string method{};
    std::string target{};
    std::string origin{};
    std::string key_id{};
    std::string signature{};
    std::uint64_t origin_server_ts{0U};
    std::uint64_t now_ts{0U};
    std::string body{};
};

struct FederationPdu final
{
    std::string event_id{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::vector<events::EventSignature> signatures{};
};

struct FederationAcceptedTransaction final
{
    std::string origin{};
    std::string transaction_id{};
    std::size_t pdu_count{0U};
    std::size_t edu_count{0U};
};

struct FederationRemoteRuntime final
{
    std::string server_name{};
    RemoteTrustState trust{};
    FederationKeyRecord signing_key{};
    RemoteServerRecord discovery{};
};

struct FederationMvpRuntime final
{
    RuntimeFederationConfig config{};
    std::vector<FederationRemoteRuntime> remotes{};
    std::vector<FederationAcceptedTransaction> accepted_transactions{};
    std::vector<observability::AuditLogEvent> audit_events{};
};

struct FederationMvpDecision final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
};

struct FederationMvpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
};

[[nodiscard]] auto load_server_signing_key(
    std::string_view server_name,
    std::string_view key_id,
    std::string_view key_material
) -> FederationSigningKey;
[[nodiscard]] auto signing_key_summary(FederationSigningKey const& key) -> std::string;
[[nodiscard]] auto make_federation_signature(
    std::string_view origin,
    std::string_view key_id,
    std::string_view verify_token,
    std::string_view method,
    std::string_view target,
    std::uint64_t origin_server_ts,
    std::string_view body
) -> std::string;
[[nodiscard]] auto verify_signed_federation_request(
    SignedFederationRequest const& request,
    FederationKeyRecord const& key,
    std::uint64_t max_clock_skew_seconds
) -> FederationMvpDecision;
[[nodiscard]] auto make_federation_mvp_runtime(RuntimeFederationConfig config) -> FederationMvpRuntime;
auto upsert_remote(FederationMvpRuntime& runtime, FederationRemoteRuntime remote) -> void;
[[nodiscard]] auto federation_remote_is_known(FederationMvpRuntime const& runtime, std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin) -> FederationMvpDecision;
[[nodiscard]] auto parse_federation_pdu(std::string_view encoded) -> FederationPdu;
[[nodiscard]] auto handle_inbound_federation_request(
    FederationMvpRuntime& runtime,
    SignedFederationRequest const& request
) -> FederationMvpResponse;
[[nodiscard]] auto federation_runtime_summary(FederationMvpRuntime const& runtime) -> std::string;
[[nodiscard]] auto federation_audit_is_safe(FederationMvpRuntime const& runtime) noexcept -> bool;

} // namespace merovingian::federation
