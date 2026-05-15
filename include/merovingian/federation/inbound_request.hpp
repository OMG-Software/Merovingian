// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/observability/observability.hpp"

#include <cstdint>
#include <optional>
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
    bool canonical_json_verified{false};
    std::string body{};
};

struct FederationPdu final
{
    std::string event_id{};
    std::string room_id{};
    std::string event_type{};
    std::string sender{};
    std::vector<events::EventSignature> signatures{};
    std::string json{};
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

struct FederationRuntimeState final
{
    RuntimeFederationConfig config{};
    std::vector<FederationRemoteRuntime> remotes{};
    std::vector<FederationAcceptedTransaction> accepted_transactions{};
    std::vector<observability::AuditLogEvent> audit_events{};
};

struct FederationDecision final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
};

struct FederationResponse final
{
    std::uint16_t status{500U};
    std::string body{};
};

[[nodiscard]] auto load_server_signing_key(std::string_view server_name, std::string_view key_id,
                                           std::string_view key_material) -> FederationSigningKey;
[[nodiscard]] auto signing_key_summary(FederationSigningKey const& key) -> std::string;
[[nodiscard]] auto make_federation_signature(std::string_view origin, std::string_view key_id,
                                             std::string_view verify_token, std::string_view method,
                                             std::string_view target, std::uint64_t origin_server_ts,
                                             std::string_view body) -> std::string;
[[nodiscard]] auto verify_signed_federation_request(SignedFederationRequest const& request,
                                                    FederationKeyRecord const& key,
                                                    std::uint64_t max_clock_skew_seconds) -> FederationDecision;
[[nodiscard]] auto make_federation_runtime_state(RuntimeFederationConfig config) -> FederationRuntimeState;
auto upsert_remote(FederationRuntimeState& runtime, FederationRemoteRuntime remote) -> void;
[[nodiscard]] auto federation_remote_is_known(FederationRuntimeState const& runtime,
                                              std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin)
    -> FederationDecision;
[[nodiscard]] auto authorize_federation_pdu(FederationPdu const& pdu, std::string_view expected_origin,
                                            std::optional<FederationKeyRecord> const& key) -> FederationDecision;
[[nodiscard]] auto parse_federation_pdu(std::string_view encoded) -> FederationPdu;
[[nodiscard]] auto handle_inbound_federation_request(FederationRuntimeState& runtime,
                                                     SignedFederationRequest const& request) -> FederationResponse;
[[nodiscard]] auto federation_runtime_summary(FederationRuntimeState const& runtime) -> std::string;
[[nodiscard]] auto federation_audit_is_safe(FederationRuntimeState const& runtime) noexcept -> bool;

} // namespace merovingian::federation
