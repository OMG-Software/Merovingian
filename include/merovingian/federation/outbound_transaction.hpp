// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct OutboundTransaction final
{
    std::string transaction_id{};
    std::string destination{};
    std::string method{"PUT"};
    std::string target{};
    std::string origin{};
    std::string origin_server_ts{};
    std::string body{};
    std::uint32_t retry_count{0U};
    std::uint64_t next_retry_ts{0U};
};

// Generates an opaque Matrix federation transaction ID suitable for
// /_matrix/federation/v1/send/{txnId}. The value is intentionally decoupled
// from local session counters so restarts cannot cause peers to deduplicate a
// fresh transaction as a replay of an older one.
[[nodiscard]] auto make_federation_transaction_id() -> std::string;

struct OutboundTransactionResult final
{
    bool sent{false};
    std::uint16_t http_status{0U};
    std::string response_body{};
    std::string error{};
};

// Composed shape ready to send: transaction shape + validated destination
// resolution + signing identity. Callers populate `pinned_addresses` from
// the address set already accepted by `federation_discovery_policy` so the
// SSRF policy remains the single source of truth.
struct OutboundCall final
{
    OutboundTransaction transaction{};
    std::string resolved_host{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
    std::string key_id{};
    // Raw 64-byte libsodium Ed25519 secret key for this server's signing
    // identity, used to sign the X-Matrix Authorization header. Carried as a
    // non-owning span: the caller (the runtime's SecretBuffer for synchronous
    // calls, or DispatchWorkerConfig::secret_key for async dispatch) owns and
    // outlives the signing operation, so the key is never copied into an
    // unpinned std::string. build_outbound_request signs synchronously and
    // discards the span before the owner can be released.
    std::span<std::uint8_t const> secret_key{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{60U};
};

[[nodiscard]] auto make_outbound_transaction(std::string_view destination, std::string_view method,
                                             std::string_view target, std::string_view origin, std::string_view body)
    -> OutboundTransaction;

// Builds the canonical-JSON body of a federation /send transaction carrying a
// single EDU and no PDUs. Pure function; performs no network I/O. The body
// includes the Matrix-required top-level `origin`, `origin_server_ts`, empty
// `pdus`, and one-entry `edus` array. The EDU is keyed by "edu_type" (per the
// Matrix federation spec, NOT "type") so receivers such as Synapse do not
// reject the entire transaction with a missing-field error. `edu_content_json`
// is parsed and re-serialized canonically; invalid content or a serialization
// failure yields std::nullopt.
[[nodiscard]] auto build_edu_transaction_body(std::string_view origin, std::string_view edu_type,
                                              std::string_view edu_content_json) -> std::optional<std::string>;

// Builds the canonical-JSON *content* of an m.receipt EDU per Matrix spec
// §receipts. Shape: { roomId: { receiptType: { userId: { event_ids: [eventId],
// data: { ts: N } } } } }. Pure function; returns std::nullopt on serialization
// failure.
[[nodiscard]] auto build_receipt_edu_content(std::string_view room_id, std::string_view receipt_type,
                                             std::string_view user_id, std::string_view event_id, std::int64_t ts)
    -> std::optional<std::string>;

[[nodiscard]] auto compute_backoff(std::uint32_t retry_count) noexcept -> std::uint64_t;

[[nodiscard]] auto destination_should_retry(FederationDestination const& destination, std::uint64_t now_ts) noexcept
    -> bool;

// Builds the OutboundRequest the HTTP client should send for the given call.
// Pure function; performs no DNS, TLS, or network I/O. The returned request
// carries the URL (https://<resolved_host>:<resolved_port><target>), the
// caller-pinned addresses for SSRF defense, the request body verbatim, and
// the X-Matrix Authorization header derived through
// `make_federation_signature`.
[[nodiscard]] auto build_outbound_request(OutboundCall const& call) -> http::OutboundRequest;

// Updates the federation destination retry state based on a call result.
// A 2xx response clears the failure counter and records last_success_ts.
// Any other outcome increments the failure counter and sets retry_after_ts
// to `now_ts + compute_backoff(consecutive_failures)`.
auto apply_outbound_result(FederationDestination& destination, OutboundTransactionResult const& result,
                           std::uint64_t now_ts) noexcept -> void;

// Executes a single attempt against the destination. Returns early with
// `error == "circuit_open"` and no network I/O when
// `destination_should_retry` rejects the attempt. Otherwise calls
// `client.perform()` and applies the result through `apply_outbound_result`.
[[nodiscard]] auto perform_outbound_transaction(http::OutboundClient& client, OutboundCall const& call,
                                                FederationDestination& destination, std::uint64_t now_ts)
    -> OutboundTransactionResult;

} // namespace merovingian::federation
