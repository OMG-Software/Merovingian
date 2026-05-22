// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
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
    // identity. Used to sign the X-Matrix Authorization header.
    std::string secret_key{};
    std::uint32_t connect_timeout_seconds{10U};
    std::uint32_t total_timeout_seconds{60U};
};

[[nodiscard]] auto make_outbound_transaction(std::string_view destination, std::string_view method,
                                             std::string_view target, std::string_view origin, std::string_view body)
    -> OutboundTransaction;

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
