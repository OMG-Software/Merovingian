// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationEndpoint.hpp"            // split-shim
#include "merovingian/federation/FederationRoute.hpp"               // split-shim
#include "merovingian/federation/FederationRouteMatch.hpp"          // split-shim
#include "merovingian/federation/FederationTransaction.hpp"         // split-shim
#include "merovingian/federation/FederationTransactionDecision.hpp" // split-shim

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

inline constexpr auto max_federation_transaction_pdus = std::uint32_t{50U};
inline constexpr auto max_federation_transaction_edus = std::uint32_t{100U};

[[nodiscard]] auto federation_endpoint_name(FederationEndpoint endpoint) noexcept -> char const*;
// True when handling this endpoint can block a federation worker thread on a
// synchronous IPC round-trip back to main — pdu_sink/edu_sink (transaction),
// membership_acceptor (send_join/send_leave/send_knock), invite_handler
// (invite), or one of the query-provider relays (query_profile, query_directory,
// public_rooms, query_keys, claim_keys, query_user_devices, query_event). False for endpoints a worker
// answers entirely from its own local, room-scoped snapshot with no relay.
// Used to route worker requests to a differently-sized thread pool so a
// burst of slow relay calls cannot starve fast local ones of a thread to run
// on — see docs/architecture.md, "Federation worker relay pool separation".
[[nodiscard]] auto federation_endpoint_requires_main_relay(FederationEndpoint endpoint) noexcept -> bool;
[[nodiscard]] auto federation_routes() -> std::vector<FederationRoute>;
[[nodiscard]] auto match_federation_route(std::string_view method, std::string_view target) -> FederationRouteMatch;
// The HTTP methods the inbound federation routes serve on `target`'s path (query string ignored),
// each once, in the table's order. Empty when no route has that path. Lets a caller tell a path
// that is not served (404) from one used with a method it does not serve (405).
[[nodiscard]] auto federation_methods_for_path(std::string_view target) -> std::vector<std::string>;
[[nodiscard]] auto validate_federation_transaction(
    FederationTransaction const& transaction, std::size_t max_transaction_bytes,
    std::uint32_t max_transaction_pdus = max_federation_transaction_pdus,
    std::uint32_t max_transaction_edus = max_federation_transaction_edus) -> FederationTransactionDecision;
[[nodiscard]] auto federation_route_audit_event(FederationRoute const& route, std::string_view origin) -> std::string;

} // namespace merovingian::federation
