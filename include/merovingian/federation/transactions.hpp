// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

enum class FederationEndpoint
{
    transaction,
    send_join,
    send_leave,
    invite,
    backfill,
    edu,
};

struct FederationTransaction final
{
    std::string origin{};
    std::string transaction_id{};
    std::vector<std::string> pdus{};
    std::vector<std::string> edus{};
    std::size_t byte_size{0U};
};

struct FederationTransactionDecision final
{
    bool accepted{false};
    std::string reason{};
};

struct FederationRoute final
{
    std::string method{};
    std::string path_template{};
    FederationEndpoint endpoint{FederationEndpoint::transaction};
    bool requires_request_signature{true};
    bool requires_event_signatures{true};
};

struct FederationRouteMatch final
{
    bool matched{false};
    FederationRoute route{};
    std::string reason{};
};

struct FederationEdu final
{
    std::string edu_type{};
    std::string origin{};
    bool ephemeral{true};
};

[[nodiscard]] auto federation_endpoint_name(FederationEndpoint endpoint) noexcept -> char const*;
[[nodiscard]] auto federation_routes() -> std::vector<FederationRoute>;
[[nodiscard]] auto match_federation_route(std::string_view method, std::string_view target) -> FederationRouteMatch;
[[nodiscard]] auto validate_federation_transaction(FederationTransaction const& transaction,
                                                   std::size_t max_transaction_bytes) -> FederationTransactionDecision;
[[nodiscard]] auto edu_is_allowed(FederationEdu const& edu) -> FederationTransactionDecision;
[[nodiscard]] auto federation_route_audit_event(FederationRoute const& route, std::string_view origin) -> std::string;

} // namespace merovingian::federation
