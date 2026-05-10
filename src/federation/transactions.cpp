// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/federation/security.hpp>
#include <merovingian/federation/transactions.hpp>

#include <string>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

[[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

[[nodiscard]] auto matches_dynamic_prefix(std::string_view target, std::string_view prefix) noexcept -> bool
{
    return target.size() > prefix.size() && starts_with(target, prefix);
}

[[nodiscard]] auto route(std::string method, std::string path_template, FederationEndpoint endpoint) -> FederationRoute
{
    auto const requires_event_signatures = endpoint != FederationEndpoint::edu;
    return {std::move(method), std::move(path_template), endpoint, true, requires_event_signatures};
}

} // namespace

auto federation_endpoint_name(FederationEndpoint endpoint) noexcept -> char const*
{
    switch (endpoint)
    {
    case FederationEndpoint::transaction:
        return "transaction";
    case FederationEndpoint::send_join:
        return "send_join";
    case FederationEndpoint::send_leave:
        return "send_leave";
    case FederationEndpoint::invite:
        return "invite";
    case FederationEndpoint::backfill:
        return "backfill";
    case FederationEndpoint::edu:
        return "edu";
    }

    return "unknown";
}

auto federation_routes() -> std::vector<FederationRoute>
{
    return {
        route("PUT", "/_matrix/federation/v1/send/{txnId}", FederationEndpoint::transaction),
        route("PUT", "/_matrix/federation/v2/send_join/{roomId}/{eventId}", FederationEndpoint::send_join),
        route("PUT", "/_matrix/federation/v2/send_leave/{roomId}/{eventId}", FederationEndpoint::send_leave),
        route("PUT", "/_matrix/federation/v2/invite/{roomId}/{eventId}", FederationEndpoint::invite),
        route("GET", "/_matrix/federation/v1/backfill/{roomId}", FederationEndpoint::backfill),
        route("PUT", "/_matrix/federation/v1/send_edu/{eduType}/{txnId}", FederationEndpoint::edu),
    };
}

auto match_federation_route(std::string_view method, std::string_view target) -> FederationRouteMatch
{
    for (auto const& candidate : federation_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target)
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::transaction && matches_dynamic_prefix(target, "/_matrix/federation/v1/send/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_join && matches_dynamic_prefix(target, "/_matrix/federation/v2/send_join/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_leave && matches_dynamic_prefix(target, "/_matrix/federation/v2/send_leave/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::invite && matches_dynamic_prefix(target, "/_matrix/federation/v2/invite/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::backfill && matches_dynamic_prefix(target, "/_matrix/federation/v1/backfill/"))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::edu && matches_dynamic_prefix(target, "/_matrix/federation/v1/send_edu/"))
        {
            return {true, candidate, {}};
        }
    }

    return {false, {}, "federation route not found"};
}

auto validate_federation_transaction(
    FederationTransaction const& transaction,
    std::size_t max_transaction_bytes
) -> FederationTransactionDecision
{
    if (!server_name_is_valid(transaction.origin))
    {
        return {false, "invalid transaction origin"};
    }
    if (transaction.transaction_id.empty())
    {
        return {false, "transaction id is required"};
    }
    if (transaction.byte_size > max_transaction_bytes)
    {
        return {false, "transaction exceeds configured byte limit"};
    }
    if (transaction.pdus.empty() && transaction.edus.empty())
    {
        return {false, "transaction must contain PDUs or EDUs"};
    }

    return {true, {}};
}

auto edu_is_allowed(FederationEdu const& edu) -> FederationTransactionDecision
{
    if (!server_name_is_valid(edu.origin))
    {
        return {false, "invalid EDU origin"};
    }
    if (edu.edu_type.empty())
    {
        return {false, "EDU type is required"};
    }
    if (!edu.ephemeral)
    {
        return {false, "EDUs must remain ephemeral"};
    }

    return {true, {}};
}

auto federation_route_audit_event(FederationRoute const& route, std::string_view origin) -> std::string
{
    return "federation." + std::string{federation_endpoint_name(route.endpoint)} + " origin=" + std::string{origin};
}

} // namespace merovingian::federation
