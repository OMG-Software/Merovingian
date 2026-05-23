// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/transactions.hpp"

#include "merovingian/federation/security.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <utility>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("transactions", event, std::move(fields)));
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto dynamic_suffix_has_segments(std::string_view target, std::string_view prefix,
                                                   std::size_t expected_segments) noexcept -> bool
    {
        if (target.size() <= prefix.size() || !starts_with(target, prefix))
        {
            return false;
        }
        auto const suffix = target.substr(prefix.size());
        auto segments = std::size_t{1U};
        for (auto const character : suffix)
        {
            if (character == '/')
            {
                ++segments;
            }
        }
        return segments == expected_segments && suffix.find("//") == std::string_view::npos && suffix.front() != '/' &&
               suffix.back() != '/';
    }

    [[nodiscard]] auto route(std::string method, std::string path_template, FederationEndpoint endpoint)
        -> FederationRoute
    {
        // make_* + backfill are GET endpoints that return event templates or
        // historical PDUs; the server never receives signed event bodies on
        // those paths. send_edu also carries no inbound event signatures.
        auto const carries_event_bodies = endpoint == FederationEndpoint::transaction ||
                                          endpoint == FederationEndpoint::send_join ||
                                          endpoint == FederationEndpoint::send_leave ||
                                          endpoint == FederationEndpoint::send_knock ||
                                          endpoint == FederationEndpoint::invite;
        return {std::move(method), std::move(path_template), endpoint, true, carries_event_bodies};
    }

} // namespace

auto federation_endpoint_name(FederationEndpoint endpoint) noexcept -> char const*
{
    switch (endpoint)
    {
    case FederationEndpoint::transaction:
        return "transaction";
    case FederationEndpoint::make_join:
        return "make_join";
    case FederationEndpoint::send_join:
        return "send_join";
    case FederationEndpoint::make_leave:
        return "make_leave";
    case FederationEndpoint::send_leave:
        return "send_leave";
    case FederationEndpoint::make_knock:
        return "make_knock";
    case FederationEndpoint::send_knock:
        return "send_knock";
    case FederationEndpoint::invite:
        return "invite";
    case FederationEndpoint::backfill:
        return "backfill";
    case FederationEndpoint::edu:
        return "edu";
    case FederationEndpoint::query_profile:
        return "query_profile";
    case FederationEndpoint::query_keys:
        return "query_keys";
    case FederationEndpoint::claim_keys:
        return "claim_keys";
    case FederationEndpoint::query_user_devices:
        return "query_user_devices";
    case FederationEndpoint::query_event:
        return "query_event";
    case FederationEndpoint::query_state:
        return "query_state";
    case FederationEndpoint::query_state_ids:
        return "query_state_ids";
    case FederationEndpoint::get_missing_events:
        return "get_missing_events";
    }

    return "unknown";
}

auto federation_routes() -> std::vector<FederationRoute>
{
    return {
        route("PUT", "/_matrix/federation/v1/send/{txnId}", FederationEndpoint::transaction),
        route("GET", "/_matrix/federation/v1/make_join/{roomId}/{userId}", FederationEndpoint::make_join),
        route("PUT", "/_matrix/federation/v2/send_join/{roomId}/{eventId}", FederationEndpoint::send_join),
        route("PUT", "/_matrix/federation/v1/send_join/{roomId}/{eventId}", FederationEndpoint::send_join),
        route("GET", "/_matrix/federation/v1/make_leave/{roomId}/{userId}", FederationEndpoint::make_leave),
        route("PUT", "/_matrix/federation/v2/send_leave/{roomId}/{eventId}", FederationEndpoint::send_leave),
        route("PUT", "/_matrix/federation/v1/send_leave/{roomId}/{eventId}", FederationEndpoint::send_leave),
        route("GET", "/_matrix/federation/v1/make_knock/{roomId}/{userId}", FederationEndpoint::make_knock),
        route("PUT", "/_matrix/federation/v1/send_knock/{roomId}/{eventId}", FederationEndpoint::send_knock),
        route("PUT", "/_matrix/federation/v2/invite/{roomId}/{eventId}", FederationEndpoint::invite),
        route("PUT", "/_matrix/federation/v1/invite/{roomId}/{eventId}", FederationEndpoint::invite),
        route("GET", "/_matrix/federation/v1/backfill/{roomId}", FederationEndpoint::backfill),
        route("PUT", "/_matrix/federation/v1/send_edu/{eduType}/{txnId}", FederationEndpoint::edu),
        route("GET", "/_matrix/federation/v1/query/profile", FederationEndpoint::query_profile),
        route("POST", "/_matrix/federation/v1/user/keys/query", FederationEndpoint::query_keys),
        route("POST", "/_matrix/federation/v1/user/keys/claim", FederationEndpoint::claim_keys),
        route("GET", "/_matrix/federation/v1/user/devices/{userId}", FederationEndpoint::query_user_devices),
        route("GET", "/_matrix/federation/v1/event/{eventId}", FederationEndpoint::query_event),
        route("GET", "/_matrix/federation/v1/state/{roomId}", FederationEndpoint::query_state),
        route("GET", "/_matrix/federation/v1/state_ids/{roomId}", FederationEndpoint::query_state_ids),
        route("POST", "/_matrix/federation/v1/get_missing_events/{roomId}", FederationEndpoint::get_missing_events),
    };
}

auto match_federation_route(std::string_view method, std::string_view target) -> FederationRouteMatch
{
    auto const target_has_query = target.find('?');
    auto const target_path = target_has_query == std::string_view::npos ? target : target.substr(0U, target_has_query);
    for (auto const& candidate : federation_routes())
    {
        if (candidate.method != method)
        {
            continue;
        }
        if (candidate.path_template == target_path)
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::transaction &&
            candidate.path_template == "/_matrix/federation/v1/send/{txnId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/send/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::make_join &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/make_join/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_join &&
            candidate.path_template == "/_matrix/federation/v2/send_join/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v2/send_join/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_join &&
            candidate.path_template == "/_matrix/federation/v1/send_join/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/send_join/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::make_leave &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/make_leave/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_leave &&
            candidate.path_template == "/_matrix/federation/v2/send_leave/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v2/send_leave/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_leave &&
            candidate.path_template == "/_matrix/federation/v1/send_leave/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/send_leave/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::make_knock &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/make_knock/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::send_knock &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/send_knock/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::invite &&
            candidate.path_template == "/_matrix/federation/v2/invite/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v2/invite/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::invite &&
            candidate.path_template == "/_matrix/federation/v1/invite/{roomId}/{eventId}" &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/invite/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::backfill &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/backfill/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::edu &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/send_edu/", 2U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::query_user_devices &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/user/devices/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::query_event &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/event/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::query_state &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/state/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::query_state_ids &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/state_ids/", 1U))
        {
            return {true, candidate, {}};
        }
        if (candidate.endpoint == FederationEndpoint::get_missing_events &&
            dynamic_suffix_has_segments(target_path, "/_matrix/federation/v1/get_missing_events/", 1U))
        {
            return {true, candidate, {}};
        }
    }

    return {false, {}, "federation route not found"};
}

auto validate_federation_transaction(FederationTransaction const& transaction, std::size_t max_transaction_bytes)
    -> FederationTransactionDecision
{
    auto result = [&]() -> FederationTransactionDecision {
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
    }();
    log_diagnostic(result.accepted ? "transaction.accepted" : "transaction.rejected",
                   {{"origin",         transaction.origin,                          false},
                    {"transaction_id", transaction.transaction_id,                  false},
                    {"pdus",           std::to_string(transaction.pdus.size()),      false},
                    {"edus",           std::to_string(transaction.edus.size()),      false},
                    {"reason",         result.reason,                                false}});
    return result;
}

auto edu_is_allowed(FederationEdu const& edu) -> FederationTransactionDecision
{
    auto result = [&]() -> FederationTransactionDecision {
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
    }();
    log_diagnostic(result.accepted ? "edu.allowed" : "edu.rejected",
                   {{"origin",   edu.origin,   false},
                    {"edu_type", edu.edu_type, false},
                    {"reason",   result.reason, false}});
    return result;
}

auto federation_route_audit_event(FederationRoute const& route, std::string_view origin) -> std::string
{
    return "federation." + std::string{federation_endpoint_name(route.endpoint)} + " origin=" + std::string{origin};
}

} // namespace merovingian::federation
