// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/outbound_membership.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("federation", event, std::move(fields)));
    }

    auto append_query_arg(std::string& target, std::string_view key, std::string_view value, bool& first) -> void
    {
        target.push_back(first ? '?' : '&');
        first = false;
        target.append(key);
        target.push_back('=');
        target.append(value);
    }

    [[nodiscard]] auto build_v2_invite_body(std::string_view room_version, std::string_view signed_event_json,
                                            std::vector<std::string> const& invite_room_state_json) -> std::string
    {
        auto root = canonicaljson::Object{};
        root.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
        auto event_value = canonicaljson::Value{};
        auto parsed = canonicaljson::parse_lossless(signed_event_json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            event_value = std::move(parsed.value);
        }
        root.push_back(canonicaljson::make_member("event", std::move(event_value)));
        auto state_array = canonicaljson::Array{};
        for (auto const& entry : invite_room_state_json)
        {
            auto parsed_entry = canonicaljson::parse_lossless(entry);
            if (parsed_entry.error == canonicaljson::ParseError::none)
            {
                state_array.push_back(std::move(parsed_entry.value));
            }
        }
        root.push_back(canonicaljson::make_member("invite_room_state", canonicaljson::Value{std::move(state_array)}));
        auto const out = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(root)});
        return out.error == canonicaljson::CanonicalJsonError::none ? out.output : std::string{};
    }

} // namespace

auto make_outbound_make_membership(FederationEndpoint endpoint, std::string_view destination, std::string_view origin,
                                   std::string_view room_id, std::string_view user_id,
                                   std::vector<std::string> const& supported_room_versions) -> OutboundTransaction
{
    auto target = std::string{};
    switch (endpoint)
    {
    case FederationEndpoint::make_join:
        target = "/_matrix/federation/v1/make_join/";
        break;
    case FederationEndpoint::make_leave:
        target = "/_matrix/federation/v1/make_leave/";
        break;
    case FederationEndpoint::make_knock:
        target = "/_matrix/federation/v1/make_knock/";
        break;
    default:
        return {};
    }
    target.append(core::percent_encode_path_component(room_id));
    target.push_back('/');
    target.append(core::percent_encode_path_component(user_id));
    auto first_query = true;
    for (auto const& version : supported_room_versions)
    {
        append_query_arg(target, "ver", version, first_query);
    }
    auto transaction = make_outbound_transaction(destination, "GET", target, origin, "");
    log_diagnostic("outbound.membership.make",
                   {
                       {"destination", std::string{destination},                                 false},
                       {"origin",      std::string{origin},                                      false},
                       {"room_id",     std::string{room_id},                                     false},
                       {"user_id",     std::string{user_id},                                     false},
                       {"target",      observability::sanitized_http_target(transaction.target), false}
    });
    return transaction;
}

auto make_outbound_send_membership(FederationEndpoint endpoint, std::string_view destination, std::string_view origin,
                                   std::string_view room_id, std::string_view event_id,
                                   std::string_view signed_event_json) -> OutboundTransaction
{
    auto target = std::string{};
    switch (endpoint)
    {
    case FederationEndpoint::send_join:
        target = "/_matrix/federation/v2/send_join/";
        break;
    case FederationEndpoint::send_leave:
        target = "/_matrix/federation/v2/send_leave/";
        break;
    case FederationEndpoint::send_knock:
        target = "/_matrix/federation/v1/send_knock/";
        break;
    default:
        return {};
    }
    target.append(core::percent_encode_path_component(room_id));
    target.push_back('/');
    target.append(core::percent_encode_path_component(event_id));
    auto transaction = make_outbound_transaction(destination, "PUT", target, origin, signed_event_json);
    log_diagnostic("outbound.membership.send",
                   {
                       {"destination", std::string{destination},                                 false},
                       {"origin",      std::string{origin},                                      false},
                       {"room_id",     std::string{room_id},                                     false},
                       {"event_id",    std::string{event_id},                                    false},
                       {"target",      observability::sanitized_http_target(transaction.target), false},
                       {"body_bytes",  std::to_string(transaction.body.size()),                  false}
    });
    return transaction;
}

auto make_outbound_invite(std::string_view destination, std::string_view origin, std::string_view room_id,
                          std::string_view event_id, std::string_view room_version,
                          std::string_view signed_invite_event_json,
                          std::vector<std::string> const& invite_room_state_json) -> OutboundTransaction
{
    if (room_version.empty())
    {
        // v1 invite: body IS the bare event.
        auto target = std::string{"/_matrix/federation/v1/invite/"};
        target.append(core::percent_encode_path_component(room_id));
        target.push_back('/');
        target.append(core::percent_encode_path_component(event_id));
        auto transaction = make_outbound_transaction(destination, "PUT", target, origin, signed_invite_event_json);
        log_diagnostic("outbound.invite",
                       {
                           {"destination", std::string{destination},                                 false},
                           {"origin",      std::string{origin},                                      false},
                           {"room_id",     std::string{room_id},                                     false},
                           {"event_id",    std::string{event_id},                                    false},
                           {"target",      observability::sanitized_http_target(transaction.target), false},
                           {"body_bytes",  std::to_string(transaction.body.size()),                  false}
        });
        return transaction;
    }
    auto target = std::string{"/_matrix/federation/v2/invite/"};
    target.append(core::percent_encode_path_component(room_id));
    target.push_back('/');
    target.append(core::percent_encode_path_component(event_id));
    auto body = build_v2_invite_body(room_version, signed_invite_event_json, invite_room_state_json);
    auto transaction = make_outbound_transaction(destination, "PUT", target, origin, body);
    log_diagnostic("outbound.invite", {
                                          {"destination",  std::string{destination},                                 false},
                                          {"origin",       std::string{origin},                                      false},
                                          {"room_id",      std::string{room_id},                                     false},
                                          {"event_id",     std::string{event_id},                                    false},
                                          {"room_version", std::string{room_version},                                false},
                                          {"target",       observability::sanitized_http_target(transaction.target), false},
                                          {"body_bytes",   std::to_string(transaction.body.size()),                  false}
    });
    return transaction;
}

auto make_outbound_backfill(std::string_view destination, std::string_view origin, std::string_view room_id,
                            std::vector<std::string> const& event_ids, std::size_t limit) -> OutboundTransaction
{
    auto target = std::string{"/_matrix/federation/v1/backfill/"};
    target.append(core::percent_encode_path_component(room_id));
    auto first_query = true;
    for (auto const& event_id : event_ids)
    {
        append_query_arg(target, "v", event_id, first_query);
    }
    if (limit != 0U)
    {
        append_query_arg(target, "limit", std::to_string(limit), first_query);
    }
    return make_outbound_transaction(destination, "GET", target, origin, "");
}

} // namespace merovingian::federation
