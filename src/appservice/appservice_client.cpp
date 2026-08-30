// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/appservice_client.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"

#include <algorithm>
#include <charconv>
#include <utility>

namespace merovingian::appservice
{
namespace
{

    [[nodiscard]] auto make_str_member(std::string_view key, std::string_view value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{std::string{value}});
    }

    [[nodiscard]] auto make_int_member(std::string_view key, std::int64_t value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{value});
    }

    [[nodiscard]] auto build_event_object(AppserviceTransactionEvent const& event) -> canonicaljson::Object
    {
        auto object = canonicaljson::Object{};
        if (!event.content_json.empty())
        {
            auto const parsed_content = canonicaljson::parse_json(event.content_json);
            if (parsed_content.error == canonicaljson::ParseError::none)
            {
                object.push_back(canonicaljson::make_member("content", canonicaljson::Value{parsed_content.value}));
            }
            else
            {
                object.push_back(canonicaljson::make_member("content", canonicaljson::Value{canonicaljson::Object{}}));
            }
        }
        else
        {
            object.push_back(canonicaljson::make_member("content", canonicaljson::Value{canonicaljson::Object{}}));
        }
        object.push_back(make_str_member("event_id", event.event_id));
        object.push_back(make_int_member("origin_server_ts", static_cast<std::int64_t>(event.origin_server_ts)));
        object.push_back(make_str_member("room_id", event.room_id));
        object.push_back(make_str_member("sender", event.sender));
        if (event.state_key.has_value())
        {
            object.push_back(make_str_member("state_key", *event.state_key));
        }
        object.push_back(make_str_member("type", event.type));
        return object;
    }

    // Minimal HTTP/HTTPS URL parser. Unlike push_gateway_client's, this
    // accepts either scheme (see appservice_client.hpp's doc comment) and no
    // fixed path suffix — the caller appends the Application Service API
    // path itself.
    struct ParsedAppserviceUrl final
    {
        bool is_https{true};
        std::string host{};
        std::uint16_t port{0U};
        std::string path_prefix{}; // registration.url's own path component, if any (may be empty)
    };

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto parse_appservice_url(std::string_view url) -> std::optional<ParsedAppserviceUrl>
    {
        auto out = ParsedAppserviceUrl{};
        auto authority_start = std::size_t{0U};
        if (starts_with(url, "https://"))
        {
            out.is_https = true;
            out.port = 443U;
            authority_start = std::string_view{"https://"}.size();
        }
        else if (starts_with(url, "http://"))
        {
            out.is_https = false;
            out.port = 80U;
            authority_start = std::string_view{"http://"}.size();
        }
        else
        {
            return std::nullopt;
        }

        auto const slash = url.find('/', authority_start);
        auto const authority = slash == std::string_view::npos ? url.substr(authority_start)
                                                               : url.substr(authority_start, slash - authority_start);
        if (authority.empty())
        {
            return std::nullopt;
        }
        auto const colon = authority.rfind(':');
        if (colon != std::string_view::npos)
        {
            auto const port_str = authority.substr(colon + 1U);
            auto parsed_port = std::uint16_t{0U};
            auto const parse_result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), parsed_port);
            if (parse_result.ec == std::errc{} && parse_result.ptr == port_str.data() + port_str.size() &&
                parsed_port != 0U)
            {
                out.host = std::string{authority.substr(0U, colon)};
                out.port = parsed_port;
            }
            else
            {
                out.host = std::string{authority};
            }
        }
        else
        {
            out.host = std::string{authority};
        }
        if (out.host.empty())
        {
            return std::nullopt;
        }
        if (slash != std::string_view::npos)
        {
            // Strip a single trailing slash so `path_prefix + "/_matrix/..."`
            // never produces a doubled "//".
            auto path = url.substr(slash);
            if (path.size() > 1U && path.back() == '/')
            {
                path.remove_suffix(1U);
            }
            out.path_prefix = std::string{path};
        }
        return out;
    }

    [[nodiscard]] auto hs_token_string(AppserviceRegistration const& registration) -> std::string
    {
        auto const bytes = registration.hs_token.bytes();
        return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
    }

    [[nodiscard]] auto call_appservice(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                                       AppserviceRegistration const& registration, std::string_view method,
                                       std::string_view path_suffix, std::string body)
        -> std::pair<bool, http::OutboundResult>
    {
        if (!registration.url.has_value())
        {
            return {false, http::OutboundResult{}};
        }
        auto const parsed = parse_appservice_url(*registration.url);
        if (!parsed.has_value())
        {
            auto failed = http::OutboundResult{};
            failed.ok = false;
            failed.error = http::OutboundError::invalid_url;
            failed.error_detail = "invalid appservice registration url";
            return {true, failed};
        }

        auto request = http::OutboundRequest{};
        request.method = std::string{method};
        request.url = std::string{parsed->is_https ? "https://" : "http://"} + parsed->host + ":" +
                      std::to_string(parsed->port) + parsed->path_prefix + std::string{path_suffix};
        request.body = std::move(body);
        request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});
        // Spec (Matrix v1.19, "Authorisation", changed in v1.4): "Homeservers
        // MUST include an Authorization header, containing the hs_token".
        // The legacy `access_token` query-string form is deliberately not
        // sent alongside it — putting a secret in a URL risks it landing in
        // proxy/access logs, and every appservice this homeserver can be
        // configured against understands the modern header form.
        request.headers.push_back(http::OutboundHeader{"Authorization", "Bearer " + hs_token_string(registration)});
        // See AppserviceClient's doc comment: an appservice URL is
        // operator-configured, not attacker-influenced, so cleartext http is
        // permitted (the spec's own example uses it) and host resolution
        // below intentionally bypasses the private/loopback-address
        // rejection that applies to attacker-influenced destinations.
        request.allow_cleartext_http = true;
        request.connect_timeout_seconds = 10U;
        request.total_timeout_seconds = 30U;

        auto const resolved = discovery.upstream().lookup_addresses(parsed->host, parsed->port);
        if (!resolved.ok || resolved.addresses.empty())
        {
            auto failed = http::OutboundResult{};
            failed.ok = false;
            failed.error = http::OutboundError::unresolved_host;
            failed.error_detail = "failed to resolve appservice host: " + resolved.reason;
            return {true, failed};
        }
        request.pinned_addresses = resolved.addresses;

        return {true, outbound.perform(request)};
    }

} // namespace

auto build_transaction_request_body(AppserviceTransaction const& transaction) -> std::string
{
    auto events = canonicaljson::Array{};
    for (auto const& event : transaction.events)
    {
        events.emplace_back(build_event_object(event));
    }
    auto root = canonicaljson::Object{};
    root.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(root)}).output;
}

AppserviceClient::AppserviceClient(http::OutboundClient& outbound,
                                   federation::CachedServerDiscovery& discovery) noexcept
    : outbound_{outbound}
    , discovery_{discovery}
{
}

auto AppserviceClient::send_transaction(AppserviceRegistration const& registration,
                                        AppserviceTransaction const& transaction) -> AppserviceCallResult
{
    auto const path = "/_matrix/app/v1/transactions/" + core::percent_encode_path_component(transaction.txn_id);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, registration, "PUT", path, build_transaction_request_body(transaction));
    if (!attempted)
    {
        return {false, true, 0U, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, result.error, result.error_detail};
    }
    return {result.response.status == 200U, false, result.response.status, http::OutboundError::none, {}};
}

auto AppserviceClient::perform_query(AppserviceRegistration const& registration, std::string_view path)
    -> AppserviceQueryResult
{
    auto const [attempted, result] = call_appservice(outbound_, discovery_, registration, "GET", path, {});
    if (!attempted)
    {
        return {false, true, 0U, false, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, result.error, result.error_detail};
    }
    // Spec: 200 = exists, 404 = does not exist. Anything else (401/403/5xx)
    // is neither — the caller must not read `exists` when `ok` is false.
    if (result.response.status == 200U)
    {
        return {true, false, 200U, true, http::OutboundError::none, {}};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, http::OutboundError::none, {}};
    }
    return {
        false, false, result.response.status, false, http::OutboundError::none, "unexpected appservice query status"};
}

auto AppserviceClient::query_user(AppserviceRegistration const& registration, std::string_view user_id)
    -> AppserviceQueryResult
{
    return perform_query(registration, "/_matrix/app/v1/users/" + core::percent_encode_path_component(user_id));
}

auto AppserviceClient::query_room_alias(AppserviceRegistration const& registration, std::string_view room_alias)
    -> AppserviceQueryResult
{
    return perform_query(registration, "/_matrix/app/v1/rooms/" + core::percent_encode_path_component(room_alias));
}

} // namespace merovingian::appservice
