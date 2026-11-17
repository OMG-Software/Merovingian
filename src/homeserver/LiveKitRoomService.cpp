// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LiveKitRoomService.hpp"

#include "merovingian/crypto/LiveKitToken.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundHeader.hpp"
#include "merovingian/http/ParsedOutboundUrl.hpp"
#include "merovingian/net/LoopbackLiteral.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace merovingian::homeserver
{
namespace
{

    // `api_url` parsed and held to the rule validate() applies (ADR-0829), again here so a value that reached this code
    // any other way still cannot send a signed request in cleartext off the host.
    [[nodiscard]] auto parsed_api_url(std::string_view const api_url) -> std::optional<http::ParsedOutboundUrl>
    {
        auto parsed = http::parse_outbound_url(api_url, true);
        if (!parsed.has_value() || !parsed->query.empty() ||
            (parsed->scheme != "https" && !(parsed->scheme == "http" && net::is_loopback_ip_literal(parsed->host))))
        {
            return std::nullopt;
        }
        return parsed;
    }

    // `<scheme>://<host>:<port><path><suffix>`, rebuilt from the parsed parts with the port always written.
    [[nodiscard]] auto twirp_url(http::ParsedOutboundUrl const& base, std::string_view const method) -> std::string
    {
        auto path = std::string_view{base.path};
        if (!path.empty() && path.back() == '/')
        {
            path.remove_suffix(1U);
        }
        return base.scheme + "://" + (base.ipv6_literal ? "[" + base.host + "]" : base.host) + ":" +
               std::to_string(base.port) + std::string{path} + "/twirp/livekit.RoomService/" + std::string{method};
    }

    [[nodiscard]] auto failed(http::OutboundError const error, std::string detail) -> http::OutboundResult
    {
        auto result = http::OutboundResult{};
        result.ok = false;
        result.error = error;
        result.error_detail = std::move(detail);
        return result;
    }

} // namespace

auto livekit_create_room_request(std::string_view const api_url, std::string_view const api_key,
                                 std::span<std::uint8_t const> const api_secret, std::string_view const room_name,
                                 std::int64_t const now_seconds) -> std::optional<http::OutboundRequest>
{
    auto const base = parsed_api_url(api_url);
    if (!base.has_value() || !crypto::livekit_name_is_valid(room_name))
    {
        return std::nullopt;
    }
    auto token = crypto::sign_livekit_room_create_token(api_key, api_secret, now_seconds,
                                                        now_seconds + livekit_service_token_seconds);
    if (!token.has_value())
    {
        return std::nullopt;
    }
    auto request = http::OutboundRequest{};
    request.method = "POST";
    request.url = twirp_url(*base, "CreateRoom");
    request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});
    request.headers.push_back(http::OutboundHeader{"Authorization", "Bearer " + std::move(*token)});
    // The room name is 43 base64 characters (checked above), so it needs no JSON escaping.
    request.body = R"({"name":")" + std::string{room_name} + R"(","empty_timeout":)" +
                   std::to_string(livekit_room_empty_timeout_seconds) + R"(,"departure_timeout":)" +
                   std::to_string(livekit_room_departure_timeout_seconds) + "}";
    request.allow_cleartext_http = base->scheme == "http";
    request.max_response_body_bytes = livekit_response_max_bytes;
    return request;
}

auto perform_livekit_request(http::OutboundRequest request, http::OutboundClient& client,
                             federation::CachedServerDiscovery& discovery, std::uint32_t const timeout_seconds,
                             LiveKitTestPerform const& test_perform) -> http::OutboundResult
{
    if (timeout_seconds == 0U)
    {
        return failed(http::OutboundError::timeout, "deadline exceeded");
    }
    request.total_timeout_seconds = timeout_seconds;
    request.connect_timeout_seconds = std::min(timeout_seconds, std::uint32_t{10U});
    if (test_perform)
    {
        return test_perform(request);
    }
    auto const parsed = http::parse_outbound_url(request.url, request.allow_cleartext_http);
    if (!parsed.has_value())
    {
        return failed(http::OutboundError::invalid_url, "invalid LiveKit API URL");
    }
    auto const resolved = discovery.upstream().lookup_addresses(parsed->host, parsed->port);
    if (!resolved.ok || resolved.addresses.empty())
    {
        return failed(http::OutboundError::unresolved_host, "failed to resolve the LiveKit API host");
    }
    request.pinned_addresses = resolved.addresses;
    return client.perform(request);
}

} // namespace merovingian::homeserver
