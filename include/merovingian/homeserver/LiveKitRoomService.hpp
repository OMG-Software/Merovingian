// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>

namespace merovingian::federation
{
class CachedServerDiscovery;
} // namespace merovingian::federation

namespace merovingian::http
{
class OutboundClient;
} // namespace merovingian::http

namespace merovingian::homeserver
{

// Calls to LiveKit's room service (Twirp, JSON) at `server.rtc.livekit.api_url` (ADR-0830). Each call carries a token
// of its own with only the grant that call needs, minted for one minute; the address is the operator's, never one a
// request names.

// The largest answer read from LiveKit. A `Room` or `ParticipantInfo` is far smaller.
inline constexpr auto livekit_response_max_bytes = std::size_t{16U * 1024U};
// How long the service token of one call is valid.
inline constexpr auto livekit_service_token_seconds = std::int64_t{60};
// What `CreateRoom` asks for, as lk-jwt-service does: a room with nobody in it closes after 300 s, and one everybody
// left after 20 s.
inline constexpr auto livekit_room_empty_timeout_seconds = std::uint32_t{300U};
inline constexpr auto livekit_room_departure_timeout_seconds = std::uint32_t{20U};

// The `CreateRoom` request for `room_name` (an MSC4195 room name), signed with a `roomCreate`-only token. nullopt
// when `api_url` is not an `https` URL, or an `http` URL to a loopback IP literal, or the token cannot be signed.
// `pinned_addresses` and the timeouts are left for `perform_livekit_request`.
[[nodiscard]] auto livekit_create_room_request(std::string_view api_url, std::string_view api_key,
                                               std::span<std::uint8_t const> api_secret, std::string_view room_name,
                                               std::int64_t now_seconds) -> std::optional<http::OutboundRequest>;

// The `GetParticipant` request for `identity` in `room_name` (both MSC4195 names), signed with a token granting
// `roomAdmin` over that one room only (`crypto::sign_livekit_room_admin_token`). Used only by the delegated delayed
// leave's checks (ADR-0832). nullopt on the same refusals as `livekit_create_room_request`, or a name that is not an
// MSC4195 name.
[[nodiscard]] auto livekit_get_participant_request(std::string_view api_url, std::string_view api_key,
                                                   std::span<std::uint8_t const> api_secret, std::string_view room_name,
                                                   std::string_view identity, std::int64_t now_seconds)
    -> std::optional<http::OutboundRequest>;

// Stands in for LiveKit in tests: it is handed the finished request in place of resolving and connecting.
using LiveKitTestPerform = std::function<http::OutboundResult(http::OutboundRequest const&)>;

// Sends `request` with `timeout_seconds` for the lookup and the exchange together (one `OutboundDeadline`: the
// exchange gets what the lookup leaves, and none is started once it is spent). The host is resolved with the
// operator-trusted lookup
// (`discovery.upstream()`, no private-range filter: the operator chose the address, and LiveKit often runs beside
// this server) and the connection is pinned to it. Never call with `runtime.mutex` held.
[[nodiscard]] auto perform_livekit_request(http::OutboundRequest request, http::OutboundClient& client,
                                           federation::CachedServerDiscovery& discovery, std::uint32_t timeout_seconds,
                                           LiveKitTestPerform const& test_perform) -> http::OutboundResult;

} // namespace merovingian::homeserver
