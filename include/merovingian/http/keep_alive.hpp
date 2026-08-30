// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/request.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::http
{

// Operator-tunable persistent-connection policy for the client and federation
// listeners (Matrix v1.19 is served over HTTP/1.1, where persistent
// connections are the default — RFC 9112 §9.3).
//
//   enabled           — master switch; false closes every connection after
//                        its response (the pre-0.12.1 behaviour).
//   idle_timeout_seconds — how long a kept-alive connection with no next
//                        request may be held open before the server closes
//                        it. Bounds how long a parked connection occupies a
//                        worker thread. Valid range 1..300.
//   max_connections   — cap on concurrently parked (idle, waiting for a next
//                        request) connections, process-wide. A kept-alive
//                        connection parks on a main-pool worker thread, so
//                        without a cap a client could park one worker per
//                        connection and stall every new request until each
//                        idle window expired. Valid range 1..4096.
struct KeepAlivePolicy final
{
    bool enabled{true};
    std::uint32_t idle_timeout_seconds{15U};
    std::uint32_t max_connections{8U};
};

// Whether the server should hold the connection open after writing a response
// or close it. `close` matches the historical one-request-per-connection
// behaviour; `keep_alive` emits `Connection: keep-alive` (plus a
// `Keep-Alive: timeout=N` hint) and parks the connection for the next request.
enum class ConnectionPreference : std::uint8_t
{
    close,
    keep_alive,
};

[[nodiscard]] auto keep_alive_policy_is_valid(KeepAlivePolicy const& policy) noexcept -> bool;
[[nodiscard]] auto keep_alive_policy_summary(KeepAlivePolicy const& policy) -> std::string;

// RFC 9110 §7.6.1: a Connection header value is a comma-separated list of
// case-insensitive tokens. This reports whether `token` appears in the list.
[[nodiscard]] auto connection_header_has_token(std::string_view connection_header, std::string_view token) noexcept
    -> bool;

// The connection preference requested by the client's request head alone:
// HTTP/1.1 defaults to keep-alive and honours `Connection: close`; HTTP/1.0
// defaults to close and keeps alive only on an explicit
// `Connection: keep-alive`.
[[nodiscard]] auto connection_preference_for_request(HttpVersion version, std::string_view connection_header) noexcept
    -> ConnectionPreference;

// The preference the server acts on for one response: the client's request
// composed with the operator policy and the number of connections already
// parked waiting for a next request (`parked_connections`). When the cap is
// reached the response closes the connection instead of parking another one.
[[nodiscard]] auto connection_preference_for_response(HttpVersion version, std::string_view connection_header,
                                                      KeepAlivePolicy const& policy,
                                                      std::uint32_t parked_connections) noexcept
    -> ConnectionPreference;

} // namespace merovingian::http