// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/ConnectionPreference.hpp" // split-shim
#include "merovingian/http/KeepAlivePolicy.hpp"      // split-shim
#include "merovingian/http/request.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::http
{

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