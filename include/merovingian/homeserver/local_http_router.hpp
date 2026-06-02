// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/http/request.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct LocalHttpRequest final
{
    std::string method{};
    std::string target{};
    std::string access_token{};
    std::string body{};
    // Parsed request headers (e.g. "Origin", "Authorization"). Populated by
    // `build_local_request` from the wire request head. Tests construct a
    // request directly and set this field to drive CORS logic.
    std::vector<http::Header> headers{};
};

struct LocalHttpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
    // Per-response headers. CORS preflight responses fill this with
    // `Access-Control-Allow-*` and `Vary: Origin`; `format_response` writes
    // the contents to the wire in insertion order, with the standard
    // `Content-Length` / `Content-Type` / `Connection: close` lines emitted
    // automatically.
    std::vector<std::pair<std::string, std::string>> headers{};
};

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void;

} // namespace merovingian::homeserver
