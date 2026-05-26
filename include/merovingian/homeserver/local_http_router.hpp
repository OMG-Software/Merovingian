// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

struct LocalHttpRequest final
{
    std::string method{};
    std::string target{};
    std::string access_token{};
    std::string body{};
};

struct LocalHttpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
};

[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
auto wire_federation_callbacks(HomeserverRuntime& runtime) -> void;

} // namespace merovingian::homeserver
