// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Shared by the OAuth 2.0 client registration conformance and integration scenarios: a homeserver config with the
// OAuth 2.0 API on or off, and a POST to the registration endpoint as a client sends it.

#include "InMemoryDatabaseConfig.hpp"
#include "MasterKey.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace merovingian::tests
{

inline constexpr auto oauth_register_path = std::string_view{"/_merovingian/oauth2/register"};

// A homeserver at https://matrix.example.org with the OAuth 2.0 API on (or off), an in-memory database and the
// shared test master key, which derives the client ID key.
[[nodiscard]] inline auto oauth_registration_config(bool oauth_enabled = true,
                                                    config::ServerConfig server = config::ServerConfig{})
    -> config::Config
{
    auto security = config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    server.public_baseurl = "https://matrix.example.org";
    server.oauth.enabled = oauth_enabled;
    return {
        std::move(server),   config::ListenersConfig{},        in_memory_database_config(),
        std::move(security), config::ClientRateLimitsConfig{}, config::LogModulesConfig{},
    };
}

// POST `body` to the registration endpoint with `content_type` (no Content-Type header when empty).
[[nodiscard]] inline auto post_client_registration(homeserver::ClientServerRuntime& runtime, std::string body,
                                                   std::string_view content_type = "application/json",
                                                   std::string method = "POST") -> homeserver::LocalHttpResponse
{
    auto request =
        homeserver::LocalHttpRequest{std::move(method), std::string{oauth_register_path}, {}, std::move(body)};
    if (!content_type.empty())
    {
        request.headers.push_back({"Content-Type", std::string{content_type}});
    }
    return homeserver::handle_client_server_request(runtime, request, /*can_wait=*/false).response;
}

// The value of the response header `name` (exact name match, as the dispatcher writes them), or empty.
[[nodiscard]] inline auto response_header(homeserver::LocalHttpResponse const& response, std::string_view name)
    -> std::string
{
    for (auto const& [header_name, value] : response.headers)
    {
        if (header_name == name)
        {
            return value;
        }
    }
    return {};
}

} // namespace merovingian::tests
