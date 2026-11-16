// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              OAUTH 2.0 SERVER METADATA CONFORMANCE TESTS                |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "Server metadata discovery"     |
// |        and "Authentication API discovery"                               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+
//
// `GET /_matrix/client/v1/auth_metadata`, and the same document at the MSC2965 unstable path, with the built-in
// OAuth 2.0 API on and off.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;

constexpr auto stable_path = std::string_view{"/_matrix/client/v1/auth_metadata"};
constexpr auto unstable_path = std::string_view{"/_matrix/client/unstable/org.matrix.msc2965/auth_metadata"};

[[nodiscard]] auto metadata_config(bool oauth_enabled) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    auto server = merovingian::config::ServerConfig{};
    server.public_baseurl = "https://matrix.example.org";
    server.oauth.enabled = oauth_enabled;
    return {
        std::move(server),
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto get(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view path)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(runtime, {"GET", std::string{path}, {}, {}}).response;
}

// The strings of the array member `key`, or nothing when it is absent or not an array of strings.
[[nodiscard]] auto string_list(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::optional<std::vector<std::string>>
{
    auto const* array = object_member_as_array(object, key);
    if (array == nullptr)
    {
        return std::nullopt;
    }
    auto out = std::vector<std::string>{};
    for (auto const& item : *array)
    {
        auto const* text = std::get_if<std::string>(&item.storage());
        if (text == nullptr)
        {
            return std::nullopt;
        }
        out.push_back(*text);
    }
    return out;
}

[[nodiscard]] auto holds(std::optional<std::vector<std::string>> const& list, std::string_view value) -> bool
{
    if (!list.has_value())
    {
        return false;
    }
    for (auto const& item : *list)
    {
        if (item == value)
        {
            return true;
        }
    }
    return false;
}

[[nodiscard]] auto header(merovingian::homeserver::LocalHttpResponse const& response, std::string_view name)
    -> std::optional<std::string>
{
    for (auto const& [key, value] : response.headers)
    {
        if (key == name)
        {
            return value;
        }
    }
    return std::nullopt;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/auth_metadata; Authentication API discovery
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1auth_metadata
//      ../../docs/matrix-v1.19-spec/client-server-api.md#authentication-api-discovery
//
// "404 With M_UNRECOGNIZED: the homeserver does not support the OAuth 2.0 API." Discovery: "the server SHOULD respond
// with 404 and an M_UNRECOGNIZED error code if the corresponding API is not supported." The endpoint "Requires
// authentication: No", so the probe is never answered 401.
SCENARIO("auth_metadata is 404 M_UNRECOGNIZED on both paths while the OAuth 2.0 API is off",
         "[conformance][client-server][oauth][auth_metadata]")
{
    GIVEN("a running homeserver with server.oauth.enabled left false")
    {
        auto started = merovingian::homeserver::start_client_server(metadata_config(false));
        REQUIRE(started.started);

        for (auto const path : std::array{stable_path, unstable_path})
        {
            WHEN("GET " + std::string{path} + " is called without a token")
            {
                auto const response = get(started.runtime, path);

                THEN("it is 404 M_UNRECOGNIZED, not 401")
                {
                    // Spec SHOULD: 404 when the OAuth 2.0 API is not supported.
                    REQUIRE(response.status == 404U);
                    auto const body = parse_object(response.body);
                    auto const* errcode = string_member(body, "errcode");
                    REQUIRE(errcode != nullptr);
                    // Spec SHOULD: the error code is M_UNRECOGNIZED.
                    REQUIRE(*errcode == "M_UNRECOGNIZED");
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v1/auth_metadata, 200 response
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1auth_metadata
//
// Required: issuer (an https URL with no query or fragment), authorization_endpoint, token_endpoint,
// registration_endpoint, revocation_endpoint, response_types_supported (MUST contain `code`),
// response_modes_supported (MUST contain `query` and `fragment`), grant_types_supported (MUST contain
// `authorization_code` and `refresh_token`), code_challenge_methods_supported (MUST contain `S256`).
SCENARIO("auth_metadata answers the required metadata on both paths while the OAuth 2.0 API is on",
         "[conformance][client-server][oauth][auth_metadata]")
{
    GIVEN("a running homeserver with server.oauth.enabled=true and public_baseurl https://matrix.example.org")
    {
        auto started = merovingian::homeserver::start_client_server(metadata_config(true));
        REQUIRE(started.started);

        for (auto const path : std::array{stable_path, unstable_path})
        {
            WHEN("GET " + std::string{path} + " is called without a token")
            {
                auto const response = get(started.runtime, path);

                THEN("it is 200 with every required field")
                {
                    // Spec: "Requires authentication: No"; 200 is the metadata.
                    REQUIRE(response.status == 200U);
                    auto const body = parse_object(response.body);

                    auto const* issuer = string_member(body, "issuer");
                    REQUIRE(issuer != nullptr);
                    // Spec MUST (issuer): "a URL that uses the https scheme and has no query or fragment components".
                    REQUIRE(issuer->starts_with("https://"));
                    REQUIRE(issuer->find('?') == std::string::npos);
                    REQUIRE(issuer->find('#') == std::string::npos);

                    for (auto const* key :
                         {"authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"})
                    {
                        INFO(key);
                        // Spec: each endpoint is Required.
                        REQUIRE(string_member(body, key) != nullptr);
                    }

                    // Spec MUST: response_types_supported contains `code`.
                    REQUIRE(holds(string_list(body, "response_types_supported"), "code"));
                    // Spec MUST: response_modes_supported contains `query` and `fragment`.
                    REQUIRE(holds(string_list(body, "response_modes_supported"), "query"));
                    REQUIRE(holds(string_list(body, "response_modes_supported"), "fragment"));
                    // Spec MUST: grant_types_supported contains `authorization_code` and `refresh_token`.
                    REQUIRE(holds(string_list(body, "grant_types_supported"), "authorization_code"));
                    REQUIRE(holds(string_list(body, "grant_types_supported"), "refresh_token"));
                    // Spec MUST: code_challenge_methods_supported contains `S256`.
                    REQUIRE(holds(string_list(body, "code_challenge_methods_supported"), "S256"));
                }
            }
        }

        WHEN("both paths are requested")
        {
            auto const stable = get(started.runtime, stable_path);
            auto const unstable = get(started.runtime, unstable_path);

            THEN("they answer the same document")
            {
                REQUIRE(stable.status == 200U);
                // MSC2965's unstable path names the endpoint the spec stabilised as /v1/auth_metadata.
                REQUIRE(unstable.body == stable.body);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Web Browser Clients; GET /_matrix/client/v1/auth_metadata
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#web-browser-clients
//
// "Servers MUST expose the following CORS headers on all /_matrix/ resources ... Access-Control-Allow-Origin: *".
// A browser client reads the metadata cross-origin before it can log in.
SCENARIO("auth_metadata carries the CORS headers on both paths", "[conformance][client-server][oauth][cors]")
{
    GIVEN("a running homeserver with the OAuth 2.0 API on and the default CORS policy")
    {
        auto started = merovingian::homeserver::start_client_server(metadata_config(true));
        REQUIRE(started.started);

        for (auto const path : std::array{stable_path, unstable_path})
        {
            WHEN("a browser sends GET " + std::string{path} + " with an Origin header")
            {
                auto const response =
                    merovingian::homeserver::handle_client_server_request(
                        started.runtime, {"GET", std::string{path}, {}, {}, {{"Origin", "https://app.element.io"}}})
                        .response;

                THEN("the answer carries Access-Control-Allow-Origin")
                {
                    REQUIRE(response.status == 200U);
                    // Spec MUST: Access-Control-Allow-Origin on all /_matrix/ resources.
                    auto const allow_origin = header(response, "Access-Control-Allow-Origin");
                    REQUIRE(allow_origin.has_value());
                    REQUIRE(!allow_origin->empty());
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Standard error response (M_UNRECOGNIZED)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#api-standards
//
// M_UNRECOGNIZED: "a 405 HTTP status code if the endpoint is implemented, but the incorrect HTTP method is used".
SCENARIO("auth_metadata answers another method 405 M_UNRECOGNIZED on both paths",
         "[conformance][client-server][oauth][auth_metadata]")
{
    GIVEN("a running homeserver with the OAuth 2.0 API on")
    {
        auto started = merovingian::homeserver::start_client_server(metadata_config(true));
        REQUIRE(started.started);

        for (auto const path : std::array{stable_path, unstable_path})
        {
            WHEN("POST " + std::string{path} + " is called")
            {
                auto const response = merovingian::homeserver::handle_client_server_request(
                                          started.runtime, {"POST", std::string{path}, {}, "{}"})
                                          .response;

                THEN("it is 405 M_UNRECOGNIZED")
                {
                    // Spec MUST: 405 for an implemented endpoint used with the wrong method.
                    REQUIRE(response.status == 405U);
                    auto const body = parse_object(response.body);
                    auto const* errcode = string_member(body, "errcode");
                    REQUIRE(errcode != nullptr);
                    REQUIRE(*errcode == "M_UNRECOGNIZED");
                }
            }
        }
    }
}
