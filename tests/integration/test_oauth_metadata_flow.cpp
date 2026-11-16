// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The OAuth 2.0 server metadata as a client reads it from a running homeserver: the checks Element X (through
// matrix-rust-sdk) makes before it offers an OAuth login (docs/todos/oauth-2-0-api.md, "What Element X needs"), and
// the fields the configuration turns on and off.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

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

struct MetadataSettings final
{
    std::string public_baseurl{"https://matrix.example.org"};
    bool registration_enabled{false};
    bool device_grant_enabled{false};
};

[[nodiscard]] auto oauth_config(MetadataSettings const& settings) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    if (settings.registration_enabled)
    {
        merovingian::tests::enable_token_registration(security);
    }
    auto server = merovingian::config::ServerConfig{};
    server.public_baseurl = settings.public_baseurl;
    server.oauth.enabled = true;
    server.oauth.device_grant_enabled = settings.device_grant_enabled;
    return {
        std::move(server),
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto fetch_metadata(MetadataSettings const& settings) -> merovingian::canonicaljson::Object
{
    auto started = merovingian::homeserver::start_client_server(oauth_config(settings));
    REQUIRE(started.started);
    auto const response = merovingian::homeserver::handle_client_server_request(
        started.runtime, {"GET", "/_matrix/client/v1/auth_metadata", {}, {}});
    REQUIRE(response.response.status == 200U);
    return parse_object(response.response.body);
}

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

// Every member whose value is a URL: its name ends in `_endpoint` or `_uri`, or it is the issuer.
[[nodiscard]] auto url_members(merovingian::canonicaljson::Object const& object)
    -> std::vector<std::pair<std::string, std::string>>
{
    auto out = std::vector<std::pair<std::string, std::string>>{};
    for (auto const& member : object)
    {
        auto const is_url = member.key == "issuer" || member.key.ends_with("_endpoint") || member.key.ends_with("_uri");
        auto const* text = member.value == nullptr ? nullptr : std::get_if<std::string>(&member.value->storage());
        if (is_url && text != nullptr)
        {
            out.emplace_back(member.key, *text);
        }
    }
    return out;
}

} // namespace

SCENARIO("auth_metadata passes every check Element X makes before an OAuth login", "[homeserver][oauth][element-x]")
{
    GIVEN("a running homeserver with the OAuth 2.0 API on")
    {
        WHEN("auth_metadata is read")
        {
            auto const body = fetch_metadata({});

            THEN("every URL uses https")
            {
                auto const urls = url_members(body);
                // issuer and the four required endpoints at least.
                REQUIRE(urls.size() >= 5U);
                for (auto const& [key, url] : urls)
                {
                    INFO(key << " = " << url);
                    CHECK(url.starts_with("https://"));
                }
            }

            THEN("the issuer has no query or fragment")
            {
                auto const* issuer = string_member(body, "issuer");
                REQUIRE(issuer != nullptr);
                CHECK(issuer->find('?') == std::string::npos);
                CHECK(issuer->find('#') == std::string::npos);
            }

            THEN("the four supported lists hold the values the SDK requires")
            {
                CHECK(holds(string_list(body, "response_types_supported"), "code"));
                CHECK(holds(string_list(body, "response_modes_supported"), "query"));
                CHECK(holds(string_list(body, "response_modes_supported"), "fragment"));
                CHECK(holds(string_list(body, "grant_types_supported"), "authorization_code"));
                CHECK(holds(string_list(body, "grant_types_supported"), "refresh_token"));
                CHECK(holds(string_list(body, "code_challenge_methods_supported"), "S256"));
            }

            THEN("a revocation endpoint and a registration endpoint are advertised")
            {
                auto const* revocation = string_member(body, "revocation_endpoint");
                REQUIRE(revocation != nullptr);
                CHECK(*revocation == "https://matrix.example.org/_merovingian/oauth2/revoke");
                auto const* registration = string_member(body, "registration_endpoint");
                REQUIRE(registration != nullptr);
                CHECK(*registration == "https://matrix.example.org/_merovingian/oauth2/register");
            }

            THEN("the account management fields are not advertised before the account pages exist")
            {
                CHECK(object_member(body, "account_management_uri") == nullptr);
                CHECK(object_member(body, "account_management_actions_supported") == nullptr);
            }
        }
    }
}

SCENARIO("auth_metadata derives every address from a public_baseurl with a path", "[homeserver][oauth]")
{
    GIVEN("a homeserver whose public_baseurl is https://example.org/matrix/")
    {
        WHEN("auth_metadata is read")
        {
            auto const body = fetch_metadata({.public_baseurl = "https://example.org/matrix/"});

            THEN("the issuer keeps one trailing slash and every endpoint sits under the path")
            {
                auto const* issuer = string_member(body, "issuer");
                REQUIRE(issuer != nullptr);
                CHECK(*issuer == "https://example.org/matrix/");
                auto const* token = string_member(body, "token_endpoint");
                REQUIRE(token != nullptr);
                CHECK(*token == "https://example.org/matrix/_merovingian/oauth2/token");
                auto const* authorize = string_member(body, "authorization_endpoint");
                REQUIRE(authorize != nullptr);
                CHECK(*authorize == "https://example.org/matrix/_merovingian/oauth2/authorize");
            }
        }
    }
}

SCENARIO("auth_metadata offers prompt=create only while registration is enabled", "[homeserver][oauth]")
{
    GIVEN("one homeserver with registration enabled and one without")
    {
        WHEN("auth_metadata is read from each")
        {
            auto const open = fetch_metadata({.registration_enabled = true});
            auto const closed = fetch_metadata({.registration_enabled = false});

            THEN("prompt_values_supported is [create] with registration on and absent with it off")
            {
                auto const prompts = string_list(open, "prompt_values_supported");
                REQUIRE(prompts.has_value());
                CHECK(*prompts == std::vector<std::string>{"create"});
                CHECK(object_member(closed, "prompt_values_supported") == nullptr);
            }
        }
    }
}

SCENARIO("auth_metadata advertises the device grant only while server.oauth.device_grant_enabled is true",
         "[homeserver][oauth]")
{
    GIVEN("one homeserver with the device grant on and one with it off")
    {
        WHEN("auth_metadata is read from each")
        {
            auto const on = fetch_metadata({.device_grant_enabled = true});
            auto const off = fetch_metadata({.device_grant_enabled = false});

            THEN("the device code grant type and device_authorization_endpoint appear only with it on")
            {
                constexpr auto device_code = std::string_view{"urn:ietf:params:oauth:grant-type:device_code"};
                CHECK(holds(string_list(on, "grant_types_supported"), device_code));
                auto const* endpoint = string_member(on, "device_authorization_endpoint");
                REQUIRE(endpoint != nullptr);
                CHECK(*endpoint == "https://matrix.example.org/_merovingian/oauth2/device");
                CHECK_FALSE(holds(string_list(off, "grant_types_supported"), device_code));
                CHECK(object_member(off, "device_authorization_endpoint") == nullptr);
            }
        }
    }
}
