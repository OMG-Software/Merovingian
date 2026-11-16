// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// OAuthBaseUrl, the one builder of every absolute OAuth address, and server_metadata, the auth_metadata document
// (ADR-0773; spec "Server metadata discovery").

#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"
#include "merovingian/oauth/OAuthPaths.hpp"
#include "merovingian/oauth/ServerMetadata.hpp"
#include "merovingian/oauth/ServerMetadataOptions.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;
using merovingian::oauth::OAuthBaseUrl;

[[nodiscard]] auto read_base(std::string_view text) -> OAuthBaseUrl
{
    auto result = OAuthBaseUrl::read(text);
    REQUIRE(std::holds_alternative<OAuthBaseUrl>(result));
    return std::get<OAuthBaseUrl>(std::move(result));
}

[[nodiscard]] auto as_object(Value const& value) -> Object const&
{
    auto const* object = std::get_if<Object>(&value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

[[nodiscard]] auto member(Object const& object, std::string_view key) -> Value const*
{
    for (auto const& entry : object)
    {
        if (entry.key == key)
        {
            return entry.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto text(Object const& object, std::string_view key) -> std::string
{
    auto const* value = member(object, key);
    REQUIRE(value != nullptr);
    auto const* string = std::get_if<std::string>(&value->storage());
    REQUIRE(string != nullptr);
    return *string;
}

[[nodiscard]] auto texts(Object const& object, std::string_view key) -> std::vector<std::string>
{
    auto const* value = member(object, key);
    REQUIRE(value != nullptr);
    auto const* array = std::get_if<merovingian::canonicaljson::Array>(&value->storage());
    REQUIRE(array != nullptr);
    auto out = std::vector<std::string>{};
    for (auto const& item : *array)
    {
        auto const* string = std::get_if<std::string>(&item.storage());
        REQUIRE(string != nullptr);
        out.push_back(*string);
    }
    return out;
}

} // namespace

SCENARIO("the OAuth paths are the documented constants", "[oauth][urls]")
{
    GIVEN("the path constants")
    {
        WHEN("they are read")
        {
            THEN("each names its route under /_merovingian/")
            {
                CHECK(merovingian::oauth::register_path.view() == "/_merovingian/oauth2/register");
                CHECK(merovingian::oauth::authorize_path.view() == "/_merovingian/oauth2/authorize");
                CHECK(merovingian::oauth::token_path.view() == "/_merovingian/oauth2/token");
                CHECK(merovingian::oauth::revoke_path.view() == "/_merovingian/oauth2/revoke");
                CHECK(merovingian::oauth::device_path.view() == "/_merovingian/oauth2/device");
                CHECK(merovingian::oauth::link_path.view() == "/_merovingian/oauth2/link");
                CHECK(merovingian::oauth::account_path.view() == "/_merovingian/account");
                CHECK(merovingian::oauth::auth_metadata_path == "/_matrix/client/v1/auth_metadata");
                CHECK(merovingian::oauth::auth_metadata_unstable_path ==
                      "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata");
            }
        }
    }
}

SCENARIO("the issuer is the base URL with exactly one trailing slash", "[oauth][urls]")
{
    GIVEN("base URLs with and without a path and trailing slashes")
    {
        struct Case final
        {
            std::string_view base;
            std::string_view issuer;
            std::string_view token;
        };
        auto const sample = GENERATE(Case{"https://matrix.example.org", "https://matrix.example.org/",
                                          "https://matrix.example.org/_merovingian/oauth2/token"},
                                     Case{"https://matrix.example.org/", "https://matrix.example.org/",
                                          "https://matrix.example.org/_merovingian/oauth2/token"},
                                     Case{"https://matrix.example.org//", "https://matrix.example.org/",
                                          "https://matrix.example.org/_merovingian/oauth2/token"},
                                     Case{"https://example.org/matrix", "https://example.org/matrix/",
                                          "https://example.org/matrix/_merovingian/oauth2/token"},
                                     Case{"https://example.org/matrix/", "https://example.org/matrix/",
                                          "https://example.org/matrix/_merovingian/oauth2/token"},
                                     Case{"https://example.org:8448/a/b/", "https://example.org:8448/a/b/",
                                          "https://example.org:8448/a/b/_merovingian/oauth2/token"});

        WHEN("the base URL is read and its addresses are built")
        {
            auto const base = read_base(sample.base);

            THEN("the issuer ends in one slash and each endpoint is the base without its slashes plus the path")
            {
                INFO(sample.base);
                CHECK(base.issuer() == sample.issuer);
                CHECK(base.url(merovingian::oauth::token_path) == sample.token);
                CHECK(base.uri().text() == sample.base);
            }
        }
    }
}

SCENARIO("a base URL that is not an https URL with a host and no query is refused", "[oauth][urls]")
{
    GIVEN("a base URL that breaks a rule")
    {
        auto const text = GENERATE(as<std::string>{}, "", "http://matrix.example.org", "HTTPS://matrix.example.org",
                                   "https:matrix.example.org", "https://", "https://matrix.example.org/?a=b",
                                   "https://matrix.example.org?", "https://matrix.example.org/#top",
                                   "https://user@matrix.example.org", "https://matrix example.org",
                                   "https://matrix.example.org/a\tb");

        WHEN("it is read")
        {
            auto const result = OAuthBaseUrl::read(text);

            THEN("it is refused with fixed text that does not quote the input")
            {
                INFO(text);
                auto const* error = std::get_if<merovingian::core::Error>(&result);
                REQUIRE(error != nullptr);
                CHECK(error->code() != merovingian::core::ErrorCode::none);
                CHECK(error->message().find("matrix") == std::string::npos);
            }
        }
    }

    GIVEN("a base URL longer than the reader's 2048-byte cap")
    {
        auto const text = "https://matrix.example.org/" + std::string(2048U, 'a');

        WHEN("it is read")
        {
            auto const result = OAuthBaseUrl::read(text);

            THEN("it is refused as too long")
            {
                auto const* error = std::get_if<merovingian::core::Error>(&result);
                REQUIRE(error != nullptr);
                CHECK(error->code() == merovingian::core::ErrorCode::invalid_argument);
            }
        }
    }
}

SCENARIO("the server metadata holds the required fields, every address built from the base URL",
         "[oauth][server_metadata]")
{
    GIVEN("a base URL with a path and the default options")
    {
        auto const base = read_base("https://example.org/matrix/");

        WHEN("the metadata is built")
        {
            auto const value = merovingian::oauth::server_metadata(base, {});
            auto const& object = as_object(value);

            THEN("each required field is present with the address or list the spec asks for")
            {
                CHECK(text(object, "issuer") == "https://example.org/matrix/");
                CHECK(text(object, "authorization_endpoint") ==
                      "https://example.org/matrix/_merovingian/oauth2/authorize");
                CHECK(text(object, "token_endpoint") == "https://example.org/matrix/_merovingian/oauth2/token");
                CHECK(text(object, "registration_endpoint") ==
                      "https://example.org/matrix/_merovingian/oauth2/register");
                CHECK(text(object, "revocation_endpoint") == "https://example.org/matrix/_merovingian/oauth2/revoke");
                CHECK(texts(object, "response_types_supported") == std::vector<std::string>{"code"});
                CHECK(texts(object, "response_modes_supported") == std::vector<std::string>{"query", "fragment"});
                CHECK(texts(object, "grant_types_supported") ==
                      std::vector<std::string>{"authorization_code", "refresh_token"});
                CHECK(texts(object, "code_challenge_methods_supported") == std::vector<std::string>{"S256"});
            }

            THEN("nothing optional is advertised")
            {
                CHECK(member(object, "device_authorization_endpoint") == nullptr);
                CHECK(member(object, "prompt_values_supported") == nullptr);
                CHECK(member(object, "account_management_uri") == nullptr);
                CHECK(member(object, "account_management_actions_supported") == nullptr);
                CHECK(object.size() == 9U);
            }
        }
    }
}

SCENARIO("the server metadata follows its options", "[oauth][server_metadata]")
{
    GIVEN("a base URL without a path")
    {
        auto const base = read_base("https://matrix.example.org");

        WHEN("the device grant is enabled")
        {
            auto options = merovingian::oauth::ServerMetadataOptions{};
            options.device_grant_enabled = true;
            auto const value = merovingian::oauth::server_metadata(base, options);
            auto const& object = as_object(value);

            THEN("the device code grant type and the device authorization endpoint are advertised")
            {
                CHECK(texts(object, "grant_types_supported") ==
                      std::vector<std::string>{"authorization_code", "refresh_token",
                                               "urn:ietf:params:oauth:grant-type:device_code"});
                CHECK(text(object, "device_authorization_endpoint") ==
                      "https://matrix.example.org/_merovingian/oauth2/device");
            }
        }

        WHEN("registration is enabled")
        {
            auto options = merovingian::oauth::ServerMetadataOptions{};
            options.registration_enabled = true;
            auto const value = merovingian::oauth::server_metadata(base, options);
            auto const& object = as_object(value);

            THEN("prompt_values_supported holds create alone")
            {
                CHECK(texts(object, "prompt_values_supported") == std::vector<std::string>{"create"});
            }
        }

        WHEN("account management actions are given")
        {
            auto options = merovingian::oauth::ServerMetadataOptions{};
            options.account_management_actions = {"org.matrix.profile", "org.matrix.devices_list"};
            auto const value = merovingian::oauth::server_metadata(base, options);
            auto const& object = as_object(value);

            THEN("the account page and the actions are advertised in order")
            {
                CHECK(text(object, "account_management_uri") == "https://matrix.example.org/_merovingian/account");
                CHECK(texts(object, "account_management_actions_supported") ==
                      std::vector<std::string>{"org.matrix.profile", "org.matrix.devices_list"});
            }
        }
    }
}
