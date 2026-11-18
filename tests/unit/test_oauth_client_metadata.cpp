// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth::ClientMetadata (spec v1.19 Client-Server API "Client metadata", "Dynamic client registration flow",
// RFC 7591; ADR-0771).

#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;
using merovingian::oauth::ClientMetadata;
using merovingian::oauth::OAuthRefusal;

[[nodiscard]] auto parse(std::string_view json) -> Value
{
    auto parsed = merovingian::canonicaljson::parse_json(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto validate(std::string_view json) -> std::variant<ClientMetadata, OAuthRefusal>
{
    return ClientMetadata::validate(parse(json));
}

[[nodiscard]] auto refusal_code(std::variant<ClientMetadata, OAuthRefusal> const& result) -> std::string
{
    auto const* refusal = std::get_if<OAuthRefusal>(&result);
    return refusal == nullptr ? std::string{} : refusal->error_code;
}

[[nodiscard]] auto canonical(std::variant<ClientMetadata, OAuthRefusal> const& result) -> std::string
{
    auto const* metadata = std::get_if<ClientMetadata>(&result);
    REQUIRE(metadata != nullptr);
    auto bytes = metadata->canonical_bytes();
    REQUIRE(std::holds_alternative<std::string>(bytes));
    return std::get<std::string>(std::move(bytes));
}

// The smallest valid web registration.
constexpr auto minimal_web =
    std::string_view{R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"]})"};

} // namespace

SCENARIO("The spec's registration example registers what the spec's answer shows", "[oauth][metadata]")
{
    // Spec v1.19 Client-Server API, "Dynamic client registration flow": the example request and response.
    GIVEN("the example registration request")
    {
        auto const request = std::string_view{R"({
          "client_name": "My App",
          "client_name#fr": "Mon application",
          "client_uri": "https://example.com/",
          "logo_uri": "https://example.com/logo.png",
          "tos_uri": "https://example.com/tos.html",
          "tos_uri#fr": "https://example.com/fr/tos.html",
          "policy_uri": "https://example.com/policy.html",
          "policy_uri#fr": "https://example.com/fr/policy.html",
          "redirect_uris": ["https://app.example.com/callback"],
          "token_endpoint_auth_method": "none",
          "response_types": ["code"],
          "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
          "application_type": "web"
        })"};

        WHEN("it is validated and serialised")
        {
            auto const result = validate(request);

            THEN("the localised values, the logo and the unknown grant type are not registered")
            {
                REQUIRE(canonical(result) ==
                        R"({"application_type":"web","client_name":"My App","client_uri":"https://example.com/",)"
                        R"("grant_types":["authorization_code","refresh_token"],)"
                        R"("policy_uri":"https://example.com/policy.html",)"
                        R"("redirect_uris":["https://app.example.com/callback"],"response_types":["code"],)"
                        R"("token_endpoint_auth_method":"none","tos_uri":"https://example.com/tos.html"})");
                auto const& metadata = std::get<ClientMetadata>(result);
                REQUIRE(metadata.application_type() == merovingian::oauth::ApplicationType::web);
                REQUIRE(metadata.has_grant_type("refresh_token"));
                REQUIRE_FALSE(metadata.has_grant_type("urn:ietf:params:oauth:grant-type:token-exchange"));
            }
        }
    }
}

SCENARIO("Omitted members take the RFC 7591 defaults", "[oauth][metadata]")
{
    GIVEN("a registration with only client_uri and redirect_uris")
    {
        WHEN("it is validated")
        {
            auto const result = validate(minimal_web);

            THEN("it is a web client with the authorization_code grant, the code response type and auth method none")
            {
                auto const* metadata = std::get_if<ClientMetadata>(&result);
                REQUIRE(metadata != nullptr);
                REQUIRE(metadata->application_type() == merovingian::oauth::ApplicationType::web);
                REQUIRE(metadata->grant_types() == std::vector<std::string>{"authorization_code"});
                REQUIRE(metadata->response_types() == std::vector<std::string>{"code"});
                REQUIRE_FALSE(metadata->client_name().has_value());
                REQUIRE(canonical(result).find(R"("token_endpoint_auth_method":"none")") != std::string::npos);
            }
        }
    }
}

SCENARIO("The canonical bytes ignore key order, duplicate values and ignored members", "[oauth][metadata]")
{
    GIVEN("two requests for the same metadata written differently")
    {
        auto const first = std::string_view{R"({"client_uri":"https://example.com/","application_type":"native",)"
                                            R"("redirect_uris":["com.example.app:/cb","http://127.0.0.1/cb"],)"
                                            R"("grant_types":["refresh_token","authorization_code"]})"};
        auto const second = std::string_view{
            R"({"logo_uri":"https://example.com/l.png","grant_types":["authorization_code","x","refresh_token",)"
            R"("authorization_code"],"redirect_uris":["http://127.0.0.1/cb","com.example.app:/cb",)"
            R"("http://127.0.0.1/cb"],"client_name#de":"App","response_types":["code","token","code"],)"
            R"("token_endpoint_auth_method":"none","unknown":{"deep":[1,2]},"application_type":"native",)"
            R"("client_uri":"https://example.com/"})"};

        WHEN("both are validated")
        {
            auto const a = canonical(validate(first));
            auto const b = canonical(validate(second));

            THEN("the canonical bytes are identical")
            {
                REQUIRE(a == b);
                REQUIRE(a == R"({"application_type":"native","client_uri":"https://example.com/",)"
                             R"("grant_types":["authorization_code","refresh_token"],)"
                             R"("redirect_uris":["com.example.app:/cb","http://127.0.0.1/cb"],)"
                             R"("response_types":["code"],"token_endpoint_auth_method":"none"})");
            }
        }
    }
}

SCENARIO("A known member of the wrong JSON type is invalid_client_metadata", "[oauth][metadata][security]")
{
    GIVEN("registrations each giving one known member the wrong type")
    {
        auto const bodies = std::array<std::string_view, 12>{
            R"({"client_uri":1})",
            R"({"client_uri":null})",
            R"({"client_uri":"https://example.com/","redirect_uris":"https://example.com/cb"})",
            R"({"client_uri":"https://example.com/","redirect_uris":[1]})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"application_type":["web"]})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"grant_types":"authorization_code"})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"grant_types":[true]})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"response_types":{}})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":0})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"client_name":5})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"policy_uri":false})",
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"tos_uri":[]})",
        };

        WHEN("each is validated")
        {
            THEN("each is refused with invalid_client_metadata")
            {
                for (auto const body : bodies)
                {
                    INFO(body);
                    REQUIRE(refusal_code(validate(body)) == merovingian::oauth::error_invalid_client_metadata);
                }
                REQUIRE(refusal_code(validate("[]")) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate("{}")) == merovingian::oauth::error_invalid_client_metadata);
            }
        }
    }
}

SCENARIO("Unsupported application types and auth methods are refused", "[oauth][metadata]")
{
    GIVEN("a registration with application_type desktop, and one with client_secret_basic")
    {
        auto const desktop = std::string_view{
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"application_type":"desktop"})"};
        auto const secret =
            std::string_view{R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],)"
                             R"("token_endpoint_auth_method":"client_secret_basic"})"};

        WHEN("each is validated")
        {
            THEN("each is invalid_client_metadata")
            {
                REQUIRE(refusal_code(validate(desktop)) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(secret)) == merovingian::oauth::error_invalid_client_metadata);
            }
        }
    }
}

SCENARIO("A bad redirect URI is invalid_redirect_uri; too many is invalid_client_metadata", "[oauth][metadata]")
{
    GIVEN("a registration with an off-host redirect URI and one with 17 redirect URIs")
    {
        auto const off_host = std::string_view{
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb","https://app.com/cb"]})"};
        auto many = std::string{R"({"client_uri":"https://example.com/","redirect_uris":[)"};
        for (auto index = std::size_t{0U}; index < 17U; ++index)
        {
            many.append(index == 0U ? "" : ",");
            many.append("\"https://example.com/cb" + std::to_string(index) + "\"");
        }
        many.append("]}");

        WHEN("each is validated")
        {
            THEN("the error codes are as stated, and 16 URIs are accepted")
            {
                REQUIRE(refusal_code(validate(off_host)) == merovingian::oauth::error_invalid_redirect_uri);
                REQUIRE(refusal_code(validate(many)) == merovingian::oauth::error_invalid_client_metadata);
                auto sixteen = std::string{R"({"client_uri":"https://example.com/","redirect_uris":[)"};
                for (auto index = std::size_t{0U}; index < 16U; ++index)
                {
                    sixteen.append(index == 0U ? "" : ",");
                    sixteen.append("\"https://example.com/cb" + std::to_string(index) + "\"");
                }
                sixteen.append("]}");
                REQUIRE(refusal_code(validate(sixteen)).empty());
            }
        }
    }
}

SCENARIO("The authorization_code grant needs the code response type and a redirect URI", "[oauth][metadata]")
{
    GIVEN("an authorization_code client with no redirect URI, and one whose only response type is token")
    {
        auto const no_redirect = std::string_view{R"({"client_uri":"https://example.com/"})"};
        auto const empty_redirects = std::string_view{R"({"client_uri":"https://example.com/","redirect_uris":[]})"};
        auto const token_only = std::string_view{
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"response_types":["token"]})"};

        WHEN("each is validated")
        {
            THEN("each is invalid_client_metadata")
            {
                REQUIRE(refusal_code(validate(no_redirect)) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(empty_redirects)) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(token_only)) == merovingian::oauth::error_invalid_client_metadata);
            }
        }
    }
}

SCENARIO("A device-grant client needs no redirect URI, and a client with no known grant is refused",
         "[oauth][metadata]")
{
    GIVEN("a device_code client without redirect URIs, and a client naming only an unknown grant")
    {
        auto const device =
            std::string_view{R"({"client_uri":"https://example.com/","application_type":"native",)"
                             R"("grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]})"};
        auto const unknown_only = std::string_view{
            R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],"grant_types":["implicit"]})"};

        WHEN("each is validated")
        {
            auto const device_result = validate(device);

            THEN("the device client is registered and the other refused")
            {
                auto const* metadata = std::get_if<ClientMetadata>(&device_result);
                REQUIRE(metadata != nullptr);
                REQUIRE(metadata->grant_types() == std::vector<std::string>{
                                                       "refresh_token",
                                                       "urn:ietf:params:oauth:grant-type:device_code",
                                                   });
                REQUIRE(metadata->redirect_uris().empty());
                REQUIRE(refusal_code(validate(unknown_only)) == merovingian::oauth::error_invalid_client_metadata);
            }
        }
    }
}

SCENARIO("client_name is capped and refuses control and bidirectional characters", "[oauth][metadata][security]")
{
    GIVEN("client names of 128 and 129 bytes, empty, with a newline, NUL, C1 control, RLO, LRI or invalid UTF-8")
    {
        auto const with_name = [](std::string name) {
            auto object = Object{};
            object.push_back(
                merovingian::canonicaljson::make_member("client_uri", Value{std::string{"https://example.com/"}}));
            auto uris = merovingian::canonicaljson::Array{};
            uris.emplace_back(std::string{"https://example.com/cb"});
            object.push_back(merovingian::canonicaljson::make_member("redirect_uris", Value{std::move(uris)}));
            object.push_back(merovingian::canonicaljson::make_member("client_name", Value{std::move(name)}));
            return ClientMetadata::validate(Value{std::move(object)});
        };

        WHEN("each is validated")
        {
            THEN("only the 128-byte plain and non-Latin names are registered")
            {
                REQUIRE(std::holds_alternative<ClientMetadata>(with_name(std::string(128U, 'a'))));
                REQUIRE(std::holds_alternative<ClientMetadata>(with_name("Élément \xe2\x9c\x93 アプリ")));
                for (auto const& bad : std::array<std::string, 9>{
                         std::string(129U, 'a'),
                         std::string{},
                         std::string{"a\nb"},
                         std::string{"a\0b", 3U},
                         std::string{"a\xc2\x85"},
                         std::string{"evil\xe2\x80\xaemoc.elpmaxe"},
                         std::string{"a\xe2\x81\xa6"},
                         std::string{"a\xff"},
                         std::string{"a\xe2\x80\xa8"},
                })
                {
                    REQUIRE(refusal_code(with_name(bad)) == merovingian::oauth::error_invalid_client_metadata);
                }
            }
        }
    }
}

SCENARIO("client_name refuses invisible characters that make two names look alike", "[oauth][metadata][security]")
{
    GIVEN("a name holding each invisible character, at the edges of each refused range, and names next to them")
    {
        auto const with_name = [](std::string name) {
            auto object = Object{};
            object.push_back(
                merovingian::canonicaljson::make_member("client_uri", Value{std::string{"https://example.com/"}}));
            auto uris = merovingian::canonicaljson::Array{};
            uris.emplace_back(std::string{"https://example.com/cb"});
            object.push_back(merovingian::canonicaljson::make_member("redirect_uris", Value{std::move(uris)}));
            object.push_back(merovingian::canonicaljson::make_member("client_name", Value{std::move(name)}));
            return ClientMetadata::validate(Value{std::move(object)});
        };

        WHEN("each is validated")
        {
            THEN("each invisible character is refused and its neighbours are registered")
            {
                // U+00AD, U+180E, U+200B, U+200D, U+2060, U+2064, U+FEFF, U+FFF9, U+FFFB, U+E0000, U+E0041, U+E007F.
                for (auto const& bad : std::array<std::string, 12>{
                         std::string{"Pay\xc2\xad"
                                     "Pal"},
                         std::string{"Pay\xe1\xa0\x8e"
                                     "Pal"},
                         std::string{"Pay\xe2\x80\x8b"
                                     "Pal"},
                         std::string{"Pay\xe2\x80\x8d"
                                     "Pal"},
                         std::string{"Pay\xe2\x81\xa0"
                                     "Pal"},
                         std::string{"Pay\xe2\x81\xa4"
                                     "Pal"},
                         std::string{"\xef\xbb\xbf"
                                     "PayPal"},
                         std::string{"Pay\xef\xbf\xb9"
                                     "Pal"},
                         std::string{"Pay\xef\xbf\xbb"
                                     "Pal"},
                         std::string{"Pay\xf3\xa0\x80\x80"
                                     "Pal"},
                         std::string{"PayPal\xf3\xa0\x81\x81"},
                         std::string{"PayPal\xf3\xa0\x81\xbf"},
                     })
                {
                    INFO(bad);
                    REQUIRE(refusal_code(with_name(bad)) == merovingian::oauth::error_invalid_client_metadata);
                }
                // U+00AC, U+00AE, U+200A, U+2065 (unassigned, outside both ranges), U+FFFC, U+E0080, U+1F600.
                for (auto const& good : std::array<std::string, 7>{
                         std::string{"Pay\xc2\xac"
                                     "Pal"},
                         std::string{"Pay\xc2\xae"
                                     "Pal"},
                         std::string{"Pay\xe2\x80\x8a"
                                     "Pal"},
                         std::string{"Pay\xe2\x81\xa5"
                                     "Pal"},
                         std::string{"Pay\xef\xbf\xbc"
                                     "Pal"},
                         std::string{"Pay\xf3\xa0\x82\x80"
                                     "Pal"},
                         std::string{"Pay\xf0\x9f\x98\x80"
                                     "Pal"},
                     })
                {
                    INFO(good);
                    REQUIRE(std::holds_alternative<ClientMetadata>(with_name(good)));
                }
            }
        }
    }
}

SCENARIO("policy_uri and tos_uri must be https on the client host", "[oauth][metadata][security]")
{
    GIVEN("policy and terms URIs on http, another host, with userinfo, and a subdomain")
    {
        auto const body = [](std::string_view key, std::string_view uri) {
            return std::string{R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],")"} +
                   std::string{key} + R"(":")" + std::string{uri} + R"("})";
        };

        WHEN("each is validated")
        {
            THEN("only the subdomain is accepted")
            {
                REQUIRE(refusal_code(validate(body("policy_uri", "https://docs.example.com/p"))).empty());
                REQUIRE(refusal_code(validate(body("policy_uri", "http://example.com/p"))) ==
                        merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(body("tos_uri", "https://evil.example/t"))) ==
                        merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(body("tos_uri", "https://u@example.com/t"))) ==
                        merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(validate(body("tos_uri", "javascript:alert(1)"))) ==
                        merovingian::oauth::error_invalid_client_metadata);
            }
        }
    }
}

SCENARIO("An object with more than 128 members or a repeated key is refused", "[oauth][metadata][boundary]")
{
    GIVEN("a registration padded to 129 members, and an object built with client_uri twice")
    {
        auto padded = std::string{R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"])"};
        for (auto index = std::size_t{0U}; index < 127U; ++index)
        {
            padded.append(",\"x" + std::to_string(index) + "\":0");
        }
        padded.append("}");
        auto repeated = Object{};
        repeated.push_back(
            merovingian::canonicaljson::make_member("client_uri", Value{std::string{"https://example.com/"}}));
        repeated.push_back(
            merovingian::canonicaljson::make_member("client_uri", Value{std::string{"https://evil.example/"}}));

        WHEN("each is validated")
        {
            auto const padded_result = validate(padded);
            auto const repeated_result = ClientMetadata::validate(Value{std::move(repeated)});

            THEN("each is invalid_client_metadata and the messages quote nothing")
            {
                REQUIRE(refusal_code(padded_result) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(refusal_code(repeated_result) == merovingian::oauth::error_invalid_client_metadata);
                REQUIRE(std::get<OAuthRefusal>(repeated_result).error.message().find("evil") == std::string::npos);
            }
        }
    }
}
