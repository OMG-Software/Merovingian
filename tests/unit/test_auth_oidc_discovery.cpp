// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              OIDC DISCOVERY METADATA UNIT TESTS                         |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — GET /_matrix/client/v1/auth_metadata |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1auth_metadata |
// +-------------------------------------------------------------------------+

#include "merovingian/auth/oidc_discovery.hpp"
#include "merovingian/config/config.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace cjson = merovingian::canonicaljson;

namespace
{

[[nodiscard]] auto field(cjson::Object const& object, std::string_view key) -> cjson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto string_value(cjson::Value const* value) -> std::string
{
    if (value == nullptr)
    {
        return {};
    }
    auto const* text = std::get_if<std::string>(&value->storage());
    return text == nullptr ? std::string{} : *text;
}

[[nodiscard]] auto has_string_member(cjson::Object const& object, std::string_view key, std::string_view expected)
    -> bool
{
    return string_value(field(object, key)) == expected;
}

} // namespace

SCENARIO("OIDC metadata is absent when OIDC is not enabled", "[auth][oidc]")
{
    GIVEN("an empty OIDC configuration")
    {
        auto const config = merovingian::config::OidcConfig{};

        WHEN("auth metadata is built")
        {
            auto const metadata = merovingian::auth::make_auth_metadata(config);

            THEN("the result reports not configured")
            {
                REQUIRE_FALSE(metadata.configured);
                REQUIRE(metadata.fields.empty());
            }
        }
    }
}

SCENARIO("OIDC metadata contains all required v1.19 fields", "[auth][oidc]")
{
    GIVEN("a fully populated OIDC configuration")
    {
        auto config = merovingian::config::OidcConfig{};
        config.enabled = true;
        config.issuer = "https://account.example.com/";
        config.authorization_endpoint = "https://account.example.com/oauth2/auth";
        config.token_endpoint = "https://account.example.com/oauth2/token";
        config.registration_endpoint = "https://account.example.com/oauth2/clients/register";
        config.revocation_endpoint = "https://account.example.com/oauth2/revoke";
        config.device_authorization_endpoint = "https://account.example.com/oauth2/device";
        config.account_management_uri = "https://account.example.com/manage";
        config.account_management_actions_supported = {"org.matrix.profile", "org.matrix.devices_list",
                                                       "org.matrix.account_deactivate"};

        WHEN("auth metadata is built")
        {
            auto const metadata = merovingian::auth::make_auth_metadata(config);

            THEN("the result reports configured and contains every required field")
            {
                REQUIRE(metadata.configured);
                REQUIRE(has_string_member(metadata.fields, "issuer", config.issuer));
                REQUIRE(has_string_member(metadata.fields, "authorization_endpoint", config.authorization_endpoint));
                REQUIRE(has_string_member(metadata.fields, "token_endpoint", config.token_endpoint));
                REQUIRE(has_string_member(metadata.fields, "registration_endpoint", config.registration_endpoint));
                REQUIRE(has_string_member(metadata.fields, "revocation_endpoint", config.revocation_endpoint));
                REQUIRE(has_string_member(metadata.fields, "device_authorization_endpoint",
                                          config.device_authorization_endpoint));
                REQUIRE(has_string_member(metadata.fields, "account_management_uri", config.account_management_uri));
            }
        }
    }
}

SCENARIO("OIDC metadata omits optional fields when they are empty", "[auth][oidc]")
{
    GIVEN("an OIDC configuration without optional endpoints")
    {
        auto config = merovingian::config::OidcConfig{};
        config.enabled = true;
        config.issuer = "https://auth.example.com/";
        config.authorization_endpoint = "https://auth.example.com/auth";
        config.token_endpoint = "https://auth.example.com/token";
        config.registration_endpoint = "https://auth.example.com/register";
        config.revocation_endpoint = "https://auth.example.com/revoke";

        WHEN("auth metadata is built")
        {
            auto const metadata = merovingian::auth::make_auth_metadata(config);

            THEN("device_authorization_endpoint and account_management_uri are absent")
            {
                REQUIRE(metadata.configured);
                REQUIRE(field(metadata.fields, "device_authorization_endpoint") == nullptr);
                REQUIRE(field(metadata.fields, "account_management_uri") == nullptr);
                REQUIRE(field(metadata.fields, "account_management_actions_supported") == nullptr);
            }
        }
    }
}

SCENARIO("OIDC metadata advertises the required grant and response types", "[auth][oidc]")
{
    GIVEN("a minimal enabled OIDC configuration")
    {
        auto config = merovingian::config::OidcConfig{};
        config.enabled = true;
        config.issuer = "https://auth.example.com/";
        config.authorization_endpoint = "https://auth.example.com/auth";
        config.token_endpoint = "https://auth.example.com/token";
        config.registration_endpoint = "https://auth.example.com/register";
        config.revocation_endpoint = "https://auth.example.com/revoke";

        WHEN("auth metadata is built")
        {
            auto const metadata = merovingian::auth::make_auth_metadata(config);

            THEN("the response_types_supported array contains exactly 'code'")
            {
                auto const* response_types = field(metadata.fields, "response_types_supported");
                REQUIRE(response_types != nullptr);
                auto const* array = std::get_if<cjson::Array>(&response_types->storage());
                REQUIRE(array != nullptr);
                REQUIRE(array->size() == 1U);
                REQUIRE(string_value(&array->front()) == "code");
            }

            THEN("the code_challenge_methods_supported array contains exactly 'S256'")
            {
                auto const* methods = field(metadata.fields, "code_challenge_methods_supported");
                REQUIRE(methods != nullptr);
                auto const* array = std::get_if<cjson::Array>(&methods->storage());
                REQUIRE(array != nullptr);
                REQUIRE(array->size() == 1U);
                REQUIRE(string_value(&array->front()) == "S256");
            }

            THEN("the grant_types_supported array contains 'authorization_code' and 'refresh_token'")
            {
                auto const* grants = field(metadata.fields, "grant_types_supported");
                REQUIRE(grants != nullptr);
                auto const* array = std::get_if<cjson::Array>(&grants->storage());
                REQUIRE(array != nullptr);
                REQUIRE(array->size() == 2U);
                REQUIRE(string_value(&array->at(0)) == "authorization_code");
                REQUIRE(string_value(&array->at(1)) == "refresh_token");
            }
        }
    }
}
