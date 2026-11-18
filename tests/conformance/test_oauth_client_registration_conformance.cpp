// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            OAUTH 2.0 CLIENT REGISTRATION CONFORMANCE TESTS              |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "Client registration",          |
// |        "Client metadata", "Redirect URI validation" and                 |
// |        "Dynamic client registration flow" (RFC 7591)                    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+
//
// Every requirement of those sections that `POST /_merovingian/oauth2/register` can show, through the endpoint.

#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;

// A registration of one redirect URI for `https://example.com/` as `application_type`.
[[nodiscard]] auto redirect_registration(std::string_view application_type, std::string_view redirect_uri)
    -> std::string
{
    return R"({"client_uri":"https://example.com/","application_type":")" + std::string{application_type} +
           R"(","redirect_uris":[")" + std::string{redirect_uri} + R"("],"token_endpoint_auth_method":"none"})";
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

[[nodiscard]] auto oauth_error_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* error = string_member(body, "error");
    return error == nullptr ? std::string{} : *error;
}

// The registration request of the spec's own example ("Dynamic client registration flow").
constexpr auto spec_example_request = std::string_view{R"({
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
  "grant_types": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "application_type": "web"
})"};

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Dynamic client registration flow
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#dynamic-client-registration-flow
//
// "Upon successful registration, the server replies with an HTTP 201 Created response, with a JSON object containing
// the allocated client_id and all the registered metadata values." The spec's example: the unknown grant type and the
// locale-specific values are not registered, so they are not in the answer.
SCENARIO("the spec's registration example is answered 201 with a client_id and the registered metadata",
         "[conformance][client-server][oauth][registration]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = merovingian::homeserver::start_client_server(oauth_registration_config());
        REQUIRE(started.started);

        WHEN("the spec's example registration request is posted")
        {
            auto const response = post_client_registration(started.runtime, std::string{spec_example_request});

            THEN("it is 201 with a JSON object holding a client_id and every registered value")
            {
                // Spec MUST: "replies with an HTTP 201 Created response".
                REQUIRE(response.status == 201U);
                CHECK(response_header(response, "Content-Type") == "application/json");
                auto const body = parse_object(response.body);
                auto const* client_id = string_member(body, "client_id");
                // Spec MUST: "a JSON object containing the allocated client_id".
                REQUIRE(client_id != nullptr);
                CHECK_FALSE(client_id->empty());
                // Spec MUST: "... and all the registered metadata values".
                REQUIRE(string_member(body, "client_name") != nullptr);
                CHECK(*string_member(body, "client_name") == "My App");
                REQUIRE(string_member(body, "client_uri") != nullptr);
                CHECK(*string_member(body, "client_uri") == "https://example.com/");
                REQUIRE(string_member(body, "tos_uri") != nullptr);
                CHECK(*string_member(body, "tos_uri") == "https://example.com/tos.html");
                REQUIRE(string_member(body, "policy_uri") != nullptr);
                CHECK(*string_member(body, "policy_uri") == "https://example.com/policy.html");
                REQUIRE(string_member(body, "application_type") != nullptr);
                CHECK(*string_member(body, "application_type") == "web");
                REQUIRE(string_member(body, "token_endpoint_auth_method") != nullptr);
                CHECK(*string_member(body, "token_endpoint_auth_method") == "none");
                CHECK(string_list(body, "redirect_uris") ==
                      std::vector<std::string>{"https://app.example.com/callback"});
                CHECK(string_list(body, "response_types") == std::vector<std::string>{"code"});
            }

            THEN("the unknown grant type is ignored and not in the answer")
            {
                REQUIRE(response.status == 201U);
                auto const body = parse_object(response.body);
                // Spec MUST: "The server MUST ignore values that it does not understand" (grant_types).
                CHECK(string_list(body, "grant_types") ==
                      std::vector<std::string>{"authorization_code", "refresh_token"});
            }

            THEN("the localized values and the logo are not registered, so they are not in the answer")
            {
                REQUIRE(response.status == 201U);
                auto const body = parse_object(response.body);
                // Spec: "the server has not registered the locale-specific values ... which is why they are not
                // present in the response". This server never registers a logo: it never fetches one.
                CHECK(object_member(body, "client_name#fr") == nullptr);
                CHECK(object_member(body, "tos_uri#fr") == nullptr);
                CHECK(object_member(body, "policy_uri#fr") == nullptr);
                CHECK(object_member(body, "logo_uri") == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Client metadata (`application_type`, `token_endpoint_auth_method`, `response_types`)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#client-metadata
//
// "The homeserver MUST support the web and native values" of application_type; "The homeserver MUST support the none
// value" of token_endpoint_auth_method; response_types: "The server MUST ignore values that it does not understand."
SCENARIO("web and native clients, the none auth method and unknown response types are accepted",
         "[conformance][client-server][oauth][registration]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = merovingian::homeserver::start_client_server(oauth_registration_config());
        REQUIRE(started.started);

        WHEN("a web client, a native client and a client with an unknown response type register")
        {
            auto const web =
                post_client_registration(started.runtime, redirect_registration("web", "https://example.com/callback"));
            auto const native =
                post_client_registration(started.runtime, redirect_registration("native", "com.example.app:/callback"));
            auto const unknown_type = post_client_registration(
                started.runtime, R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"],)"
                                 R"("response_types":["code","code id_token"],"token_endpoint_auth_method":"none"})");

            THEN("each is registered")
            {
                // Spec MUST: support application_type "web".
                REQUIRE(web.status == 201U);
                // Spec MUST: support application_type "native".
                REQUIRE(native.status == 201U);
                REQUIRE(unknown_type.status == 201U);
                auto const web_body = parse_object(web.body);
                auto const native_body = parse_object(native.body);
                CHECK(*string_member(web_body, "application_type") == "web");
                CHECK(*string_member(native_body, "application_type") == "native");
                // Spec MUST: support token_endpoint_auth_method "none".
                CHECK(*string_member(web_body, "token_endpoint_auth_method") == "none");
                // Spec MUST: ignore response types it does not understand; they are not registered.
                CHECK(string_list(parse_object(unknown_type.body), "response_types") ==
                      std::vector<std::string>{"code"});
            }
        }

        WHEN("a client omits application_type")
        {
            auto const response = post_client_registration(
                started.runtime, R"({"client_uri":"https://example.com/","redirect_uris":["https://example.com/cb"]})");

            THEN("it is registered as a web client")
            {
                REQUIRE(response.status == 201U);
                // Spec: application_type "Defaults to web if omitted."
                CHECK(*string_member(parse_object(response.body), "application_type") == "web");
            }
        }

        WHEN("a client's client_uri does not use https")
        {
            auto const response = post_client_registration(
                started.runtime, R"({"client_uri":"http://example.com/","redirect_uris":["https://example.com/cb"]})");

            THEN("it is refused as invalid client metadata")
            {
                // Spec MUST: client_uri "MUST use the https scheme"; RFC 7591 section 3.2.2 names the error.
                REQUIRE(response.status == 400U);
                CHECK(oauth_error_of(response) == "invalid_client_metadata");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Redirect URI validation ("Web clients")
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#redirect-uri-validation
//
// The spec's own valid and invalid web redirect URIs for the client URI https://example.com/. "The server MUST
// perform validation on redirect URIs"; RFC 7591 section 3.2.2 answers a refused one `invalid_redirect_uri`.
SCENARIO("the spec's web redirect URI examples are accepted and refused as it says",
         "[conformance][client-server][oauth][registration][redirect]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = merovingian::homeserver::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        constexpr auto valid = std::to_array<std::string_view>({
            "https://example.com/callback",
            "https://app.example.com/callback",
            "https://example.com:5173/?query=value",
        });
        constexpr auto invalid = std::to_array<std::string_view>({
            "https://example.com/callback#fragment",
            "http://example.com/callback",
            "http://localhost/",
        });

        WHEN("a web client registers each example")
        {
            THEN("the valid ones are registered and the invalid ones refused with invalid_redirect_uri")
            {
                for (auto const uri : valid)
                {
                    INFO(uri);
                    auto const response = post_client_registration(started.runtime, redirect_registration("web", uri));
                    // Spec: listed among "the following are valid redirect URIs".
                    CHECK(response.status == 201U);
                }
                for (auto const uri : invalid)
                {
                    INFO(uri);
                    auto const response = post_client_registration(started.runtime, redirect_registration("web", uri));
                    // Spec MUST: no fragment; "MUST use the https scheme"; on the client URI's host.
                    CHECK(response.status == 400U);
                    CHECK(oauth_error_of(response) == "invalid_redirect_uri");
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Redirect URI validation ("Native clients")
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#redirect-uri-validation
//
// The spec's own valid and invalid native redirect URIs for the client URI https://example.com/: a private-use scheme
// that is the reversed client host with no authority, or http on a loopback host with no port.
SCENARIO("the spec's native redirect URI examples are accepted and refused as it says",
         "[conformance][client-server][oauth][registration][redirect]")
{
    GIVEN("a homeserver with the OAuth 2.0 API on")
    {
        auto started = merovingian::homeserver::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        constexpr auto valid = std::to_array<std::string_view>({
            "com.example.app:/callback",
            "com.example:/",
            "com.example:callback",
            "http://localhost/callback",
            "http://127.0.0.1/callback",
            "http://[::1]/callback",
        });
        constexpr auto invalid = std::to_array<std::string_view>({
            "example:/callback",
            "com.example.app://callback",
            "https://localhost/callback",
            "http://localhost:1234/callback",
        });

        WHEN("a native client registers each example")
        {
            THEN("the valid ones are registered and the invalid ones refused with invalid_redirect_uri")
            {
                for (auto const uri : valid)
                {
                    INFO(uri);
                    auto const response =
                        post_client_registration(started.runtime, redirect_registration("native", uri));
                    // Spec: listed among "These are valid redirect URIs".
                    CHECK(response.status == 201U);
                }
                for (auto const uri : invalid)
                {
                    INFO(uri);
                    auto const response =
                        post_client_registration(started.runtime, redirect_registration("native", uri));
                    // Spec MUST: reversed client host as the scheme, no authority, loopback without a port.
                    CHECK(response.status == 400U);
                    CHECK(oauth_error_of(response) == "invalid_redirect_uri");
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Dynamic client registration flow
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#dynamic-client-registration-flow
//
// "The server MUST NOT delete client registrations that have an active session." This server deletes idle clients to
// make room at its registration cap; one with a session is never among them.
SCENARIO("a client with a session is never deleted to make room for another",
         "[conformance][client-server][oauth][registration][cap]")
{
    GIVEN("a homeserver that holds at most one client, and that client has a session")
    {
        auto started = merovingian::homeserver::start_client_server(oauth_registration_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        rt.limits.max_oauth_clients = 1U;
        auto const first = post_client_registration(rt, redirect_registration("web", "https://example.com/one"));
        REQUIRE(first.status == 201U);
        auto const client_id = *string_member(parse_object(first.body), "client_id");
        REQUIRE(merovingian::database::store_oauth_session(
            rt.homeserver.database.persistent_store,
            merovingian::database::PersistentOAuthSession{"@alice:example.org", "DEVICE", client_id,
                                                          "urn:matrix:client:api:*", 1U}));

        WHEN("a client with other metadata registers")
        {
            auto const second = post_client_registration(rt, redirect_registration("web", "https://example.com/two"));

            THEN("it is refused and the client with a session is still registered")
            {
                CHECK(second.status == 503U);
                CHECK(oauth_error_of(second) == "temporarily_unavailable");
                // Spec MUST NOT: delete a client registration that has an active session.
                REQUIRE(merovingian::database::find_oauth_client(rt.homeserver.database.persistent_store, client_id) !=
                        nullptr);
            }
        }
    }
}
