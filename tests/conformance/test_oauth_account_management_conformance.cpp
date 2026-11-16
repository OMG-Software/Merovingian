// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            OAUTH 2.0 ACCOUNT MANAGEMENT CONFORMANCE TESTS               |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — "Account management" (OAuth     |
// |        2.0 API) and "OAuth authentication" (the m.oauth UIA type)       |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                |
// +-------------------------------------------------------------------------+
//
// The account management URL the metadata advertises, its `action` and `device_id` parameters, and the `m.oauth` stage
// of a replacing `POST /keys/device_signing/upload` from an OAuth session (ADR-0796, ADR-0797).

#include "../support/CrossSigningFixture.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/OAuthAccountPageSupport.hpp"
#include "../support/OAuthAuthorizationSupport.hpp"
#include "../support/OAuthRegistrationSupport.hpp"
#include "../support/OAuthTokenSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto alice_password = std::string_view{"AlicePass99!x"};
constexpr auto alice_id = std::string_view{"@alice:example.org"};

struct Fixture final
{
    hs::ClientServerStartResult started;
    std::string client_id;
};

[[nodiscard]] auto make_fixture() -> Fixture
{
    auto config = oauth_registration_config(true);
    config.server().server_name = "example.org";
    enable_token_registration(config.security());
    auto started = hs::start_client_server(config);
    REQUIRE(started.started);
    REQUIRE(
        hs::register_local_user(started.runtime.homeserver, "alice", alice_password, std::string{registration_token})
            .ok);
    auto client_id = register_oauth_web_client(
        started.runtime, R"(,"client_name":"Test App","grant_types":["authorization_code","refresh_token"])");
    REQUIRE_FALSE(client_id.empty());
    return {std::move(started), std::move(client_id)};
}

[[nodiscard]] auto upload(hs::ClientServerRuntime& rt, std::string const& token, std::string const& members)
    -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(
               rt, {"POST", "/_matrix/client/v3/keys/device_signing/upload", token, "{" + members + "}"}, false)
        .response;
}

[[nodiscard]] auto object_of(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Object const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<merovingian::canonicaljson::Object>(&value->storage());
}

[[nodiscard]] auto string_array(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::vector<std::string>
{
    auto out = std::vector<std::string>{};
    auto const* array = object_member_as_array(object, key);
    if (array == nullptr)
    {
        return out;
    }
    for (auto const& entry : *array)
    {
        if (auto const* text = std::get_if<std::string>(&entry.storage()); text != nullptr)
        {
            out.push_back(*text);
        }
    }
    return out;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Account management URL discovery; Account management URL actions
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#account-management-url-discovery
//      ../../docs/matrix-v1.19-spec/client-server-api.md#account-management-url-actions
//
// The metadata "is extended to include the following optional fields": `account_management_actions_supported`, a
// "List of actions that the account management URL supports", and `account_management_uri`, "The URL where the user is
// able to access the account management capabilities of the server". The six Matrix-specific actions are listed.
SCENARIO("auth_metadata advertises the account management URL and the six Matrix actions",
         "[conformance][client-server][oauth][oauth-account]")
{
    GIVEN("a running homeserver with the OAuth 2.0 API on")
    {
        auto fixture = make_fixture();

        WHEN("the metadata is read and the advertised URL is opened")
        {
            auto const metadata =
                hs::handle_client_server_request(fixture.started.runtime,
                                                 {"GET", "/_matrix/client/v1/auth_metadata", {}, {}}, false)
                    .response;
            auto const body = parse_object(metadata.body);
            auto const page = get_account(fixture.started.runtime, {});

            THEN("the URL is an https URL this server answers, and every listed action is one of the six")
            {
                REQUIRE(metadata.status == 200U);
                auto const* uri = string_member(body, "account_management_uri");
                REQUIRE(uri != nullptr);
                REQUIRE(*uri == oauth_account_url);
                auto const actions = string_array(body, "account_management_actions_supported");
                REQUIRE(actions == std::vector<std::string>{"org.matrix.profile", "org.matrix.devices_list",
                                                            "org.matrix.device_view", "org.matrix.device_delete",
                                                            "org.matrix.account_deactivate",
                                                            "org.matrix.cross_signing_reset"});
                REQUIRE(page.status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Account management URL parameters
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#account-management-url-parameters
//
// `action`: "The action that the user wishes to take. Must match one of the actions advertised". `device_id`: "Actions
// which don't support the device ID will ignore it. If the org.matrix.device_view or org.matrix.device_delete actions
// are advertised as supported by the server then the server SHOULD support the device_id parameter."
SCENARIO("The account management URL takes action and device_id, and ignores the device for other actions",
         "[conformance][client-server][oauth][oauth-account]")
{
    GIVEN("alice signed in through OAuth (device OAUTHDEV01) and signed in to the account pages")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        REQUIRE(oauth_sign_in(rt, fixture.client_id, "alice", alice_password).ok);
        auto const signed_in = account_sign_in(rt, "alice", alice_password);
        REQUIRE_FALSE(signed_in.form_token.empty());

        WHEN("each action is opened, the device actions with her device")
        {
            auto const view = get_account(rt, "action=org.matrix.device_view&device_id=OAUTHDEV01", signed_in.browser);
            auto const remove =
                get_account(rt, "action=org.matrix.device_delete&device_id=OAUTHDEV01", signed_in.browser);
            auto const list = get_account(rt, "action=org.matrix.devices_list&device_id=OAUTHDEV01", signed_in.browser);
            auto const profile = get_account(rt, "action=org.matrix.profile&device_id=OAUTHDEV01", signed_in.browser);
            auto const deactivate = get_account(rt, "action=org.matrix.account_deactivate", signed_in.browser);
            auto const reset = get_account(rt, "action=org.matrix.cross_signing_reset", signed_in.browser);

            THEN("each is answered with its page, and the device appears only where the action takes it")
            {
                REQUIRE(view.status == 200U);
                REQUIRE(view.body.find("OAUTHDEV01") != std::string::npos);
                REQUIRE(remove.status == 200U);
                REQUIRE(remove.body.find(R"(name="device_id" value="OAUTHDEV01")") != std::string::npos);
                REQUIRE(list.status == 200U);
                REQUIRE(list.body.find("Your devices") != std::string::npos);
                REQUIRE(profile.status == 200U);
                REQUIRE(profile.body.find("@alice:example.org") != std::string::npos);
                REQUIRE(profile.body.find("OAUTHDEV01") == std::string::npos);
                REQUIRE(deactivate.status == 200U);
                REQUIRE(deactivate.body.find(R"(value="deactivate")") != std::string::npos);
                REQUIRE(reset.status == 200U);
                REQUIRE(reset.body.find(R"(value="approve_cross_signing_reset")") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: OAuth authentication (m.oauth); Account management URL actions; POST /keys/device_signing/upload
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#oauth-authentication
//      ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysdevice_signingupload
//
// "the server returns a 401 response on the respective request, where the response body includes m.oauth in the flows
// list, and the m.oauth property in the params object has the structure shown below" (`url`). "Once the user has done
// so, the client submits an auth dict with just the session". `org.matrix.cross_signing_reset`: "Servers SHOULD use
// this action in the URL of the m.oauth UIA type."
SCENARIO(
    "A replacing cross-signing upload from an OAuth session is the m.oauth stage, completed with the session alone",
    "[conformance][client-server][oauth][oauth-account][oauth-uia]")
{
    GIVEN("alice signed in through OAuth, holding cross-signing keys")
    {
        auto fixture = make_fixture();
        auto& rt = fixture.started.runtime;
        auto const oauth = oauth_sign_in(rt, fixture.client_id, "alice", alice_password);
        REQUIRE(oauth.ok);
        REQUIRE(upload(rt, oauth.access_token,
                       make_cross_signing_set(std::string{alice_id}).selected_members(true, true, true))
                    .status == 200U);
        auto const replacement = make_cross_signing_set(std::string{alice_id}).master_member();

        WHEN("she uploads a new master key, approves the reset on the account page, and retries with the session")
        {
            auto const challenge = upload(rt, oauth.access_token, replacement);
            auto const body = parse_object(challenge.body);
            auto const* session = string_member(body, "session");
            REQUIRE(session != nullptr);
            auto const signed_in = account_sign_in(rt, "alice", alice_password);
            auto const approved =
                post_account(rt,
                             {
                                 {"form_token", signed_in.form_token         },
                                 {"action",     "approve_cross_signing_reset"}
            },
                             signed_in.browser);
            auto const completed =
                upload(rt, oauth.access_token, replacement + R"(,"auth":{"session":")" + *session + R"("})");

            THEN("the 401 lists m.oauth with the reset URL, and the session alone completes the stage")
            {
                // Spec: "the server returns a 401 response".
                REQUIRE(challenge.status == 401U);
                auto const* flows = object_member_as_array(body, "flows");
                REQUIRE(flows != nullptr);
                // Spec: "the response body includes m.oauth in the flows list". The list may hold other flows (this
                // server adds the pre-standard stage name as a second one, ADR-0799); one of them is m.oauth alone.
                auto const oauth_flows =
                    std::ranges::count_if(*flows, [](merovingian::canonicaljson::Value const& value) {
                        auto const* flow = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                        return flow != nullptr && string_array(*flow, "stages") == std::vector<std::string>{"m.oauth"};
                    });
                REQUIRE(oauth_flows == 1);
                auto const* params = object_of(body, "params");
                REQUIRE(params != nullptr);
                auto const* oauth_params = object_of(*params, "m.oauth");
                REQUIRE(oauth_params != nullptr);
                auto const* url = string_member(*oauth_params, "url");
                REQUIRE(url != nullptr);
                // Spec SHOULD: the org.matrix.cross_signing_reset action in the URL of the m.oauth UIA type. Spec
                // (account management URL parameters): "For Matrix-specific actions, the user's device ID" MAY be
                // carried as device_id; the server names the device that asked (ADR-0809).
                REQUIRE(*url == std::string{oauth_account_url} + "?action=org.matrix.cross_signing_reset&device_id=" +
                                    std::string{oauth_test_device});
                REQUIRE(approved.status == 200U);
                // Spec: "the client submits an auth dict with just the session ... to complete the stage".
                REQUIRE(completed.status == 200U);
            }
        }
    }
}
