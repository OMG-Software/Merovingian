// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            PUSH NOTIFICATIONS — PUSHER LIFECYCLE CONFORMANCE            |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §push-notifications               |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pusherset |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3pushers |
// |                                                                         |
// |  Covers the pusher-management endpoints' MUST/SHOULD behaviour: the     |
// |  set/get round-trip, kind:null delete, the append:false/true            |
// |  cross-user removal rule, and http pusher URL validation. Real gateway  |
// |  delivery (config gate, notify, rejection handling, unreachable-gateway |
// |  resilience) is covered end to end in                                   |
// |  tests/integration/test_push_delivery_flow.cpp — this file only checks  |
// |  endpoint-observable behaviour.                                         |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// Registers `localpart` and logs them in, returning the access token.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            localpart + R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart +
                            R"(_DEV"})";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// A well-formed POST /pushers/set body for an "http" pusher, minus the fields
// under test (app_id/pushkey/data.url are substituted by the caller).
[[nodiscard]] auto http_pusher_body(std::string const& app_id, std::string const& pushkey, std::string const& url,
                                    bool append) -> std::string
{
    return std::string{R"({"app_id":")"} + app_id + R"(","pushkey":")" + pushkey +
           R"(","kind":"http","app_display_name":"Conformance App","device_display_name":"Conformance Device",)" +
           R"("lang":"en","append":)" + (append ? "true" : "false") + R"(,"data":{"url":")" + url + R"("}})";
}

} // namespace

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pusherset
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3pushers
//
// Spec MUST: "If kind is not null, the pusher with this app_id and pushkey
// for this user is updated, or it is created if it doesn't exist." GET
// /pushers "[g]ets all currently active pushers for the authenticated user"
// and each entry carries app_display_name/app_id/data/device_display_name/
// kind/lang/profile_tag/pushkey.
SCENARIO("POST /pushers/set followed by GET /pushers round-trips the stored pusher",
         "[conformance][client-server][push]")
{
    GIVEN("alice, logged in, with no pushers registered")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");

        WHEN("she registers an http pusher")
        {
            auto const set_response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  http_pusher_body("org.matrix.conformance", "alice-pushkey-1",
                                                   "https://push.example.org/_matrix/push/v1/notify", false)});

            THEN("the set response is 200 {}")
            {
                // Spec MUST (200 response): "{}"
                REQUIRE(set_response.response.status == 200U);
                auto const set_body = parse_object(set_response.response.body);
                REQUIRE(set_body.empty());
            }

            THEN("GET /pushers returns exactly that pusher with every required field")
            {
                auto const get_response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", alice, {}});
                REQUIRE(get_response.response.status == 200U);
                auto const body = parse_object(get_response.response.body);
                auto const* pushers = object_member_as_array(body, "pushers");
                REQUIRE(pushers != nullptr);
                REQUIRE(pushers->size() == 1U);
                auto const* pusher = std::get_if<merovingian::canonicaljson::Object>(&(*pushers)[0].storage());
                REQUIRE(pusher != nullptr);

                // Spec MUST: every Pusher field below is "Required".
                auto const* app_display_name = string_member(*pusher, "app_display_name");
                auto const* app_id = string_member(*pusher, "app_id");
                auto const* device_display_name = string_member(*pusher, "device_display_name");
                auto const* kind = string_member(*pusher, "kind");
                auto const* lang = string_member(*pusher, "lang");
                auto const* pushkey = string_member(*pusher, "pushkey");
                auto const* data = object_member_as_object(*pusher, "data");
                REQUIRE(app_display_name != nullptr);
                REQUIRE(app_id != nullptr);
                REQUIRE(device_display_name != nullptr);
                REQUIRE(kind != nullptr);
                REQUIRE(lang != nullptr);
                REQUIRE(pushkey != nullptr);
                REQUIRE(data != nullptr);
                REQUIRE(*app_id == "org.matrix.conformance");
                REQUIRE(*pushkey == "alice-pushkey-1");
                REQUIRE(*kind == "http");
                auto const* url = string_member(*data, "url");
                REQUIRE(url != nullptr);
                REQUIRE(*url == "https://push.example.org/_matrix/push/v1/notify");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pusherset
//
// Spec MUST: "If kind is null, the pusher with this app_id and pushkey for
// this user is deleted."
SCENARIO("POST /pushers/set with kind:null deletes the identified pusher", "[conformance][client-server][push]")
{
    GIVEN("alice with one registered pusher")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const set_response = merovingian::homeserver::handle_client_server_request(
            started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                              http_pusher_body("org.matrix.conformance", "alice-pushkey-2",
                                               "https://push.example.org/_matrix/push/v1/notify", false)});
        REQUIRE(set_response.response.status == 200U);

        WHEN("she deletes it with kind:null")
        {
            auto const delete_response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  R"({"app_id":"org.matrix.conformance","pushkey":"alice-pushkey-2","kind":null})"});

            THEN("the response is 200 {} and the pusher no longer appears in GET /pushers")
            {
                REQUIRE(delete_response.response.status == 200U);
                auto const get_response = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", alice, {}});
                auto const body = parse_object(get_response.response.body);
                auto const* pushers = object_member_as_array(body, "pushers");
                REQUIRE(pushers != nullptr);
                REQUIRE(pushers->empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pusherset
//
// Spec MUST: an http pusher's data.url "MUST be an HTTPS URL with a path of
// /_matrix/push/v1/notify". A non-HTTPS scheme or wrong path is a 400
// M_MISSING_PARAM/M_BAD_JSON-class rejection ("One or more of the pusher
// values were invalid").
SCENARIO("POST /pushers/set rejects an http pusher whose data.url is not https or lacks the notify path",
         "[conformance][client-server][push]")
{
    GIVEN("alice, logged in")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");

        WHEN("she submits an http pusher with a plain-HTTP url")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  http_pusher_body("org.matrix.conformance", "alice-pushkey-3",
                                                   "http://push.example.org/_matrix/push/v1/notify", false)});

            THEN("the request is rejected with 400")
            {
                // Spec MUST (400 response): "One or more of the pusher values were invalid."
                REQUIRE(response.response.status == 400U);
            }
        }

        WHEN("she submits an http pusher whose url path is not /_matrix/push/v1/notify")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  http_pusher_body("org.matrix.conformance", "alice-pushkey-4",
                                                   "https://push.example.org/wrong/path", false)});

            THEN("the request is rejected with 400")
            {
                REQUIRE(response.response.status == 400U);
            }
        }

        THEN("neither rejected attempt registered a pusher")
        {
            auto const get_response = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"GET", "/_matrix/client/v3/pushers", alice, {}});
            auto const body = parse_object(get_response.response.body);
            auto const* pushers = object_member_as_array(body, "pushers");
            REQUIRE(pushers != nullptr);
            REQUIRE(pushers->empty());
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §push-notifications
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3pusherset
//
// Spec MUST (`append` field): "If true, the homeserver should add another
// pusher with the given pushkey and App ID in addition to any others with
// different user IDs. Otherwise, the homeserver must remove any other
// pushers with the same App ID and pushkey for different users. The default
// is false."
SCENARIO("append:false removes another user's pusher sharing the same app_id and pushkey; append:true preserves it",
         "[conformance][client-server][push]")
{
    GIVEN("alice and bob, both logged in")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto const alice = register_and_login(started.runtime, "alice");
        auto const bob = register_and_login(started.runtime, "bob");
        auto const shared_app_id = std::string{"org.matrix.conformance.shared"};
        auto const shared_pushkey = std::string{"shared-device-token"};

        WHEN("alice registers a pusher, then bob registers one with the same app_id+pushkey and append:false")
        {
            auto const alice_set = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  http_pusher_body(shared_app_id, shared_pushkey,
                                                   "https://push.example.org/_matrix/push/v1/notify", false)});
            REQUIRE(alice_set.response.status == 200U);
            auto const bob_set = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", bob,
                                  http_pusher_body(shared_app_id, shared_pushkey,
                                                   "https://push.example.org/_matrix/push/v1/notify", false)});
            REQUIRE(bob_set.response.status == 200U);

            THEN("alice's pusher sharing that app_id+pushkey was removed")
            {
                auto const alice_pushers = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", alice, {}});
                auto const alice_body = parse_object(alice_pushers.response.body);
                auto const* pushers = object_member_as_array(alice_body, "pushers");
                REQUIRE(pushers != nullptr);
                REQUIRE(pushers->empty());

                auto const bob_pushers = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", bob, {}});
                auto const bob_body = parse_object(bob_pushers.response.body);
                auto const* bob_array = object_member_as_array(bob_body, "pushers");
                REQUIRE(bob_array != nullptr);
                REQUIRE(bob_array->size() == 1U);
            }
        }

        WHEN("alice registers a pusher, then bob registers one with the same app_id+pushkey and append:true")
        {
            auto const alice_set = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", alice,
                                  http_pusher_body(shared_app_id, shared_pushkey,
                                                   "https://push.example.org/_matrix/push/v1/notify", false)});
            REQUIRE(alice_set.response.status == 200U);
            auto const bob_set = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/pushers/set", bob,
                                  http_pusher_body(shared_app_id, shared_pushkey,
                                                   "https://push.example.org/_matrix/push/v1/notify", true)});
            REQUIRE(bob_set.response.status == 200U);

            THEN("both alice's and bob's pushers with that app_id+pushkey still exist")
            {
                auto const alice_pushers = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", alice, {}});
                auto const alice_body = parse_object(alice_pushers.response.body);
                auto const* alice_array = object_member_as_array(alice_body, "pushers");
                REQUIRE(alice_array != nullptr);
                REQUIRE(alice_array->size() == 1U);

                auto const bob_pushers = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"GET", "/_matrix/client/v3/pushers", bob, {}});
                auto const bob_body = parse_object(bob_pushers.response.body);
                auto const* bob_array = object_member_as_array(bob_body, "pushers");
                REQUIRE(bob_array != nullptr);
                REQUIRE(bob_array->size() == 1U);
            }
        }
    }
}
