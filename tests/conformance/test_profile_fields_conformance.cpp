// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX EXTENDED PROFILE FIELDS CONFORMANCE TESTS                 |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19 (profile fields added in v1.16)    |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers GET/PUT/DELETE /profile/{userId}/{keyName} for `m.tz` and        |
// |  custom keys, the key-name grammar, the 64 KiB profile limit and the     |
// |  `m.profile_fields` capability.                                          |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::DispatchResult;

constexpr auto alice_path = std::string_view{"/_matrix/client/v3/profile/%40alice%3Aexample.org"};

[[nodiscard]] auto conformance_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    // Fixture: registration must succeed before the user can log in.
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})"});
    // Fixture: login must succeed so the profile requests are authenticated.
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    // Fixture: the login response must carry the token.
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto call(merovingian::homeserver::ClientServerRuntime& runtime, std::string method, std::string target,
                        std::string token, std::string body) -> DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), std::move(token), std::move(body)});
}

[[nodiscard]] auto key_path(std::string_view key) -> std::string
{
    return std::string{alice_path} + "/" + std::string{key};
}

[[nodiscard]] auto errcode_of(DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

} // namespace

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3profileuseridkeyname
// "keyName ... MUST be either avatar_url, displayname, m.tz, or a custom field following the Common
// Namespaced Identifier Grammar"; "For custom keys, any JSON type is allowed".
// Endpoint / Section: PUT /_matrix/client/v3/profile/{userId}/{keyName}; GET /profile/{userId}[/{keyName}]
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3profileuseridkeyname
SCENARIO("PUT /profile/{userId}/{keyName} sets m.tz and custom fields that GET then returns",
         "[conformance][client-server][profile][profile-fields]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        WHEN("the user sets m.tz and a custom object-valued field")
        {
            auto const tz = call(runtime, "PUT", key_path("m.tz"), token, R"({"m.tz":"Europe/London"})");
            auto const custom = call(runtime, "PUT", key_path("org.example.pronouns"), token,
                                     R"({"org.example.pronouns":{"subject":"she","list":[1,true]}})");

            THEN("both are accepted")
            {
                REQUIRE(tz.response.status == 200U);
                REQUIRE(custom.response.status == 200U);
            }

            THEN("GET /profile/{userId}/{keyName} returns an object with that one property")
            {
                auto const got = call(runtime, "GET", key_path("m.tz"), {}, {});
                REQUIRE(got.response.status == 200U);
                auto const body = parse_object(got.response.body);
                REQUIRE(body.size() == 1U);
                auto const* value = string_member(body, "m.tz");
                REQUIRE(value != nullptr);
                REQUIRE(*value == "Europe/London");

                auto const got_custom = call(runtime, "GET", key_path("org.example.pronouns"), {}, {});
                REQUIRE(got_custom.response.status == 200U);
                auto const custom_body = parse_object(got_custom.response.body);
                REQUIRE(custom_body.size() == 1U);
                auto const* object = object_member_as_object(custom_body, "org.example.pronouns");
                REQUIRE(object != nullptr);
                REQUIRE(string_member(*object, "subject") != nullptr);
            }

            THEN("GET /profile/{userId} carries the fields beside displayname and avatar_url")
            {
                REQUIRE(call(runtime, "PUT", key_path("displayname"), token, R"({"displayname":"Alice"})")
                            .response.status == 200U);
                auto const got = call(runtime, "GET", std::string{alice_path}, {}, {});
                REQUIRE(got.response.status == 200U);
                auto const body = parse_object(got.response.body);
                REQUIRE(string_member(body, "displayname") != nullptr);
                REQUIRE(string_member(body, "m.tz") != nullptr);
                REQUIRE(object_member_as_object(body, "org.example.pronouns") != nullptr);
            }
        }

        WHEN("the user sets a custom field to each JSON type except null")
        {
            auto const as_number = call(runtime, "PUT", key_path("org.example.n"), token, R"({"org.example.n":42})");
            auto const as_bool = call(runtime, "PUT", key_path("org.example.b"), token, R"({"org.example.b":false})");
            auto const as_array = call(runtime, "PUT", key_path("org.example.a"), token, R"({"org.example.a":["x"]})");

            THEN("every type is stored and read back")
            {
                REQUIRE(as_number.response.status == 200U);
                REQUIRE(as_bool.response.status == 200U);
                REQUIRE(as_array.response.status == 200U);
                REQUIRE(int_member(parse_object(call(runtime, "GET", key_path("org.example.n"), {}, {}).response.body),
                                   "org.example.n") != nullptr);
                REQUIRE(bool_member(parse_object(call(runtime, "GET", key_path("org.example.b"), {}, {}).response.body),
                                    "org.example.b") != nullptr);
                REQUIRE(object_member_as_array(
                            parse_object(call(runtime, "GET", key_path("org.example.a"), {}, {}).response.body),
                            "org.example.a") != nullptr);
            }
        }

        WHEN("the same field is set twice")
        {
            REQUIRE(call(runtime, "PUT", key_path("m.tz"), token, R"({"m.tz":"Europe/London"})").response.status ==
                    200U);
            REQUIRE(call(runtime, "PUT", key_path("m.tz"), token, R"({"m.tz":"Asia/Tokyo"})").response.status == 200U);

            THEN("the latest value is returned")
            {
                auto const body = parse_object(call(runtime, "GET", key_path("m.tz"), {}, {}).response.body);
                auto const* value = string_member(body, "m.tz");
                REQUIRE(value != nullptr);
                REQUIRE(*value == "Asia/Tokyo");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3profileuseridkeyname
// "An object which contains exactly one property. The key of that property MUST match the keyName";
// 400 M_MISSING_PARAM "The required keyName property is missing from the request body"; 400 M_BAD_JSON
// "The provided value is not valid JSON"; 403 "insufficient permissions".
SCENARIO("PUT /profile/{userId}/{keyName} validates the request body and the caller",
         "[conformance][client-server][profile][profile-fields]")
{
    GIVEN("two logged-in users")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto const bob = register_and_login(runtime, "bob");

        WHEN("the body names a different key from the path")
        {
            auto const result = call(runtime, "PUT", key_path("m.tz"), alice, R"({"org.example.other":"x"})");

            THEN("the answer is 400 M_MISSING_PARAM")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_MISSING_PARAM");
            }
        }

        WHEN("the body has more than one property")
        {
            auto const result =
                call(runtime, "PUT", key_path("org.example.x"), alice, R"({"org.example.x":"1","org.example.y":"2"})");

            THEN("the answer is 400 M_BAD_JSON and nothing is stored")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_BAD_JSON");
                REQUIRE(call(runtime, "GET", key_path("org.example.x"), {}, {}).response.status == 404U);
            }
        }

        WHEN("the body is not valid JSON or not an object")
        {
            auto const malformed = call(runtime, "PUT", key_path("m.tz"), alice, "{not json");
            auto const array = call(runtime, "PUT", key_path("m.tz"), alice, R"(["m.tz"])");

            THEN("both are 400: text that is not JSON is the dispatcher's M_NOT_JSON, an array M_BAD_JSON")
            {
                REQUIRE(malformed.response.status == 400U);
                REQUIRE(errcode_of(malformed) == "M_NOT_JSON");
                REQUIRE(array.response.status == 400U);
                REQUIRE(errcode_of(array) == "M_BAD_JSON");
            }
        }

        WHEN("m.tz is given a value that is not a string")
        {
            auto const result = call(runtime, "PUT", key_path("m.tz"), alice, R"({"m.tz":5})");

            THEN("the answer is 400 M_INVALID_PARAM")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_INVALID_PARAM");
            }
        }

        WHEN("a user sets a field on another user's profile")
        {
            auto const result = call(runtime, "PUT", key_path("m.tz"), bob, R"({"m.tz":"Europe/London"})");

            THEN("the answer is 403 M_FORBIDDEN and the field is not set")
            {
                REQUIRE(result.response.status == 403U);
                REQUIRE(errcode_of(result) == "M_FORBIDDEN");
                REQUIRE(call(runtime, "GET", key_path("m.tz"), {}, {}).response.status == 404U);
            }
        }

        WHEN("the request carries no access token")
        {
            auto const result = call(runtime, "PUT", key_path("m.tz"), {}, R"({"m.tz":"Europe/London"})");

            THEN("the answer is 401 M_MISSING_TOKEN")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(errcode_of(result) == "M_MISSING_TOKEN");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/appendices.md#common-namespaced-identifier-grammar
// "at least one character and at most 255 characters", start with [a-z], composed of [a-z0-9-_.],
// "Identifiers starting with the characters m. are reserved"; PUT 400 M_KEY_TOO_LARGE "The supplied
// profile key exceeds the maximum allowed key length of 255 bytes", M_INVALID_PARAM "Invalid profile key."
SCENARIO("PUT and DELETE /profile/{userId}/{keyName} refuse a key outside the identifier grammar",
         "[conformance][client-server][profile][profile-fields]")
{
    GIVEN("a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        WHEN("the key contains an upper-case letter, a space, or starts with a digit")
        {
            auto const upper = call(runtime, "PUT", key_path("Org.Example"), token, R"({"Org.Example":"x"})");
            auto const space = call(runtime, "PUT", key_path("org.exa%20mple"), token, R"({"org.exa mple":"x"})");
            auto const digit = call(runtime, "PUT", key_path("1org"), token, R"({"1org":"x"})");

            THEN("each is 400 M_INVALID_PARAM")
            {
                for (auto const* result : {&upper, &space, &digit})
                {
                    REQUIRE(result->response.status == 400U);
                    REQUIRE(errcode_of(*result) == "M_INVALID_PARAM");
                }
            }
        }

        WHEN("the key starts with the reserved prefix m. and is not m.tz")
        {
            auto const result = call(runtime, "PUT", key_path("m.unknown"), token, R"({"m.unknown":"x"})");

            THEN("the answer is 400 M_INVALID_PARAM")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_INVALID_PARAM");
            }
        }

        WHEN("the key is 255 bytes and then 256 bytes long")
        {
            auto const ok_key = "org." + std::string(251U, 'a');
            auto const long_key = "org." + std::string(252U, 'a');
            auto const ok = call(runtime, "PUT", key_path(ok_key), token, R"({")" + ok_key + R"(":"x"})");
            auto const too_long = call(runtime, "PUT", key_path(long_key), token, R"({")" + long_key + R"(":"x"})");

            THEN("255 is accepted and 256 is 400 M_KEY_TOO_LARGE")
            {
                REQUIRE(ok.response.status == 200U);
                REQUIRE(too_long.response.status == 400U);
                REQUIRE(errcode_of(too_long) == "M_KEY_TOO_LARGE");
            }
        }

        WHEN("DELETE names a key outside the grammar")
        {
            auto const result = call(runtime, "DELETE", key_path("Org.Example"), token, {});

            THEN("the answer is 400 M_INVALID_PARAM")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_INVALID_PARAM");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#put_matrixclientv3profileuseridkeyname
// "the total profile MUST be under 64 KiB"; 400 M_PROFILE_TOO_LARGE "Storing the supplied value would
// make the profile exceed its maximum allowed size of 64 KiB".
SCENARIO("PUT /profile/{userId}/{keyName} counts extended fields in the 64 KiB profile limit",
         "[conformance][client-server][profile][profile-fields][profile-size]")
{
    GIVEN("a user whose custom field already takes most of 64 KiB")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");
        auto const big = std::string(60000U, 'a');
        REQUIRE(call(runtime, "PUT", key_path("org.example.big"), token, R"({"org.example.big":")" + big + R"("})")
                    .response.status == 200U);

        WHEN("another custom field would push the profile over the limit")
        {
            auto const more = std::string(6000U, 'b');
            auto const result =
                call(runtime, "PUT", key_path("org.example.more"), token, R"({"org.example.more":")" + more + R"("})");

            THEN("the answer is 400 M_PROFILE_TOO_LARGE and the field is not stored")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_PROFILE_TOO_LARGE");
                REQUIRE(call(runtime, "GET", key_path("org.example.more"), {}, {}).response.status == 404U);
            }
        }

        WHEN("a display name would push the profile over the limit")
        {
            auto const name = std::string(6000U, 'c');
            auto const result =
                call(runtime, "PUT", key_path("displayname"), token, R"({"displayname":")" + name + R"("})");

            THEN("the stored custom field counts: 400 M_PROFILE_TOO_LARGE")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_PROFILE_TOO_LARGE");
            }
        }

        WHEN("the large field is replaced by a short value")
        {
            auto const result = call(runtime, "PUT", key_path("org.example.big"), token, R"({"org.example.big":"s"})");

            THEN("shrinking is accepted")
            {
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#delete_matrixclientv3profileuseridkeyname
// "Remove a specific field from a user's profile"; 200 "The profile field was deleted or it doesn't
// exist"; 403 "The user is not authorised to delete this profile field".
SCENARIO("DELETE /profile/{userId}/{keyName} removes a field and its key",
         "[conformance][client-server][profile][profile-fields]")
{
    GIVEN("a user with a display name, m.tz and a custom field")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto const bob = register_and_login(runtime, "bob");
        REQUIRE(call(runtime, "PUT", key_path("displayname"), alice, R"({"displayname":"Alice"})").response.status ==
                200U);
        REQUIRE(call(runtime, "PUT", key_path("m.tz"), alice, R"({"m.tz":"Europe/London"})").response.status == 200U);
        REQUIRE(call(runtime, "PUT", key_path("org.example.x"), alice, R"({"org.example.x":1})").response.status ==
                200U);

        WHEN("m.tz is deleted")
        {
            auto const result = call(runtime, "DELETE", key_path("m.tz"), alice, {});

            THEN("the answer is 200 {} and the key is gone from both reads")
            {
                REQUIRE(result.response.status == 200U);
                REQUIRE(result.response.body == "{}");
                REQUIRE(call(runtime, "GET", key_path("m.tz"), {}, {}).response.status == 404U);
                auto const profile = parse_object(call(runtime, "GET", std::string{alice_path}, {}, {}).response.body);
                REQUIRE(object_member(profile, "m.tz") == nullptr);
                REQUIRE(object_member(profile, "org.example.x") != nullptr);
            }
        }

        WHEN("a field that is not set is deleted")
        {
            auto const result = call(runtime, "DELETE", key_path("org.example.absent"), alice, {});

            THEN("the answer is 200")
            {
                REQUIRE(result.response.status == 200U);
            }
        }

        WHEN("displayname is deleted")
        {
            auto const result = call(runtime, "DELETE", key_path("displayname"), alice, {});

            THEN("the display name is no longer served and the other fields remain")
            {
                REQUIRE(result.response.status == 200U);
                REQUIRE(call(runtime, "GET", key_path("displayname"), {}, {}).response.status == 404U);
                REQUIRE(call(runtime, "GET", key_path("m.tz"), {}, {}).response.status == 200U);
            }
        }

        WHEN("another user deletes the field")
        {
            auto const result = call(runtime, "DELETE", key_path("m.tz"), bob, {});

            THEN("the answer is 403 M_FORBIDDEN and the field remains")
            {
                REQUIRE(result.response.status == 403U);
                REQUIRE(errcode_of(result) == "M_FORBIDDEN");
                REQUIRE(call(runtime, "GET", key_path("m.tz"), {}, {}).response.status == 200U);
            }
        }

        WHEN("the request carries no access token")
        {
            auto const result = call(runtime, "DELETE", key_path("m.tz"), {}, {});

            THEN("the answer is 401 M_MISSING_TOKEN")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(errcode_of(result) == "M_MISSING_TOKEN");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3profileuseridkeyname
// 404 "There is no profile field with this key for this user, or the user does not exist."
SCENARIO("GET /profile/{userId}/{keyName} answers 404 for a field that is not set",
         "[conformance][client-server][profile][profile-fields]")
{
    GIVEN("a user with no extended fields")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = register_and_login(runtime, "alice");

        WHEN("m.tz, a custom field and a field of a user that does not exist are read")
        {
            auto const tz = call(runtime, "GET", key_path("m.tz"), {}, {});
            auto const custom = call(runtime, "GET", key_path("org.example.x"), {}, {});
            auto const nobody = call(runtime, "GET", "/_matrix/client/v3/profile/%40nobody%3Aexample.org/m.tz", {}, {});

            THEN("each is 404 M_NOT_FOUND")
            {
                for (auto const* result : {&tz, &custom, &nobody})
                {
                    REQUIRE(result->response.status == 404U);
                    REQUIRE(errcode_of(*result) == "M_NOT_FOUND");
                }
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#mprofile_fields-capability
// "The capability value has a required flag, enabled"; "If neither allowed nor disallowed is present,
// clients can modify all fields without restrictions, provided enabled is true."
SCENARIO("GET /capabilities advertises m.profile_fields", "[conformance][client-server][profile][capabilities]")
{
    GIVEN("a logged-in user on a server that lets users set every profile field")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        WHEN("capabilities are read")
        {
            auto const result = call(runtime, "GET", "/_matrix/client/v3/capabilities", token, {});

            THEN("m.profile_fields is enabled with no allowed or disallowed list")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* capabilities = object_member_as_object(body, "capabilities");
                REQUIRE(capabilities != nullptr);
                auto const* profile_fields = object_member_as_object(*capabilities, "m.profile_fields");
                REQUIRE(profile_fields != nullptr);
                auto const* enabled = bool_member(*profile_fields, "enabled");
                REQUIRE(enabled != nullptr);
                REQUIRE(*enabled);
                REQUIRE(object_member(*profile_fields, "allowed") == nullptr);
                REQUIRE(object_member(*profile_fields, "disallowed") == nullptr);
            }
        }
    }
}
