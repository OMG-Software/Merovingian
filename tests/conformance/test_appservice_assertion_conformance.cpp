// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |      APPLICATION SERVICE API — EXCLUSIVITY, ASSERTION, ACCOUNT MGMT     |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19                            |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Security-audit 2026-09-29 findings AUTH-7 (other services' exclusive   |
// |  namespaces), AUTH-12 (asserting a missing or deactivated user) and     |
// |  AUTH-8 (identity assertion on Account Management endpoints).           |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <tuple>

namespace
{

using namespace merovingian::tests;

constexpr auto service_a_token = "service-a-as-token-secret";
constexpr auto service_b_token = "service-b-as-token-secret";

// Service A claims every user but exclusively none of them; service B
// exclusively owns `@_b_.*`. A therefore overlaps B's exclusive namespace.
auto write_overlapping_registrations(std::filesystem::path const& path_a, std::filesystem::path const& path_b) -> void
{
    {
        auto out = std::ofstream{path_a, std::ios::binary};
        out << R"({
            "id": "service-a",
            "url": null,
            "as_token": "service-a-as-token-secret",
            "hs_token": "service-a-hs-token-secret",
            "sender_localpart": "_a_bot",
            "namespaces": {
                "users": [{"exclusive": false, "regex": "@.*"}],
                "aliases": [],
                "rooms": []
            }
        })";
    }
    {
        auto out = std::ofstream{path_b, std::ios::binary};
        out << R"({
            "id": "service-b",
            "url": null,
            "as_token": "service-b-as-token-secret",
            "hs_token": "service-b-hs-token-secret",
            "sender_localpart": "_b_bot",
            "namespaces": {
                "users": [{"exclusive": true, "regex": "@_b_.*"}],
                "aliases": [],
                "rooms": []
            }
        })";
    }
}

[[nodiscard]] auto overlapping_services_config(std::filesystem::path const& path_a, std::filesystem::path const& path_b)
    -> merovingian::config::Config
{
    write_overlapping_registrations(path_a, path_b);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.appservice().registration_files = {path_a.string(), path_b.string()};
    return config;
}

[[nodiscard]] auto register_as_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view as_token,
                                    std::string_view username) -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", std::string{as_token},
                  R"({"type":"m.login.application_service","inhibit_login":true,"username":")" + std::string{username} +
                      R"("})"});
}

[[nodiscard]] auto as_login_body(std::string_view localpart) -> std::string
{
    return R"({"type":"m.login.application_service","identifier":{"type":"m.id.user","user":")" +
           std::string{localpart} + R"("}})";
}

[[nodiscard]] auto whoami_as(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view as_token,
                             std::string_view asserted_user) -> merovingian::homeserver::DispatchResult
{
    auto target = std::string{"/_matrix/client/v3/account/whoami"};
    if (!asserted_user.empty())
    {
        target += "?user_id=" + std::string{asserted_user};
    }
    return merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, std::string{as_token}, {}});
}

[[nodiscard]] auto find_local_user(merovingian::homeserver::ClientServerRuntime& runtime, std::string_view user_id)
    -> merovingian::homeserver::LocalUser*
{
    auto& users = runtime.homeserver.database.users;
    auto const found = std::ranges::find_if(users, [user_id](merovingian::homeserver::LocalUser const& user) {
        return user.user_id == user_id;
    });
    return found == users.end() ? nullptr : &*found;
}

[[nodiscard]] auto whoami_user_id(merovingian::homeserver::DispatchResult const& response) -> std::string
{
    auto const body = parse_object(response.response.body);
    auto const* user_id = string_member(body, "user_id");
    return user_id == nullptr ? std::string{} : *user_id;
}

} // namespace

SCENARIO("an appservice cannot register, log in as, or assert a user in another service's exclusive namespace",
         "[appservice][conformance][exclusivity][auth-7]")
{
    // Spec (application-service-api.md, "Registration"): "An exclusive
    // namespace prevents humans and other application services from
    // creating/deleting entities in that namespace."
    // Spec (client-server-api.md, error codes): "M_EXCLUSIVE: The resource
    // being requested is reserved by an application service ..."
    // Spec (client-server-api.md, POST /register, 400): "M_EXCLUSIVE: The
    // desired user ID is in the exclusive namespace claimed by an
    // application service."
    GIVEN("service A (non-exclusive @.*) and service B (exclusive @_b_.*)")
    {
        auto const path_a = std::filesystem::temp_directory_path() / "merovingian-conformance-auth7-a.json";
        auto const path_b = std::filesystem::temp_directory_path() / "merovingian-conformance-auth7-b.json";
        auto const config = overlapping_services_config(path_a, path_b);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("service A registers a user inside B's exclusive namespace")
        {
            auto const response = register_as_user(runtime, service_a_token, "_b_x");

            THEN("the registration is refused with M_EXCLUSIVE and no user is created")
            {
                CHECK(response.response.status == 400U);
                CHECK(response.response.body.find("M_EXCLUSIVE") != std::string::npos);
                CHECK(find_local_user(runtime, "@_b_x:example.org") == nullptr);
            }
        }

        WHEN("service A registers a user outside every exclusive namespace")
        {
            auto const response = register_as_user(runtime, service_a_token, "_a_ok");

            THEN("the registration succeeds")
            {
                CHECK(response.response.status == 200U);
                CHECK(find_local_user(runtime, "@_a_ok:example.org") != nullptr);
            }
        }

        WHEN("service B registers a user inside its own exclusive namespace")
        {
            auto const response = register_as_user(runtime, service_b_token, "_b_x");

            THEN("the registration succeeds")
            {
                CHECK(response.response.status == 200U);
                CHECK(find_local_user(runtime, "@_b_x:example.org") != nullptr);
            }
        }

        AND_GIVEN("service B has registered the user _b_x")
        {
            REQUIRE(register_as_user(runtime, service_b_token, "_b_x").response.status == 200U);

            WHEN("service A logs in as that user with m.login.application_service")
            {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/login", service_a_token, as_login_body("_b_x")});

                THEN("the login is refused with M_EXCLUSIVE and no access token is issued")
                {
                    CHECK(response.response.status == 403U);
                    CHECK(response.response.body.find("M_EXCLUSIVE") != std::string::npos);
                    CHECK(response.response.body.find("access_token") == std::string::npos);
                }
            }

            WHEN("service B logs in as that user")
            {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/login", service_b_token, as_login_body("_b_x")});

                THEN("the login succeeds")
                {
                    CHECK(response.response.status == 200U);
                }
            }

            WHEN("service A asserts that user with ?user_id=")
            {
                auto const response = whoami_as(runtime, service_a_token, "@_b_x:example.org");

                THEN("the request is refused with M_EXCLUSIVE and does not act as that user")
                {
                    CHECK(response.response.status == 403U);
                    CHECK(response.response.body.find("M_EXCLUSIVE") != std::string::npos);
                    CHECK(response.response.body.find("@_b_x:example.org") == std::string::npos);
                }
            }

            WHEN("service B asserts that user with ?user_id=")
            {
                auto const response = whoami_as(runtime, service_b_token, "@_b_x:example.org");

                THEN("the assertion is honoured")
                {
                    REQUIRE(response.response.status == 200U);
                    CHECK(whoami_user_id(response) == "@_b_x:example.org");
                }
            }
        }

        std::filesystem::remove(path_a);
        std::filesystem::remove(path_b);
    }
}

SCENARIO("an appservice cannot assert a user that does not exist or is deactivated",
         "[appservice][conformance][auth][auth-12]")
{
    // Spec (client-server-api.md, Appservice Login): "If the access token is
    // not valid, does not correspond to an appservice or the user has not
    // previously been registered then the homeserver will respond with an
    // errcode of M_FORBIDDEN."
    // Spec (application-service-api.md, Identity assertion): "The user
    // specified in the query string must be covered by one of the
    // application service's user namespaces." The spec does not say that
    // assertion registers the user; the project owner chose to refuse an
    // unregistered or deactivated user with 403 M_FORBIDDEN.
    GIVEN("service A (non-exclusive @.*) on a freshly started server")
    {
        auto const path_a = std::filesystem::temp_directory_path() / "merovingian-conformance-auth12-a.json";
        auto const path_b = std::filesystem::temp_directory_path() / "merovingian-conformance-auth12-b.json";
        auto const config = overlapping_services_config(path_a, path_b);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("service A asserts a user inside its namespace that was never registered")
        {
            auto const response = whoami_as(runtime, service_a_token, "@_a_ghost:example.org");

            THEN("the request is refused with 403 M_FORBIDDEN")
            {
                CHECK(response.response.status == 403U);
                CHECK(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        WHEN("service A acts as its own sender_localpart user, implicitly")
        {
            auto const response = whoami_as(runtime, service_a_token, {});

            THEN("the request succeeds as the sender user")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(whoami_user_id(response) == "@_a_bot:example.org");
            }
        }

        WHEN("service A acts as its own sender_localpart user, explicitly")
        {
            auto const response = whoami_as(runtime, service_a_token, "@_a_bot:example.org");

            THEN("the request succeeds as the sender user")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(whoami_user_id(response) == "@_a_bot:example.org");
            }
        }

        AND_GIVEN("service A has registered the user _a_alice through /register")
        {
            REQUIRE(register_as_user(runtime, service_a_token, "_a_alice").response.status == 200U);

            WHEN("service A asserts that user")
            {
                auto const response = whoami_as(runtime, service_a_token, "@_a_alice:example.org");

                THEN("the assertion is honoured")
                {
                    REQUIRE(response.response.status == 200U);
                    CHECK(whoami_user_id(response) == "@_a_alice:example.org");
                }
            }

            WHEN("that user is deactivated and service A asserts it")
            {
                auto* const alice = find_local_user(runtime, "@_a_alice:example.org");
                REQUIRE(alice != nullptr);
                alice->deactivated = true;
                auto const response = whoami_as(runtime, service_a_token, "@_a_alice:example.org");

                THEN("the request is refused with 403 M_FORBIDDEN")
                {
                    CHECK(response.response.status == 403U);
                    CHECK(response.response.body.find("M_FORBIDDEN") != std::string::npos);
                }
            }
        }

        std::filesystem::remove(path_a);
        std::filesystem::remove(path_b);
    }
}

SCENARIO("identity assertion does not apply to Account Management", "[appservice][conformance][auth][auth-8]")
{
    // Spec (application-service-api.md, Identity assertion): "This applies
    // to all aspects of the Client-Server API, except for Account
    // Management." The spec's own example is GET /account/whoami with
    // ?user_id=, so whoami stays assertable.
    GIVEN("service A with a registered virtual user, and an ordinary human user")
    {
        auto const path_a = std::filesystem::temp_directory_path() / "merovingian-conformance-auth8-a.json";
        auto const path_b = std::filesystem::temp_directory_path() / "merovingian-conformance-auth8-b.json";
        auto const config = overlapping_services_config(path_a, path_b);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(register_as_user(runtime, service_a_token, "_a_alice").response.status == 200U);
        auto const human = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json("plainuser", "CorrectHorse7!")});
        REQUIRE(human.response.status == 200U);
        auto const human_body = parse_object(human.response.body);
        auto const* human_token = string_member(human_body, "access_token");
        REQUIRE(human_token != nullptr);

        struct AccountRoute final
        {
            char const* method;
            char const* path;
        };
        constexpr auto account_management_routes = std::array<AccountRoute, 12>{
            {
             {"POST", "/_matrix/client/v3/account/password"},
             {"POST", "/_matrix/client/v3/account/password/email/requestToken"},
             {"POST", "/_matrix/client/v3/account/password/msisdn/requestToken"},
             {"POST", "/_matrix/client/v3/account/deactivate"},
             {"GET", "/_matrix/client/v3/account/3pid"},
             {"POST", "/_matrix/client/v3/account/3pid"},
             {"POST", "/_matrix/client/v3/account/3pid/add"},
             {"POST", "/_matrix/client/v3/account/3pid/bind"},
             {"POST", "/_matrix/client/v3/account/3pid/delete"},
             {"POST", "/_matrix/client/v3/account/3pid/email/requestToken"},
             {"POST", "/_matrix/client/v3/account/3pid/msisdn/requestToken"},
             {"POST", "/_matrix/client/v3/account/3pid/unbind"},
             }
        };
        auto const* const alice_before = find_local_user(runtime, "@_a_alice:example.org");
        REQUIRE(alice_before != nullptr);
        auto const password_hash_before = alice_before->password_hash;

        WHEN("each Account Management endpoint is called with an asserted ?user_id=")
        {
            THEN("every one is refused with 403 M_FORBIDDEN")
            {
                for (auto const& route : account_management_routes)
                {
                    INFO(route.method << ' ' << route.path);
                    auto const response = merovingian::homeserver::handle_client_server_request(
                        runtime, {route.method, std::string{route.path} + "?user_id=@_a_alice:example.org",
                                  service_a_token, "{}"});
                    CHECK(response.response.status == 403U);
                    CHECK(response.response.body.find("M_FORBIDDEN") != std::string::npos);
                }
            }

            THEN("the asserted account is neither deactivated nor has its password changed")
            {
                std::ignore = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/account/deactivate?user_id=@_a_alice:example.org",
                              service_a_token, R"({"erase":true})"});
                std::ignore = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/account/password?user_id=@_a_alice:example.org",
                              service_a_token, R"({"new_password":"AnotherHorse8!"})"});
                auto const* const alice = find_local_user(runtime, "@_a_alice:example.org");
                REQUIRE(alice != nullptr);
                CHECK_FALSE(alice->deactivated);
                CHECK(alice->password_hash == password_hash_before);
            }
        }

        WHEN("each Account Management endpoint is called with the implicit sender_localpart identity")
        {
            THEN("every one is refused with 403 M_FORBIDDEN")
            {
                for (auto const& route : account_management_routes)
                {
                    INFO(route.method << ' ' << route.path);
                    auto const response = merovingian::homeserver::handle_client_server_request(
                        runtime, {route.method, route.path, service_a_token, "{}"});
                    CHECK(response.response.status == 403U);
                    CHECK(response.response.body.find("M_FORBIDDEN") != std::string::npos);
                }
            }
        }

        WHEN("whoami is called with an asserted ?user_id=")
        {
            auto const response = whoami_as(runtime, service_a_token, "@_a_alice:example.org");

            THEN("the assertion is honoured, as in the spec's own example")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(whoami_user_id(response) == "@_a_alice:example.org");
            }
        }

        WHEN("an ordinary user calls an Account Management endpoint with their own access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/3pid", *human_token, {}});

            THEN("the endpoint is unaffected")
            {
                CHECK(response.response.status == 200U);
            }
        }

        std::filesystem::remove(path_a);
        std::filesystem::remove(path_b);
    }
}
