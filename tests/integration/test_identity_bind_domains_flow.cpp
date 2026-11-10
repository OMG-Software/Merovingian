// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.identity_server.allowed_bind_domains: the email domains this server
// will tell an identity server about. Spec: M_THREEPID_DENIED, "The server does
// not permit this third-party identifier. This may happen if the server only
// permits, for example, email addresses from a particular domain"
// (docs/matrix-v1.19-spec/client-server-api.md, Common error codes).

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/identity/IdentityServerClient.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto bind_domain_config(std::vector<std::string> allowed) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.identity_server.trusted_servers = {"https://is.example.org"};
    server.identity_server.allowed_bind_domains = std::move(allowed);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto alice_token(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

template <typename Result>
[[nodiscard]] auto errcode_of(Result const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto email_request(std::string_view email) -> std::string
{
    return std::string{R"({"client_secret":"secret-0123456789","send_attempt":1,"id_server":"is.example.org",)"} +
           R"("id_access_token":"tokentokentoken","email":")" + std::string{email} + R"("})";
}

} // namespace

SCENARIO("An identity server is only told about email addresses on allowed bind domains", "[identity][config][3pid]")
{
    GIVEN("a trusted identity server and allowed_bind_domains=example.org")
    {
        auto started = merovingian::homeserver::start_client_server(bind_domain_config({"example.org"}));
        REQUIRE(started.started);
        auto const token = alice_token(started.runtime);

        WHEN("a registration requestToken names an address on another domain")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/register/email/requestToken", {}, email_request("bob@other.net")});

            THEN("it is refused with M_THREEPID_DENIED before any identity server is contacted")
            {
                REQUIRE(result.response.status == 403U);
                REQUIRE(errcode_of(result) == "M_THREEPID_DENIED");
            }
        }

        WHEN("an account requestToken names an address on another domain")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid/email/requestToken", token, email_request("bob@Other.NET")});

            THEN("it is refused with M_THREEPID_DENIED")
            {
                REQUIRE(result.response.status == 403U);
                REQUIRE(errcode_of(result) == "M_THREEPID_DENIED");
            }
        }

        WHEN("an account requestToken names an address on the allowed domain, in any letter case")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/email/requestToken", token,
                                  email_request("bob@EXAMPLE.org")});

            THEN("the domain gate lets it through to the identity server step")
            {
                REQUIRE(errcode_of(result) != "M_THREEPID_DENIED");
            }
        }

        WHEN("a room invite names an address on another domain")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", token, "{}"});
            REQUIRE(room.response.status == 200U);
            auto const room_body = parse_object(room.response.body);
            auto const* room_id = string_member(room_body, "room_id");
            REQUIRE(room_id != nullptr);
            auto const invite = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/rooms/" + *room_id + "/invite", token,
                 R"({"id_server":"is.example.org","id_access_token":"tokentokentoken","medium":"email","address":"bob@other.net"})"});

            THEN("it is refused with M_THREEPID_DENIED")
            {
                REQUIRE(invite.response.status == 403U);
                REQUIRE(errcode_of(invite) == "M_THREEPID_DENIED");
            }
        }
    }

    GIVEN("allowed_bind_domains is empty")
    {
        auto started = merovingian::homeserver::start_client_server(bind_domain_config({}));
        REQUIRE(started.started);

        WHEN("a registration requestToken names any domain")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/register/email/requestToken", {}, email_request("bob@other.net")});

            THEN("no domain restriction applies")
            {
                REQUIRE(errcode_of(result) != "M_THREEPID_DENIED");
            }
        }
    }
}
