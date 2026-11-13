// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// C26 (ADR-0686): a report costs no read of the audit log, one reporter files at most 20 a minute, and a repeat of a
// report writes no second row.
//
// Spec: Matrix Client-Server API v1.19, "POST /users/{userId}/report" (200, or 429 M_LIMIT_EXCEEDED when the server
// limits the caller). ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <string>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto password = "CorrectHorse7!";

[[nodiscard]] auto make_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto send(hs::ClientServerRuntime& runtime, std::string method, std::string target, std::string token,
                        std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime,
                                            {std::move(method), std::move(target), std::move(token), std::move(body)})
        .response;
}

[[nodiscard]] auto sign_in(hs::ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, password))
                .status == 200U);
    auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                                R"(:example.org"},"password":")" + password + R"(","device_id":"DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    return *string_member(body, "access_token");
}

// Reports the remote user `@u<number>:remote.example` as `token`.
[[nodiscard]] auto report_user(hs::ClientServerRuntime& runtime, std::string const& token, int number)
    -> hs::LocalHttpResponse
{
    return send(runtime, "POST", "/_matrix/client/v3/users/%40u" + std::to_string(number) + "%3Aremote.example/report",
                token, R"({"reason":"spam"})");
}

[[nodiscard]] auto report_rows(hs::ClientServerRuntime& runtime) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(runtime.homeserver.database.persistent_store.audit_log, [](auto const& row) {
            return row.event_type.ends_with(".accept_report");
        }));
}

} // namespace

SCENARIO("Reporting reads no audit log and one reporter is limited to twenty a minute",
         "[trust-safety][c26][integration]")
{
    GIVEN("a signed-in user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = sign_in(runtime, "reporter");
        auto const queries_before = runtime.homeserver.database.persistent_store.audit_type_queries.value();

        WHEN("the user files twenty distinct reports, repeats the first, and then files a twenty-first")
        {
            for (auto number = 0; number < 20; ++number)
            {
                REQUIRE(report_user(runtime, token, number).status == 200U);
            }
            auto const rows_after_twenty = report_rows(runtime);
            auto const over = report_user(runtime, token, 20);

            THEN("no report read the audit log, the first twenty wrote a row each, and the twenty-first is 429")
            {
                REQUIRE(runtime.homeserver.database.persistent_store.audit_type_queries.value() == queries_before);
                REQUIRE(rows_after_twenty == 20U);
                REQUIRE(over.status == 429U);
                auto const body = parse_object(over.body);
                REQUIRE(*string_member(body, "errcode") == "M_LIMIT_EXCEEDED");
            }
        }
    }
}

SCENARIO("A repeated user report writes one row", "[trust-safety][c26][integration]")
{
    GIVEN("a signed-in user who reported a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = sign_in(runtime, "reporter");
        REQUIRE(report_user(runtime, token, 1).status == 200U);

        WHEN("the same report is filed again")
        {
            auto const repeat = report_user(runtime, token, 1);

            THEN("it is acknowledged and no second row is written")
            {
                REQUIRE(repeat.status == 200U);
                REQUIRE(report_rows(runtime) == 1U);
            }
        }
    }
}
