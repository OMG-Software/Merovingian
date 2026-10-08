// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// AUTH-2 / AUTH-1 (security-audit-report-2026-09-29.md): the login failure
// throttle is keyed on (account, client source), has a per-account ceiling across
// all sources, and never blocks a user-interactive-auth password check made by an
// already-authenticated session. `login.rejected` audit rows are rate-gated.
//
// Spec: Matrix Client-Server API v1.19, "Login" and "User-Interactive
// Authentication API": a refusal for too many attempts is 429 M_LIMIT_EXCEEDED
// with retry_after_ms; a bad credential is 403 M_FORBIDDEN.
// ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/observability/audit_rate_gate.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include <sodium.h>

namespace
{

constexpr auto correct_password = "CorrectHorse7!";

[[nodiscard]] auto throttle_test_config() -> merovingian::config::Config
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

[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& localpart,
                         std::string const& password, std::string const& source, std::string const& device = "DEVICE1")
    -> merovingian::homeserver::DispatchResult
{
    auto const body = R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                      R"(:example.org"},"password":")" + password + R"(","device_id":")" + device + R"("})";
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, body, {}, source});
}

[[nodiscard]] auto source_address(std::size_t index) -> std::string
{
    return "198.51.100." + std::to_string((index % 250U) + 1U);
}

[[nodiscard]] auto count_rows(merovingian::database::PersistentStore const& store, std::string_view event_type)
    -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.audit_log, [event_type](auto const& event) {
        return event.event_type == event_type;
    }));
}

[[nodiscard]] auto make_runtime_with_alice() -> merovingian::homeserver::ClientServerStartResult
{
    REQUIRE(sodium_init() >= 0);
    auto started = merovingian::homeserver::start_client_server(throttle_test_config());
    REQUIRE(started.started);
    auto const reg = merovingian::homeserver::handle_client_server_request(
        started.runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", correct_password)});
    REQUIRE(reg.response.status == 200U);
    return started;
}

} // namespace

SCENARIO("Failed logins from one source do not lock the account out for other sources",
         "[homeserver][auth][login-throttle][auth-2]")
{
    GIVEN("alice has five failed logins from address A")
    {
        auto started = make_runtime_with_alice();
        auto& runtime = started.runtime;
        for (auto i = 0U; i < 5U; ++i)
        {
            REQUIRE(login(runtime, "alice", "wrong-password", "198.51.100.10").response.status == 403U);
        }

        WHEN("alice logs in with the correct password from address B")
        {
            auto const result = login(runtime, "alice", correct_password, "198.51.100.20");

            THEN("the login succeeds")
            {
                REQUIRE(result.response.status == 200U);
            }
        }

        WHEN("alice logs in with the correct password from address A")
        {
            auto const result = login(runtime, "alice", correct_password, "198.51.100.10");

            THEN("the login is refused as rate limited")
            {
                REQUIRE(result.response.status == 429U);
                REQUIRE(result.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(result.response.body.find("retry_after_ms") != std::string::npos);
            }
        }

        WHEN("another account logs in from address A")
        {
            auto const reg = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("bob", correct_password)});
            REQUIRE(reg.response.status == 200U);
            auto const result = login(runtime, "bob", correct_password, "198.51.100.10");

            THEN("it is not affected by alice's failures")
            {
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

SCENARIO("Distributed guessing against one account hits the per-account ceiling",
         "[homeserver][auth][login-throttle][auth-2]")
{
    GIVEN("alice has fifty failed logins spread over ten addresses")
    {
        auto started = make_runtime_with_alice();
        auto& runtime = started.runtime;
        for (auto address = 0U; address < 10U; ++address)
        {
            for (auto attempt = 0U; attempt < 5U; ++attempt)
            {
                REQUIRE(login(runtime, "alice", "wrong-password", source_address(address)).response.status == 403U);
            }
        }

        WHEN("alice logs in with the correct password from a fresh address")
        {
            auto const result = login(runtime, "alice", correct_password, "203.0.113.200");

            THEN("the login is refused as rate limited, whatever the source")
            {
                REQUIRE(result.response.status == 429U);
                REQUIRE(result.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
        }
    }

    GIVEN("alice has forty-nine failed logins spread over ten addresses")
    {
        auto started = make_runtime_with_alice();
        auto& runtime = started.runtime;
        auto remaining = 49U;
        for (auto address = 0U; address < 10U && remaining > 0U; ++address)
        {
            for (auto attempt = 0U; attempt < 5U && remaining > 0U; ++attempt, --remaining)
            {
                REQUIRE(login(runtime, "alice", "wrong-password", source_address(address)).response.status == 403U);
            }
        }

        WHEN("alice logs in with the correct password from a fresh address")
        {
            auto const result = login(runtime, "alice", correct_password, "203.0.113.201");

            THEN("the login still succeeds")
            {
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

SCENARIO("Unauthenticated login failures never block a user-interactive-auth password check",
         "[homeserver][auth][login-throttle][auth-2]")
{
    GIVEN("alice is signed in on DEVICE1 and an attacker has failed five logins as alice from address A")
    {
        auto started = make_runtime_with_alice();
        auto& runtime = started.runtime;
        auto const signed_in = login(runtime, "alice", correct_password, "198.51.100.30");
        REQUIRE(signed_in.response.status == 200U);
        auto const token_at = signed_in.response.body.find("\"access_token\":\"");
        REQUIRE(token_at != std::string::npos);
        auto const token_start = token_at + std::string{"\"access_token\":\""}.size();
        auto const token =
            signed_in.response.body.substr(token_start, signed_in.response.body.find('"', token_start) - token_start);
        for (auto i = 0U; i < 5U; ++i)
        {
            REQUIRE(login(runtime, "alice", "wrong-password", "198.51.100.10", "ATTACKER").response.status == 403U);
        }
        REQUIRE(login(runtime, "alice", correct_password, "198.51.100.10", "ATTACKER").response.status == 429U);

        WHEN("DEVICE1 changes the password, answering the UIA challenge with the correct password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!"},"new_password":"NewHorse7!+Ab"})"});

            THEN("it is not refused with 429 and the password is changed")
            {
                REQUIRE(response.response.status == 200U);
            }
        }
    }

    GIVEN("alice is signed in and her device has itself failed five UIA password checks")
    {
        auto started = make_runtime_with_alice();
        auto& runtime = started.runtime;
        auto const signed_in = login(runtime, "alice", correct_password, "198.51.100.30");
        REQUIRE(signed_in.response.status == 200U);
        auto const token_start =
            signed_in.response.body.find("\"access_token\":\"") + std::string{"\"access_token\":\""}.size();
        auto const token =
            signed_in.response.body.substr(token_start, signed_in.response.body.find('"', token_start) - token_start);
        for (auto i = 0U; i < 5U; ++i)
        {
            auto const bad = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"WrongPassword9!"},"new_password":"NewHorse7!+Ab"})"});
            REQUIRE(bad.response.status == 401U);
        }

        WHEN("the same device tries again")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!"},"new_password":"NewHorse7!+Ab"})"});

            THEN("the UIA guessing budget for that device is spent")
            {
                REQUIRE(response.response.status == 429U);
            }
        }

        WHEN("an unauthenticated login for alice comes from a fresh address")
        {
            auto const result = login(runtime, "alice", correct_password, "198.51.100.99", "OTHER");

            THEN("UIA failures did not feed the login throttle")
            {
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

SCENARIO("login.rejected audit rows are rate-gated like other unauthenticated rejections",
         "[homeserver][auth][login-throttle][auth-1]")
{
    GIVEN("a runtime with a frozen audit clock")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_client_server(throttle_test_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const frozen = merovingian::observability::AuditRateGate::Clock::time_point{} + std::chrono::hours{1};
        runtime.homeserver.database.audit_rate_gate.set_clock([frozen]() {
            return frozen;
        });

        WHEN("two hundred failed logins arrive for distinct accounts from distinct addresses")
        {
            auto refused = std::size_t{0U};
            for (auto i = 0U; i < 200U; ++i)
            {
                auto const result = login(runtime, "nobody" + std::to_string(i), "wrong-password", source_address(i));
                if (result.response.status == 403U)
                {
                    ++refused;
                }
            }

            THEN("every login was refused but no more than the per-window allowance of rows was written")
            {
                REQUIRE(refused == 200U);
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(count_rows(store, "login.rejected") > 0U);
                REQUIRE(count_rows(store, "login.rejected") <= merovingian::observability::audit_rate_gate_max_rows);
            }
        }
    }
}
