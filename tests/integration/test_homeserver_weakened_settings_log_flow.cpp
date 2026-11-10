// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// A setting that weakens the server is announced at CRITICAL every time the
// server starts (ADR-0232, ADR-0236): open registration, and a password policy
// weaker than the default. A server at its defaults announces neither.

#include "../support/ConsoleLogCapture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/PasswordPolicyConfig.hpp"
#include "merovingian/config/RegistrationSecurityConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/observability/LogLevel.hpp"
#include "merovingian/observability/SingleLog.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

namespace
{

[[nodiscard]] auto config_with(merovingian::config::RegistrationSecurityConfig registration,
                               merovingian::config::PasswordPolicyConfig password_policy) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.registration = std::move(registration);
    security.password_policy = password_policy;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

} // namespace

SCENARIO("Weakened registration and password settings are logged at CRITICAL on start",
         "[homeserver][startup][security][password-policy][open-registration]")
{
    GIVEN("a server with open registration and the most relaxed password policy")
    {
        auto const config = config_with({.enabled = true, .require_token = false, .allow_open_registration = true},
                                        {.min_length = 1U, .require_character_classes = false});

        WHEN("it starts")
        {
            auto const capture = merovingian::tests::ConsoleLogCapture{};
            auto started = merovingian::homeserver::start_client_server(config);

            THEN("both weakenings are announced at CRITICAL")
            {
                REQUIRE(started.started);
                REQUIRE(capture.has_line("CRITICAL", "registration.open"));
                REQUIRE(capture.has_line("CRITICAL", "registration.password_policy_relaxed"));
            }
        }
    }

    GIVEN("a server whose password policy only drops the character classes")
    {
        auto const config = config_with({}, {.min_length = 12U, .require_character_classes = false});

        WHEN("it starts")
        {
            auto const capture = merovingian::tests::ConsoleLogCapture{};
            auto started = merovingian::homeserver::start_client_server(config);

            THEN("the weaker policy is announced, and closed registration is not")
            {
                REQUIRE(started.started);
                REQUIRE(capture.has_line("CRITICAL", "registration.password_policy_relaxed"));
                REQUIRE_FALSE(capture.has_line("CRITICAL", "registration.open"));
            }
        }
    }

    GIVEN("a server at its defaults, and one with a stricter password policy")
    {
        auto const defaults = config_with({}, {});
        auto const stricter = config_with({}, {.min_length = 20U, .require_character_classes = true});

        WHEN("each starts")
        {
            auto const capture = merovingian::tests::ConsoleLogCapture{};
            auto started_defaults = merovingian::homeserver::start_client_server(defaults);
            auto started_stricter = merovingian::homeserver::start_client_server(stricter);

            THEN("neither announces a weakening")
            {
                REQUIRE(started_defaults.started);
                REQUIRE(started_stricter.started);
                REQUIRE_FALSE(capture.has_line("CRITICAL", "registration.open"));
                REQUIRE_FALSE(capture.has_line("CRITICAL", "registration.password_policy_relaxed"));
            }
        }
    }
}
