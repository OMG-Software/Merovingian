// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// A setting that weakens the server is announced at CRITICAL every time the
// server starts (ADR-0232, ADR-0236): open registration, and a password policy
// weaker than the default. A server at its defaults announces neither.

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/observability/logger.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

namespace
{

// Sends the console log to a string for the scope's lifetime. Safe only while
// the logger's asynchronous writer threads are not running, which is the case
// in the unit test binary.
class ConsoleLogCapture final
{
public:
    ConsoleLogCapture()
        : logger_{merovingian::observability::SingleLog::instance()}
    {
        REQUIRE_FALSE(logger_.get().writers_started());
        previous_level_ = logger_.get().exchange_console_log_level(merovingian::observability::LogLevel::info);
        previous_buffer_ = std::cout.rdbuf(output_.rdbuf());
    }
    ~ConsoleLogCapture()
    {
        std::cout.rdbuf(previous_buffer_);
        std::ignore = logger_.get().exchange_console_log_level(previous_level_);
    }
    ConsoleLogCapture(ConsoleLogCapture const&) = delete;
    auto operator=(ConsoleLogCapture const&) -> ConsoleLogCapture& = delete;
    ConsoleLogCapture(ConsoleLogCapture&&) = delete;
    auto operator=(ConsoleLogCapture&&) -> ConsoleLogCapture& = delete;

    // True when a CRITICAL line names `event`.
    [[nodiscard]] auto has_critical(std::string const& event) const -> bool
    {
        auto lines = std::istringstream{output_.str()};
        for (auto line = std::string{}; std::getline(lines, line);)
        {
            if (line.find("<CRITICAL>") != std::string::npos && line.find(event) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

private:
    std::reference_wrapper<merovingian::observability::SingleLog> logger_;
    std::ostringstream output_{};
    std::streambuf* previous_buffer_{nullptr};
    merovingian::observability::LogLevel previous_level_{};
};

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
            auto const capture = ConsoleLogCapture{};
            auto started = merovingian::homeserver::start_client_server(config);

            THEN("both weakenings are announced at CRITICAL")
            {
                REQUIRE(started.started);
                REQUIRE(capture.has_critical("registration.open"));
                REQUIRE(capture.has_critical("registration.password_policy_relaxed"));
            }
        }
    }

    GIVEN("a server whose password policy only drops the character classes")
    {
        auto const config = config_with({}, {.min_length = 12U, .require_character_classes = false});

        WHEN("it starts")
        {
            auto const capture = ConsoleLogCapture{};
            auto started = merovingian::homeserver::start_client_server(config);

            THEN("the weaker policy is announced, and closed registration is not")
            {
                REQUIRE(started.started);
                REQUIRE(capture.has_critical("registration.password_policy_relaxed"));
                REQUIRE_FALSE(capture.has_critical("registration.open"));
            }
        }
    }

    GIVEN("a server at its defaults, and one with a stricter password policy")
    {
        auto const defaults = config_with({}, {});
        auto const stricter = config_with({}, {.min_length = 20U, .require_character_classes = true});

        WHEN("each starts")
        {
            auto const capture = ConsoleLogCapture{};
            auto started_defaults = merovingian::homeserver::start_client_server(defaults);
            auto started_stricter = merovingian::homeserver::start_client_server(stricter);

            THEN("neither announces a weakening")
            {
                REQUIRE(started_defaults.started);
                REQUIRE(started_stricter.started);
                REQUIRE_FALSE(capture.has_critical("registration.open"));
                REQUIRE_FALSE(capture.has_critical("registration.password_policy_relaxed"));
            }
        }
    }
}
