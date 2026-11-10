// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.password_hashing.max_concurrent (ADR-0246, refining ADR-0090): how many Argon2id
// hashes the process admits at once. Four unless the operator says otherwise; a request past it
// is answered 429 at once, before any hash work.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/auth/Argon2idSlot.hpp"
#include "merovingian/auth/Password.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParseResult.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
[[nodiscard]] auto has_finding(merovingian::config::ConfigParseResult const& result, std::string_view field) -> bool
{
    return std::ranges::any_of(result.findings, [field](merovingian::config::ConfigValidationFinding const& finding) {
        return finding.field == field;
    });
}

constexpr auto key = std::string_view{"security.password_hashing.max_concurrent"};
} // namespace

SCENARIO("Password hashing admits four hashes at once by default", "[config][password-hashing]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the password hashing cap is read")
        {
            auto const cap = config.security().password_hashing.max_concurrent;

            THEN("it is the cap the server had before it was configurable")
            {
                REQUIRE(cap == 4U);
                REQUIRE(cap == merovingian::auth::default_argon2id_capacity());
            }
        }
    }
}

SCENARIO("The password hashing cap is read from the config", "[config][password-hashing]")
{
    GIVEN("a config that raises the cap to the largest value the server accepts")
    {
        auto const input = std::string{key} + "=128\n";

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("it is read and raises no finding")
            {
                REQUIRE(result.config.security().password_hashing.max_concurrent == 128U);
                REQUIRE_FALSE(has_finding(result, key));
            }
        }
    }
}

SCENARIO("A password hashing cap outside its range is a startup finding", "[config][password-hashing][security]")
{
    // Zero would refuse every login and registration; past 128 is more than the admission
    // semaphore can count, and unbounded hashing is what ADR-0090 exists to prevent.
    for (auto const* value : {"0", "129", "four", "-2", ""})
    {
        GIVEN(std::string{"the value '"} + value + "'")
        {
            auto const input = std::string{key} + "=" + value + "\n";

            WHEN("the config is parsed")
            {
                auto const result = merovingian::config::parse_key_value_config(input);

                THEN("it is refused")
                {
                    REQUIRE(has_finding(result, key));
                }
            }
        }
    }
}

SCENARIO("A password hashing cap change takes effect only on restart", "[config][password-hashing][reload]")
{
    GIVEN("a running config and one that raises the cap")
    {
        auto const current = merovingian::config::parse_key_value_config("").config;
        auto const next = merovingian::config::parse_key_value_config(std::string{key} + "=16\n").config;

        WHEN("the reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the key changes and needs a restart: the admission semaphore is built at start-up")
            {
                REQUIRE(std::ranges::any_of(plan.changes(), [](auto const& change) {
                    return change.key == key;
                }));
                REQUIRE(merovingian::config::reload_policy_for_key(key) ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}
