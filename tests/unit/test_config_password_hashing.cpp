// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.password_hashing.max_concurrent (ADR-0246, refining ADR-0090): how many Argon2id
// hashes the process admits at once. Four unless the operator says otherwise; a request past it
// is answered 429 at once, before any hash work.

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"
#include "merovingian/homeserver/runtime.hpp"

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

// How many Argon2id slots the runtime hands out before refusing one.
[[nodiscard]] auto admitted_slots(merovingian::homeserver::HomeserverRuntime& runtime) -> std::size_t
{
    REQUIRE(runtime.argon2id_admission != nullptr);
    auto held = std::vector<merovingian::auth::Argon2idSlot>{};
    while (held.size() <= merovingian::auth::argon2id_admission_max_capacity)
    {
        auto slot = runtime.argon2id_admission->try_acquire();
        if (!slot.has_value())
        {
            break;
        }
        held.push_back(std::move(*slot));
    }
    return held.size();
}
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

SCENARIO("The runtime admits as many concurrent hashes as the config says", "[homeserver][auth][password-hashing]")
{
    for (auto const configured :
         {std::optional<std::uint32_t>{}, std::optional<std::uint32_t>{2U}, std::optional<std::uint32_t>{16U}})
    {
        auto const description =
            configured.has_value() ? "a cap of " + std::to_string(*configured) : std::string{"no cap configured"};
        GIVEN(description)
        {
            auto security = merovingian::config::SecurityConfig{};
            security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
            if (configured.has_value())
            {
                security.password_hashing.max_concurrent = *configured;
            }
            auto started = merovingian::homeserver::start_runtime({
                merovingian::config::ServerConfig{},
                merovingian::config::ListenersConfig{},
                merovingian::tests::in_memory_database_config(),
                security,
                merovingian::config::ClientRateLimitsConfig{},
                merovingian::config::LogModulesConfig{},
            });
            REQUIRE(started.started);

            WHEN("hash slots are taken until one is refused")
            {
                auto const admitted = admitted_slots(started.runtime);

                THEN("exactly the configured number is admitted, four by default")
                {
                    REQUIRE(admitted == configured.value_or(4U));
                }
            }
        }
    }
}
