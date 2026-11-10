// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.password_hashing.max_concurrent (ADR-0246, refining ADR-0090): how many Argon2id
// hashes the process admits at once. Four unless the operator says otherwise; a request past it
// is answered 429 at once, before any hash work.

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "merovingian/auth/Argon2idAdmission.hpp"
#include "merovingian/auth/Argon2idSlot.hpp"
#include "merovingian/auth/password.hpp"
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
#include "merovingian/config/config_parser.hpp"
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
