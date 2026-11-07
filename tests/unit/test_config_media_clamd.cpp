// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The security.media.clamd_* keys (G15, ADR-0565): defaults, parsing, validation and reload policy.

#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/ReloadPolicy.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/media/RuntimeMediaConfig.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <string>

namespace
{

[[nodiscard]] auto config_with(merovingian::config::MediaSecurityConfig const& media) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.media = media;
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto has_finding(merovingian::config::Config const& config, std::string const& field) -> bool
{
    auto const findings = merovingian::config::validate(config);
    return std::ranges::any_of(findings, [&field](auto const& finding) {
        return finding.field == field;
    });
}

} // namespace

SCENARIO("clamd scanning is off by default", "[g15][config][media]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the runtime media config is built")
        {
            auto const runtime = merovingian::media::make_runtime_media_config(config);

            THEN("no socket is set, the limits are clamd's usual ones, and no clamd finding is raised")
            {
                REQUIRE(config.security().media.clamd_socket_path.empty());
                REQUIRE_FALSE(runtime.clamd.enabled());
                REQUIRE(runtime.clamd.timeout_ms == 10000U);
                REQUIRE(runtime.clamd.max_scan_bytes == 25U * 1024U * 1024U);
                REQUIRE(runtime.clamd.max_concurrent == 4U);
                REQUIRE_FALSE(has_finding(config, "security.media.clamd_socket_path"));
                REQUIRE_FALSE(has_finding(config, "security.media.clamd_timeout_ms"));
                REQUIRE_FALSE(has_finding(config, "security.media.clamd_max_scan_size"));
                REQUIRE_FALSE(has_finding(config, "security.media.clamd_max_concurrent"));
            }
        }
    }
}

SCENARIO("the clamd keys are parsed from key-value config", "[g15][config][media][parser]")
{
    GIVEN("a configuration naming a socket and limits")
    {
        auto const input = std::string{"security.media.clamd_socket_path=/run/clamav/clamd.ctl\n"
                                       "security.media.clamd_timeout_ms=2500\n"
                                       "security.media.clamd_max_scan_size=10MiB\n"
                                       "security.media.clamd_max_concurrent=3\n"};

        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("every key is applied and the runtime config enables the scanner")
            {
                REQUIRE(result.findings.empty());
                auto const& media = result.config.security().media;
                REQUIRE(media.clamd_socket_path == "/run/clamav/clamd.ctl");
                REQUIRE(media.clamd_timeout_ms == 2500U);
                REQUIRE(media.clamd_max_scan_size == "10MiB");
                REQUIRE(media.clamd_max_concurrent == 3U);
                auto const runtime = merovingian::media::make_runtime_media_config(result.config);
                REQUIRE(runtime.clamd.enabled());
                REQUIRE(runtime.clamd.max_scan_bytes == 10U * 1024U * 1024U);
            }
        }
    }

    GIVEN("a non-numeric timeout")
    {
        WHEN("it is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config("security.media.clamd_timeout_ms=soon\n");

            THEN("a parse finding names the key")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "security.media.clamd_timeout_ms");
            }
        }
    }
}

SCENARIO("clamd settings are validated at parse time", "[g15][config][media][validation]")
{
    GIVEN("a socket path that is not acceptable")
    {
        auto media = merovingian::config::MediaSecurityConfig{};
        media.clamd_socket_path = GENERATE(std::string{"relative/clamd.sock"}, std::string{"/run/clamd\n.sock"},
                                           "/" + std::string(120U, 'a'));

        WHEN("the config is validated")
        {
            THEN("the socket path is refused")
            {
                REQUIRE(has_finding(config_with(media), "security.media.clamd_socket_path"));
            }
        }
    }

    GIVEN("a socket path with the AV scanner switched off")
    {
        auto media = merovingian::config::MediaSecurityConfig{};
        media.clamd_socket_path = "/run/clamav/clamd.ctl";
        media.enable_av_scanner = false;

        WHEN("the config is validated")
        {
            THEN("it is refused, since the repository would ignore the verdict")
            {
                REQUIRE(has_finding(config_with(media), "security.media.clamd_socket_path"));
            }
        }
    }

    GIVEN("a valid absolute socket path")
    {
        auto media = merovingian::config::MediaSecurityConfig{};
        media.clamd_socket_path = "/run/clamav/clamd.ctl";

        WHEN("the config is validated")
        {
            THEN("no clamd finding is raised")
            {
                REQUIRE_FALSE(has_finding(config_with(media), "security.media.clamd_socket_path"));
            }
        }
    }

    GIVEN("limits outside their ranges")
    {
        auto media = merovingian::config::MediaSecurityConfig{};
        media.clamd_timeout_ms = GENERATE(0U, 99U, 120001U);
        media.clamd_max_concurrent = GENERATE(0U, 65U);
        media.clamd_max_scan_size = GENERATE(std::string{"0"}, std::string{"2GiB"}, std::string{"lots"}, std::string{});

        WHEN("the config is validated")
        {
            auto const config = config_with(media);

            THEN("each is refused")
            {
                REQUIRE(has_finding(config, "security.media.clamd_timeout_ms"));
                REQUIRE(has_finding(config, "security.media.clamd_max_concurrent"));
                REQUIRE(has_finding(config, "security.media.clamd_max_scan_size"));
            }
        }
    }
}

SCENARIO("clamd settings need a restart", "[g15][config][media][reload]")
{
    GIVEN("current and next configs with different clamd settings")
    {
        auto current_media = merovingian::config::MediaSecurityConfig{};
        auto next_media = merovingian::config::MediaSecurityConfig{};
        next_media.clamd_socket_path = "/run/clamav/clamd.ctl";
        next_media.clamd_timeout_ms = 5000U;

        WHEN("a reload plan is built")
        {
            auto const plan =
                merovingian::config::build_reload_plan(config_with(current_media), config_with(next_media));

            THEN("both changes are listed and need a restart")
            {
                REQUIRE(plan.changes().size() == 2U);
                for (auto const& change : plan.changes())
                {
                    REQUIRE(change.policy == merovingian::config::ReloadPolicy::restart_required);
                }
                REQUIRE(merovingian::config::reload_policy_for_key("security.media.clamd_max_scan_size") ==
                        merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_policy_for_key("security.media.clamd_max_concurrent") ==
                        merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}
