// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  CLIENT RATE-LIMIT CONFIG                                                |
// |                                                                         |
// |  These scenarios cover the parser + validator wiring of                |
// |  `client_rate_limits.per_ip.<target>`,                                 |
// |  `client_rate_limits.per_user.<target>`,                               |
// |  `client_rate_limits.tier.<name>`, and                                 |
// |  `client_rate_limits.default_per_ip` keys. The keys are dotted         |
// |  to support target prefixes that themselves contain slashes           |
// |  (e.g. `/_matrix/client/v3/login`). Tier names are validated           |
// |  against the engine's tier table. Bad values become findings; the     |
// |  parser rejects zero-window/zero-cap policies.                         |
// +-------------------------------------------------------------------------+

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using merovingian::config::parse_key_value_config;

} // namespace

SCENARIO("Default config leaves the per-IP and per-user maps empty and falls back to default_per_ip",
         "[config][rate-limit]")
{
    GIVEN("an empty config")
    {
        auto const input = std::string{};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the per-IP and per-user maps are empty and default_per_ip is the 90/60s fallback")
            {
                REQUIRE(result.findings.empty());
                auto const& limits = result.config.client_rate_limits();
                REQUIRE(limits.per_ip.empty());
                REQUIRE(limits.per_user.empty());
                // The struct default keeps the rate-limit engine's
                // "everything else" bucket at 90 requests per 60s.
                REQUIRE(limits.default_per_ip.max_requests == 90U);
                REQUIRE(limits.default_per_ip.window_seconds == 60U);
            }
        }
    }
}

SCENARIO("Parsing client_rate_limits.per_ip.<target>=N/Ws populates the per-IP map", "[config][rate-limit]")
{
    GIVEN("a config that sets a per-IP policy for /register")
    {
        auto const input = std::string{"client_rate_limits.per_ip./_matrix/client/v3/register=50/120s\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parsed value lands in the per-IP map with no findings")
            {
                REQUIRE(result.findings.empty());
                auto const& limits = result.config.client_rate_limits();
                REQUIRE(limits.per_ip.contains("/_matrix/client/v3/register"));
                REQUIRE(limits.per_ip.at("/_matrix/client/v3/register").max_requests == 50U);
                REQUIRE(limits.per_ip.at("/_matrix/client/v3/register").window_seconds == 120U);
            }
        }
    }
}

SCENARIO("Malformed client_rate_limits values are rejected as findings", "[config][rate-limit]")
{
    GIVEN("a config that sets a per-IP policy to a non-numeric value")
    {
        auto const input = std::string{"client_rate_limits.per_ip./_matrix/client/v3/login=foo\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parser reports a finding rather than silently dropping the key")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.per_ip./_matrix/client/v3/login");
            }
        }
    }
}

SCENARIO("The config parser rejects a zero-window rate-limit policy at parse time", "[config][rate-limit]")
{
    GIVEN("a config whose per-user policy has zero window")
    {
        // The parser refuses a zero-window policy outright (the rate-limit
        // engine would loop forever on a 0s window) and emits a finding
        // rather than silently dropping the key.
        auto const input = std::string{"client_rate_limits.per_user./_matrix/client/v3/login=5/0s\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parser emits a finding on the offending key")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.per_user./_matrix/client/v3/login");
            }
        }
    }
}

SCENARIO("Empty client_rate_limits target keys are rejected", "[config][rate-limit]")
{
    GIVEN("a config with an empty per-IP rate-limit target")
    {
        auto const input = std::string{"client_rate_limits.per_ip.=5/60s\n"};

        WHEN("the config is parsed and validated")
        {
            auto const result = parse_key_value_config(input);

            THEN("the validator emits a finding on the empty target")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.per_ip");
            }
        }
    }

    GIVEN("a config with an empty per-user rate-limit target")
    {
        auto const input = std::string{"client_rate_limits.per_user.=5/60s\n"};

        WHEN("the config is parsed and validated")
        {
            auto const result = parse_key_value_config(input);

            THEN("the validator emits a finding on the empty target")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.per_user");
            }
        }
    }
}

SCENARIO("Parsing client_rate_limits.tier.<name>=N/Ws populates the tier override map", "[config][rate-limit][tier]")
{
    GIVEN("a config that tightens the auth_sensitive and generic tiers")
    {
        auto const input = std::string{"client_rate_limits.tier.auth_sensitive=10/60s\n"
                                       "client_rate_limits.tier.generic=45/120s\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("both tier overrides land in the tier map with no findings")
            {
                REQUIRE(result.findings.empty());
                auto const& limits = result.config.client_rate_limits();
                REQUIRE(limits.tier.contains("auth_sensitive"));
                REQUIRE(limits.tier.at("auth_sensitive").max_requests == 10U);
                REQUIRE(limits.tier.at("auth_sensitive").window_seconds == 60U);
                REQUIRE(limits.tier.contains("generic"));
                REQUIRE(limits.tier.at("generic").max_requests == 45U);
                REQUIRE(limits.tier.at("generic").window_seconds == 120U);
            }
        }
    }
}

SCENARIO("An unknown client_rate_limits.tier name is rejected as a parse finding",
         "[config][rate-limit][tier][security]")
{
    GIVEN("a config that names a tier the engine does not define")
    {
        auto const input = std::string{"client_rate_limits.tier.login=10/60s\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the typo becomes a finding rather than a silently ignored key")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.tier.login");
                REQUIRE(result.config.client_rate_limits().tier.empty());
            }
        }
    }
}

SCENARIO("A malformed client_rate_limits.tier policy is rejected as a parse finding", "[config][rate-limit][tier]")
{
    GIVEN("a config with a valid tier name but a non-numeric policy")
    {
        auto const input = std::string{"client_rate_limits.tier.media=lots\n"};

        WHEN("the config is parsed")
        {
            auto const result = parse_key_value_config(input);

            THEN("the parser emits a finding and the tier map stays empty")
            {
                REQUIRE_FALSE(result.findings.empty());
                REQUIRE(result.findings.front().field == "client_rate_limits.tier.media");
                REQUIRE(result.config.client_rate_limits().tier.empty());
            }
        }
    }
}
