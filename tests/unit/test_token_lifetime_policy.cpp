// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>

SCENARIO("Token lifetime admission preserves values and enforces project upper bounds", "[config][ops-4-upper-bound]")
{
    GIVEN("healthy parsed defaults and valid zero sentinels for both token kinds")
    {
        auto const healthy = merovingian::config::parse_key_value_config("");
        REQUIRE(healthy.findings.empty());
        REQUIRE(merovingian::config::validate(healthy.config).empty());
        REQUIRE(merovingian::config::is_valid(healthy.config));
        REQUIRE(healthy.config.security().access_token_lifetime_ms == 3600000);
        REQUIRE(healthy.config.security().refresh_token_lifetime_ms == 2592000000);

        auto const parsed_zero = merovingian::config::parse_key_value_config(
            "security.access_token_lifetime_ms=0\nsecurity.refresh_token_lifetime_ms=0\n");
        REQUIRE(parsed_zero.findings.empty());
        REQUIRE(merovingian::config::validate(parsed_zero.config).empty());
        REQUIRE(merovingian::config::is_valid(parsed_zero.config));
        REQUIRE(parsed_zero.config.security().access_token_lifetime_ms == 0);
        REQUIRE(parsed_zero.config.security().refresh_token_lifetime_ms == 0);

        auto typed_zero = healthy.config;
        typed_zero.security().access_token_lifetime_ms = 0;
        typed_zero.security().refresh_token_lifetime_ms = 0;
        REQUIRE(merovingian::config::validate(typed_zero).empty());
        REQUIRE(merovingian::config::is_valid(typed_zero));
        REQUIRE(typed_zero.security().access_token_lifetime_ms == 0);
        REQUIRE(typed_zero.security().refresh_token_lifetime_ms == 0);

        WHEN("each lifetime is parsed or directly mutated before typed validation")
        {
            THEN("zero, defaults and inclusive caps remain valid while oversized values are rejected unchanged")
            {
                struct LifetimeField final
                {
                    std::string name;
                    std::int64_t default_value;
                    std::int64_t maximum;
                    bool access;
                };
                struct LifetimeInput final
                {
                    std::int64_t value;
                    bool accepted;
                };

                // These are project admission limits, not Matrix protocol limits.
                auto const fields = std::array{
                    LifetimeField{"security.access_token_lifetime_ms",
                                  healthy.config.security().access_token_lifetime_ms,  2592000000,  true },
                    LifetimeField{"security.refresh_token_lifetime_ms",
                                  healthy.config.security().refresh_token_lifetime_ms, 31536000000, false}
                };
                auto const lifetime = [](auto& config, bool access) -> auto& {
                    return access ? config.security().access_token_lifetime_ms
                                  : config.security().refresh_token_lifetime_ms;
                };

                for (auto const& field : fields)
                {
                    auto const inputs = std::array{
                        LifetimeInput{0,                                        true },
                        LifetimeInput{1,                                        true },
                        LifetimeInput{field.default_value,                      true },
                        LifetimeInput{field.maximum,                            true },
                        LifetimeInput{field.maximum + 1,                        false},
                        LifetimeInput{std::numeric_limits<std::int64_t>::max(), false}
                    };
                    for (auto const& input : inputs)
                    {
                        INFO("lifetime field: " << field.name << ", milliseconds: " << input.value);

                        auto const parsed = merovingian::config::parse_key_value_config(
                            field.name + "=" + std::to_string(input.value) + "\n");
                        CHECK(lifetime(parsed.config, field.access) == input.value);
                        auto const parsed_findings = merovingian::config::validate(parsed.config);
                        auto const parser_has_field_finding =
                            std::ranges::any_of(parsed.findings, [&field](auto const& finding) {
                                return finding.field == field.name;
                            });
                        auto const parsed_validation_has_field_finding =
                            std::ranges::any_of(parsed_findings, [&field](auto const& finding) {
                                return finding.field == field.name;
                            });
                        if (input.accepted)
                        {
                            CHECK_FALSE(parser_has_field_finding);
                            CHECK_FALSE(parsed_validation_has_field_finding);
                            CHECK(parsed.findings.empty());
                            CHECK(parsed_findings.empty());
                            CHECK(merovingian::config::is_valid(parsed.config));
                        }
                        else
                        {
                            CHECK(parser_has_field_finding);
                            CHECK(parsed_validation_has_field_finding);
                            CHECK_FALSE(merovingian::config::is_valid(parsed.config));
                        }
                        CHECK(lifetime(parsed.config, field.access) == input.value);

                        auto typed = healthy.config;
                        lifetime(typed, field.access) = input.value;
                        CHECK(lifetime(typed, field.access) == input.value);
                        auto const typed_findings = merovingian::config::validate(typed);
                        auto const typed_has_field_finding =
                            std::ranges::any_of(typed_findings, [&field](auto const& finding) {
                                return finding.field == field.name;
                            });
                        if (input.accepted)
                        {
                            CHECK_FALSE(typed_has_field_finding);
                            CHECK(typed_findings.empty());
                            CHECK(merovingian::config::is_valid(typed));
                        }
                        else
                        {
                            CHECK(typed_has_field_finding);
                            CHECK_FALSE(merovingian::config::is_valid(typed));
                        }
                        CHECK(lifetime(typed, field.access) == input.value);
                    }
                }
            }
        }
    }
}
