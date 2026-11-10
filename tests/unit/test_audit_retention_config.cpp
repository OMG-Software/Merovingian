// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto retention_is_accepted(std::string const& value) -> bool
{
    auto const parsed =
        merovingian::config::parse_key_value_config("security.audit_log_retention_days=" + value + "\n");
    return parsed.findings.empty() && merovingian::config::is_valid(parsed.config);
}

} // namespace

SCENARIO("The audit retention period is validated when the configuration is parsed", "[config][retention][g7]")
{
    GIVEN("configuration text that names, or leaves out, the retention period")
    {
        WHEN("the key is absent")
        {
            auto const parsed = merovingian::config::parse_key_value_config("");

            THEN("a year is kept")
            {
                REQUIRE(parsed.config.security().audit_log_retention_days == 365U);
                REQUIRE(merovingian::config::is_valid(parsed.config));
            }
        }

        WHEN("it is 0 or inside 30..3650")
        {
            THEN("it is accepted and stored")
            {
                REQUIRE(retention_is_accepted("0"));
                REQUIRE(retention_is_accepted("30"));
                REQUIRE(retention_is_accepted("3650"));
                auto const parsed =
                    merovingian::config::parse_key_value_config("security.audit_log_retention_days=30\n");
                REQUIRE(parsed.config.security().audit_log_retention_days == 30U);
            }
        }

        WHEN("it is under a month, over ten years, negative, fractional or not a number")
        {
            THEN("each is refused")
            {
                REQUIRE_FALSE(retention_is_accepted("1"));
                REQUIRE_FALSE(retention_is_accepted("29"));
                REQUIRE_FALSE(retention_is_accepted("3651"));
                REQUIRE_FALSE(retention_is_accepted("-1"));
                REQUIRE_FALSE(retention_is_accepted("1.5"));
                REQUIRE_FALSE(retention_is_accepted("forever"));
                REQUIRE_FALSE(retention_is_accepted("99999999999"));
            }
        }
    }
}
